//! Tauri desktop shell around the Rust engine and embedded interface.
use crate::{
    config::Config,
    control::{self, helper_request, valid_helper},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tauri::{RunEvent, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent};
use tokio_util::sync::CancellationToken;

struct DesktopState {
    control: url::Url,
    busy: AtomicBool,
}

pub fn app_navigation_allowed(url: &url::Url) -> bool {
    url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && match url.scheme() {
            "tauri" => url.host_str() == Some("localhost"),
            "http" | "https" => url.host_str() == Some("tauri.localhost"),
            _ => false,
        }
}

fn validate_window(window: &WebviewWindow) -> Result<()> {
    ensure!(
        window.label() == "main" && app_navigation_allowed(&window.url()?),
        "native commands require the bundled main window"
    );
    Ok(())
}

pub async fn request_control(control: &url::Url, path: &str, body: Option<Value>) -> Result<Value> {
    valid_helper(control.as_str())?;
    let get = ["status", "profiles", "vault/status", "diagnostics", "logs"].contains(&path);
    let post = [
        "start",
        "stop",
        "import",
        "vault/unlock",
        "profiles/save",
        "profiles/delete",
        "profiles/share",
        "profiles/import-shared",
        "logs/read",
    ]
    .contains(&path);
    ensure!(
        (get && body.is_none()) || (post && body.is_some()),
        "unsupported desktop control request"
    );
    if let Some(body) = &body {
        ensure!(
            serde_json::to_vec(body)?.len() <= 65536,
            "desktop control request too large"
        );
    }
    helper_request(control, path, body).await
}

#[tauri::command]
async fn control_request(
    window: WebviewWindow,
    state: tauri::State<'_, DesktopState>,
    path: String,
    body: Option<Value>,
) -> std::result::Result<Value, String> {
    let result = async {
        validate_window(&window)?;
        request_control(&state.control, &path, body).await
    }
    .await;
    result.map_err(|e| e.to_string())
}

#[tauri::command]
async fn connect_full_device(
    window: WebviewWindow,
    state: tauri::State<'_, DesktopState>,
    args: Vec<String>,
) -> std::result::Result<Value, String> {
    let result = async {
        validate_window(&window)?;
        ensure!(
            !state.busy.swap(true, Ordering::SeqCst),
            "Administrator authorization is already in progress"
        );
        let result = connect_privileged(state.control.clone(), json!(args)).await;
        state.busy.store(false, Ordering::SeqCst);
        result
    }
    .await;
    result.map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_shared_profile(
    window: WebviewWindow,
    request: Value,
) -> std::result::Result<Value, String> {
    validate_window(&window).map_err(|e| e.to_string())?;
    // Native dialogs must run on the UI thread; never block Tauri's async worker.
    let (sender, receiver) = tokio::sync::oneshot::channel();
    window
        .run_on_main_thread(move || {
            let result = save_share_file(request).map_err(|e| e.to_string());
            let _ = sender.send(result);
        })
        .map_err(|e| e.to_string())?;
    receiver.await.map_err(|e| e.to_string())?
}

pub fn run() -> Result<()> {
    ensure!(
        !crate::runtime::is_admin(),
        "launch the desktop window as your normal user"
    );
    let runtime = tokio::runtime::Runtime::new()?;
    tauri::async_runtime::set(runtime.handle().clone());
    let cancel = CancellationToken::new();
    let finished = Arc::new(AtomicBool::new(false));
    let (sender, ready) = tokio::sync::oneshot::channel();
    let config = Config::parse(&["-ui".into(), "-ui-no-browser".into()])?;
    let server = runtime.spawn(control::serve_with_ready(
        config,
        cancel.clone(),
        Some(sender),
    ));
    let raw = match runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(30), ready).await })
    {
        Ok(Ok(raw)) => raw,
        other => {
            cancel.cancel();
            bail!("desktop control service did not start: {other:?}")
        }
    };
    let control_url = valid_helper(&raw)?;
    let close_cancel = cancel.clone();
    let app = tauri::Builder::default()
        .manage(DesktopState {
            control: control_url,
            busy: AtomicBool::new(false),
        })
        .invoke_handler(tauri::generate_handler![
            control_request,
            connect_full_device,
            save_shared_profile
        ])
        .setup(|app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("TunnelNest · Rust")
                .inner_size(1320., 960.)
                .min_inner_size(820., 650.)
                .initialization_script(include_str!("../desktop/tauri-bridge.js"))
                .on_navigation(app_navigation_allowed)
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            Ok(())
        })
        .on_window_event(move |_, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                close_cancel.cancel();
            }
        })
        .build(tauri::generate_context!());
    let app = match app {
        Ok(app) => app,
        Err(error) => {
            cancel.cancel();
            runtime.block_on(async {
                let _ = server.await;
            });
            return Err(error.into());
        }
    };
    let handle = app.handle().clone();
    let exited = finished.clone();
    let watcher = runtime.spawn(async move {
        let code = match server.await {
            Ok(Ok(())) => 0,
            error => {
                eprintln!("Desktop control service stopped: {error:?}");
                1
            }
        };
        exited.store(true, Ordering::SeqCst);
        handle.exit(code);
    });
    let signal_cancel = cancel.clone();
    runtime.spawn(async move {
        #[cfg(unix)]
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>(),_=term.recv()=>()}
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        signal_cancel.cancel();
    });
    let exit_cancel = cancel.clone();
    app.run(move |_, event| {
        if let RunEvent::ExitRequested { api, .. } = event
            && !finished.load(Ordering::SeqCst)
        {
            api.prevent_exit();
            exit_cancel.cancel();
        }
    });
    cancel.cancel();
    runtime.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(15), watcher).await;
    });
    Ok(())
}

pub fn share_file_bytes(request: &Value) -> Result<(String, String, Vec<u8>)> {
    let name = request["name"].as_str().unwrap_or("profile");
    let name: String = name
        .chars()
        .take(80)
        .map(|c| {
            if c.is_control() || "<>:\"/\\|?*".contains(c) {
                '-'
            } else {
                c
            }
        })
        .collect();
    let name = name.trim_end_matches(['.', ' ']);
    let name = if name.is_empty() { "profile" } else { name };
    match request["format"].as_str() {
        Some("profile") => {
            let code = request["code"]
                .as_str()
                .context("missing share code")?
                .trim();
            ensure!(code.len() <= 24576, "share code too large");
            let (prefix, data) = code.split_once('.').context("invalid share code")?;
            ensure!(
                ["TN1", "TN2", "TN2P"].contains(&prefix)
                    && !data.is_empty()
                    && data
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "invalid share code"
            );
            Ok((
                format!("TunnelNest-{name}.tnprofile"),
                "tnprofile".into(),
                format!("{code}\n").into_bytes(),
            ))
        }
        Some("qr") => {
            let image = request["image"].as_str().context("missing QR image")?;
            ensure!(image.len() <= 2 * 1024 * 1024, "QR image too large");
            let data = STANDARD.decode(
                image
                    .strip_prefix("data:image/png;base64,")
                    .context("invalid PNG data URL")?,
            )?;
            ensure!(
                data.len() <= 1024 * 1024 && data.starts_with(b"\x89PNG\r\n\x1a\n"),
                "invalid PNG image"
            );
            Ok((format!("TunnelNest-{name}-QR.png"), "png".into(), data))
        }
        _ => bail!("unsupported share format"),
    }
}
fn save_share_file(request: Value) -> Result<Value> {
    let (name, extension, data) = share_file_bytes(&request)?;
    let path = rfd::FileDialog::new()
        .set_title("Save shared profile")
        .set_file_name(name)
        .add_filter("TunnelNest share", &[&extension])
        .save_file();
    let Some(path) = path else {
        return Ok(json!({"cancelled":true}));
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&data)?;
    Ok(json!({"cancelled":false,"filename":path.file_name().unwrap_or_default().to_string_lossy()}))
}
#[cfg(target_os = "macos")]
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}
#[cfg(windows)]
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
async fn connect_privileged(control: url::Url, value: Value) -> Result<Value> {
    let mut args: Vec<String> = serde_json::from_value(value)?;
    let config = Config::parse(&args)?;
    ensure!(
        args.len() <= 128 && config.tun() && !config.boolean("ui"),
        "invalid full-device request"
    );
    for (flag, name) in [("tun-binary", "sing-box"), ("v2ray-binary", "xray")] {
        if !config.flags.contains_key(flag) && (flag == "tun-binary" || config.mode() != "ssh") {
            args.extend([
                format!("-{flag}"),
                crate::core::find_core("", &[name])?
                    .to_string_lossy()
                    .into(),
            ]);
        }
    }
    if config.mode() == "ssh" && !config.flags.contains_key("ssh-known-hosts") {
        args.extend([
            "-ssh-known-hosts".into(),
            dirs::home_dir()
                .context("no home directory")?
                .join(".ssh/known_hosts")
                .to_string_lossy()
                .into(),
        ]);
    }
    let temp = tempfile::tempdir()?;
    let ready = temp.path().join("ready");
    std::fs::File::create(&ready)?;
    let exe = std::env::current_exe()?;
    let exe = exe.to_str().context("invalid executable path")?;
    let path = ready.to_str().context("invalid readiness path")?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let helper_args = [
        "-ui",
        "-ui-helper",
        "-ui-no-browser",
        "-ui-ready-file",
        path,
    ];
    #[cfg(target_os = "macos")]
    let mut launcher = {
        let command = std::iter::once(exe)
            .chain(helper_args)
            .map(shell_quote)
            .collect::<Vec<_>>()
            .join(" ")
            + " </dev/null >/dev/null 2>&1 &";
        tokio::process::Command::new("/usr/bin/osascript")
            .args([
                "-e",
                &format!(
                    "do shell script {} with administrator privileges",
                    serde_json::to_string(&command)?
                ),
            ])
            .spawn()?
    };
    #[cfg(target_os = "linux")]
    let mut launcher = tokio::process::Command::new("pkexec")
        .arg(exe)
        .args(helper_args)
        .spawn()?;
    #[cfg(windows)]
    let mut launcher = {
        let line = format!("-ui -ui-helper -ui-no-browser -ui-ready-file \"{path}\"");
        tokio::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -WindowStyle Hidden",
                    ps_quote(exe),
                    ps_quote(&line)
                ),
            ])
            .spawn()?
    };
    let mut helper = None;
    for _ in 0..400 {
        let text = tokio::fs::read_to_string(&ready).await.unwrap_or_default();
        if !text.trim().is_empty() {
            helper = Some(valid_helper(&text)?);
            break;
        }
        if let Some(status) = launcher.try_wait()? {
            ensure!(
                status.success(),
                "administrator authorization was declined or the helper failed"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let helper = helper.context("timed out waiting for administrator helper")?;
    let result = async {
        helper_request(
            &control,
            "helper/attach",
            Some(json!({"url":helper.as_str()})),
        )
        .await?;
        helper_request(&control, "start", Some(json!({"args":args}))).await
    }
    .await;
    if result.is_err() {
        let _ = helper_request(&helper, "quit", Some(json!({}))).await;
    }
    result
}
