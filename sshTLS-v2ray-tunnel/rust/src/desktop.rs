//! Rust desktop shell. The embedded HTML/CSS interface uses the same local API as CLI -ui.
use crate::{
    config::Config,
    control::{self, helper_request, valid_helper},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use tokio_util::sync::CancellationToken;

const BRIDGE: &str = r#"(() => {
if(window!==window.top)return;
let next=0;const pending=new Map();
window.__tnNativeComplete=(id,value,error)=>{const p=pending.get(id);if(!p)return;pending.delete(id);if(error)p.reject(new Error(error));else p.resolve(value);};
const call=(kind,value)=>new Promise((resolve,reject)=>{const id=++next;pending.set(id,{resolve,reject});window.ipc.postMessage(JSON.stringify({id,kind,value}));});
Object.defineProperty(window,'tunnelDesktop',{value:Object.freeze({connectPrivileged:args=>call('connect',args),saveShareFile:request=>call('save',request)}),writable:false});
})();"#;
#[derive(Debug)]
enum NativeEvent {
    Reply(u64, Value, Option<String>),
    Exit,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    id: u64,
    kind: String,
    value: Value,
}

pub fn run() -> Result<()> {
    ensure!(
        !crate::runtime::is_admin(),
        "launch the desktop window as your normal user"
    );
    let runtime = Arc::new(tokio::runtime::Runtime::new()?);
    let cancel = CancellationToken::new();
    let (sender, ready) = tokio::sync::oneshot::channel();
    let config = Config::parse(&["-ui".into(), "-ui-no-browser".into()])?;
    let server = runtime.spawn(control::serve_with_ready(
        config,
        cancel.clone(),
        Some(sender),
    ));
    let signal_cancel = cancel.clone();
    runtime.spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! {_=tokio::signal::ctrl_c()=>(),_=term.recv()=>()}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        signal_cancel.cancel();
    });
    let raw = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(30), ready).await })??;
    let control_url = valid_helper(&raw)?;
    let origin = control_url.origin().ascii_serialization();
    let event_loop = EventLoopBuilder::<NativeEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let exit_proxy = proxy.clone();
    runtime.spawn(async move {
        let _ = server.await;
        let _ = exit_proxy.send_event(NativeEvent::Exit);
    });
    let window = WindowBuilder::new()
        .with_title("TunnelNest · Rust")
        .with_inner_size(tao::dpi::LogicalSize::new(1320., 960.))
        .with_min_inner_size(tao::dpi::LogicalSize::new(820., 650.))
        .build(&event_loop)?;
    let busy = Arc::new(AtomicBool::new(false));
    let rt = runtime.clone();
    let proxy_ipc = proxy.clone();
    let ipc_origin = origin.clone();
    let builder = wry::WebViewBuilder::new()
        .with_url(&raw)
        .with_initialization_script(BRIDGE)
        .with_navigation_handler(move |url| {
            url::Url::parse(&url).is_ok_and(|u| u.origin().ascii_serialization() == origin)
        })
        .with_new_window_req_handler(|_, _| wry::NewWindowResponse::Deny)
        .with_ipc_handler(move |request| {
            if request.body().len() > 2 * 1024 * 1024
                || !url::Url::parse(&request.uri().to_string())
                    .is_ok_and(|u| u.origin().ascii_serialization() == ipc_origin)
            {
                return;
            }
            let Ok(message) = serde_json::from_str::<Message>(request.body()) else {
                return;
            };
            let id = message.id;
            if message.kind == "save" {
                let result = save_share_file(message.value);
                let event = match result {
                    Ok(v) => NativeEvent::Reply(id, v, None),
                    Err(e) => NativeEvent::Reply(id, Value::Null, Some(e.to_string())),
                };
                let _ = proxy_ipc.send_event(event);
            } else if message.kind == "connect" {
                if busy.swap(true, Ordering::SeqCst) {
                    let _ = proxy_ipc.send_event(NativeEvent::Reply(
                        id,
                        Value::Null,
                        Some("Administrator authorization is already in progress".into()),
                    ));
                    return;
                }
                let url = control_url.clone();
                let proxy = proxy_ipc.clone();
                let busy = busy.clone();
                rt.spawn(async move {
                    let result = connect_privileged(url, message.value).await;
                    busy.store(false, Ordering::SeqCst);
                    let event = match result {
                        Ok(v) => NativeEvent::Reply(id, v, None),
                        Err(e) => NativeEvent::Reply(id, Value::Null, Some(e.to_string())),
                    };
                    let _ = proxy.send_event(event);
                });
            }
        });
    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        builder.build_gtk(
            window
                .default_vbox()
                .context("GTK window container unavailable")?,
        )?
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window)?;
    let mut closing = false;
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } if !closing => {
                closing = true;
                cancel.cancel();
            }
            Event::UserEvent(NativeEvent::Reply(id, value, error)) => {
                let script = format!(
                    "window.__tnNativeComplete({id},{},{});",
                    value,
                    serde_json::to_string(&error).unwrap()
                );
                let _ = webview.evaluate_script(&script);
            }
            Event::UserEvent(NativeEvent::Exit) => *flow = ControlFlow::Exit,
            _ => (),
        }
    });
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
