//! Control server lifecycle
//!
//! Starts the loopback listener and enforces helper leases, ready-file lifecycle and browser startup.

use super::Control;
use super::helper::close_helper;
use super::http::router;
use crate::config::Config;
use crate::runtime::is_admin;
use crate::store::Store;
use crate::store::random;
use anyhow::Result;
use anyhow::ensure;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub(super) struct ReadyFile(Option<PathBuf>);
impl Drop for ReadyFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}
pub async fn serve(config: Config, cancel: CancellationToken) -> Result<()> {
    serve_with_ready(config, cancel, None).await
}
pub async fn serve_with_ready(
    config: Config,
    cancel: CancellationToken,
    notify: Option<tokio::sync::oneshot::Sender<String>>,
) -> Result<()> {
    let helper = config.boolean("ui-helper");
    ensure!(
        !helper || is_admin(),
        "helper requires administrator privileges"
    );
    let listener = TcpListener::bind(("127.0.0.1", config.number("ui-port", 0)? as u16)).await?;
    let host = listener.local_addr()?.to_string();
    let token = hex::encode(random::<32>());
    let store = if helper {
        None
    } else if notify.is_some() {
        // Native windows must appear before any interactive OS keychain access.
        // Existing keychain vaults can be unlocked from the rendered UI; password
        // vaults retain their usual unlock flow. No secret is read at startup.
        Some(Store::open_password(&Store::default_path()?)?)
    } else {
        Some(Store::open(&Store::default_path()?)?)
    };
    let c = Control::new(host.clone(), token.clone(), helper, store, cancel.clone());
    if !config.get("ui-helper-address-file", "").is_empty() {
        let path = config.get("ui-helper-address-file", "");
        c.attach(&tokio::fs::read_to_string(path).await?).await?;
        tokio::fs::remove_file(path).await?;
    }
    let url = format!("http://{host}/#{token}");
    let mut ready = ReadyFile(None);
    if !config.get("ui-ready-file", "").is_empty() {
        use std::io::Write;
        let path = PathBuf::from(config.get("ui-ready-file", ""));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).truncate(true).create(true);
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
        file.write_all(url.as_bytes())?;
        ready.0 = Some(path);
    }
    if !helper {
        println!("CONTROL_URL={url}");
    }
    if let Some(notify) = notify {
        let _ = notify.send(url.clone());
    }
    if !helper && !config.boolean("ui-no-browser") {
        let _ = webbrowser::open(&url);
    }
    let lease_c = c.clone();
    let lease = tokio::spawn(async move {
        if helper {
            loop {
                tokio::select! {_=lease_c.cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{if lease_c.epoch.elapsed().as_secs().saturating_sub(lease_c.last_lease.load(Ordering::Relaxed))>15{lease_c.cancel.cancel();break;}}}
            }
        }
    });
    let cleanup = c.clone();
    let shutdown = cancel.clone();
    let result = axum::serve(listener, router(c.clone()))
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
            let _ = cleanup.stop().await;
        })
        .await;
    lease.abort();
    let _ = lease.await;
    if let Some(helper) = c.helper.lock().await.take() {
        close_helper(helper).await;
    }
    result?;
    Ok(())
}

// Diagnostics export uses a deliberate allowlist in diagnostics.rs.
