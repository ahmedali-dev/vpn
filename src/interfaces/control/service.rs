//! Local control service
//!
//! Coordinates local sessions and elevated helpers; keeps helper failure recovery available to the UI.

use super::Control;
use super::Helper;
use super::LogCursor;
use super::helper::close_helper;
use super::helper::helper_request;
use super::helper::mirror_logs;
use super::helper::valid_helper;
use crate::config::Config;
use crate::logging;
use crate::runtime::Reporter;
use crate::runtime::Session;
use crate::runtime::is_admin;
use crate::store::Store;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde_json::Value;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

impl Control {
    pub fn new(
        host: String,
        token: String,
        helper_only: bool,
        store: Option<Store>,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            host,
            token,
            helper_only,
            cancel,
            session: AsyncMutex::new(None),
            diagnosing: AsyncMutex::new(()),
            cloud: AsyncMutex::new(None),
            store: Mutex::new(store),
            helper: AsyncMutex::new(None),
            helper_failure: Mutex::new(None),
            last_lease: AtomicU64::new(0),
            epoch: Instant::now(),
            log_dir: Mutex::new(logging::default_dir().ok()),
        })
    }
    pub fn set_log_dir(&self, dir: PathBuf) {
        *self.log_dir.lock().unwrap() = Some(dir);
    }
    pub(super) fn log_dir(&self) -> Result<PathBuf> {
        self.log_dir
            .lock()
            .unwrap()
            .clone()
            .context("log directory unavailable")
    }
    pub(super) async fn helper_url(&self) -> Option<url::Url> {
        self.helper.lock().await.as_ref().map(|h| h.url.clone())
    }
    pub(super) async fn stop(&self) -> Result<()> {
        if let Some(url) = self.helper_url().await {
            if helper_request(&url, "stop", Some(json!({}))).await.is_err() {
                self.detach_failed_helper(&url).await;
            } else {
                let _ = self.status().await;
            }
        }
        let mut session = self.session.lock().await;
        if let Some(s) = session.as_mut() {
            s.stop().await;
        }
        Ok(())
    }
    pub(super) async fn status(&self) -> Result<Value> {
        // A replaced helper must never inherit an old helper's status or logs.
        for _ in 0..2 {
            let Some(url) = self.helper_url().await else {
                break;
            };
            let response = helper_request(&url, "status", None).await;
            if self.helper_url().await.as_ref() != Some(&url) {
                continue;
            }
            let mut v = match response {
                Ok(v) => v,
                Err(_) => {
                    self.detach_failed_helper(&url).await;
                    continue;
                }
            };
            let attached = self.helper.lock().await;
            let Some(h) = attached.as_ref().filter(|h| h.url == url) else {
                continue;
            };
            mirror_logs(&h.mirror, &h.last, &v);
            let local = h.mirror.snapshot();
            v["logFile"] = local["logFile"].clone();
            v["logError"] = local["logError"].clone();
            v["administrator"] = json!(is_admin());
            v["helperAvailable"] = json!(true);
            v["version"] = json!(env!("CARGO_PKG_VERSION"));
            return Ok(v);
        }
        Ok(self.local_status().await)
    }
    pub(super) async fn local_status(&self) -> Value {
        if let Some(value) = self.helper_failure.lock().unwrap().clone() {
            return value;
        }
        let session = self.session.lock().await;
        let mut status = session
            .as_ref()
            .map(|s| s.report.snapshot())
            .unwrap_or_else(|| Reporter::default().snapshot());
        status["version"] = json!(env!("CARGO_PKG_VERSION"));
        status["helperAvailable"] = json!(false);
        status
    }
    pub(super) async fn detach_failed_helper(&self, url: &url::Url) {
        let mut attached = self.helper.lock().await;
        if attached.as_ref().is_none_or(|h| h.url != *url) {
            return;
        }
        let helper = attached.take().unwrap();
        let reason = "Administrator helper disconnected. Previous VPN cleanup is unverified; reconnect to authorize a fresh helper.";
        helper.mirror.event("ERROR", "HELPER", reason);
        let mut snapshot = helper.mirror.snapshot();
        snapshot["state"] = json!("error");
        snapshot["error"] = json!(reason);
        snapshot["health"] = json!({"state":"failed","error":reason});
        snapshot["recovery"] = json!({"tunCleanupVerified":false,"lastFailure":{"category":"helper","reason":reason,"terminal":true}});
        snapshot["helperAvailable"] = json!(false);
        snapshot["version"] = json!(env!("CARGO_PKG_VERSION"));
        *self.helper_failure.lock().unwrap() = Some(snapshot);
        // Revoke renewal. The helper's bounded lease remains the cleanup backstop.
        helper.cancel.cancel();
    }
    pub(super) async fn start(&self, args: Vec<String>) -> Result<()> {
        let c = Config::parse(&args)?;
        ensure!(!c.boolean("ui"), "nested control servers are forbidden");
        ensure!(
            !self.helper_only || c.tun(),
            "privileged helper only accepts full-device connections"
        );
        if c.tun() && !is_admin() {
            let url = self
                .helper_url()
                .await
                .context("authorize the administrator helper for full-device routing")?;
            helper_request(&url, "start", Some(json!({"args":args}))).await?;
            return Ok(());
        }
        let mut session = self.session.lock().await;
        ensure!(
            !session.as_ref().is_some_and(Session::active),
            "disconnect the active connection first"
        );
        if let Some(helper) = self.helper.lock().await.take() {
            close_helper(helper).await;
        }
        let report = Reporter::persistent_in(&self.log_dir()?, &c);
        *self.helper_failure.lock().unwrap() = None;
        *session = Some(Session::start_with_report(c, report));
        Ok(())
    }
    pub(super) async fn attach(&self, raw: &str) -> Result<()> {
        ensure!(!self.helper_only, "helpers cannot attach another helper");
        let url = valid_helper(raw)?;
        ensure!(
            url.authority() != self.host,
            "cannot attach the control server to itself"
        );
        let status = helper_request(&url, "status", None).await?;
        ensure!(status["administrator"] == true, "helper is not elevated");
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        let u = url.clone();
        helper_request(&url, "lease", Some(json!({}))).await?;
        let mirror = Reporter::persistent_in(&self.log_dir()?, &Config::default());
        mirror.event(
            "INFO",
            "HELPER",
            "Administrator helper attached; mirroring connection logs to this user's log directory",
        );
        let last = Arc::new(Mutex::new(LogCursor::default()));
        let report = mirror.clone();
        let previous_logs = last.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {_=c.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(3))=>{
                    if helper_request(&u,"lease",Some(json!({}))).await.is_err(){report.event("ERROR","HELPER","Helper lease renewal failed");break;}
                    match helper_request(&u,"status",None).await{Ok(status)=>mirror_logs(&report,&previous_logs,&status),Err(_)=>report.event("WARN","HELPER","Could not retrieve helper status")}
                }}
            }
        });
        *self.helper_failure.lock().unwrap() = None;
        let previous = self.helper.lock().await.replace(Helper {
            url,
            cancel,
            task,
            mirror,
            last,
        });
        if let Some(old) = previous {
            close_helper(old).await;
        }
        Ok(())
    }
}
