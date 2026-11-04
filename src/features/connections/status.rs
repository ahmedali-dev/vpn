//! Session state and reporting
//!
//! Keeps the connection snapshot, health, recovery data and redacted activity log in sync.

use crate::config::Config;
use crate::core::CoreProcess;
use crate::infrastructure::privileges::is_admin;
use crate::logging;
use crate::logging::Redactor;
use crate::logging::SessionFile;
use anyhow::Result;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Default)]
pub struct Status {
    pub state: String,
    pub error: String,
    pub logs: String,
    pub log_end: u64,
    pub log_session: String,
    pub connection: Value,
    pub health: Value,
    pub cores: Value,
    pub checks: Value,
    pub recovery: Value,
    pub traffic: crate::traffic::TrafficErrors,
    pub probe_requested: Arc<tokio::sync::Notify>,
    pub log_error: String,
    pub log_file: Option<SessionFile>,
    pub redactor: Redactor,
}
#[derive(Clone)]
pub struct Reporter(pub Arc<Mutex<Status>>);
impl Default for Reporter {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Status {
            state: "disconnected".into(),
            log_session: hex::encode(rand::random::<[u8; 16]>()),
            ..Default::default()
        })))
    }
}
impl Reporter {
    pub fn persistent(config: &Config) -> Self {
        match logging::default_dir() {
            Ok(dir) => Self::persistent_in(&dir, config),
            Err(e) => {
                let r = Self::default();
                r.0.lock().unwrap().log_error = e.to_string();
                r
            }
        }
    }
    pub fn persistent_in(dir: &std::path::Path, config: &Config) -> Self {
        let r = Self::default();
        let result = SessionFile::create(dir);
        {
            let mut s = r.0.lock().unwrap();
            s.redactor = Redactor::for_config(config);
            match result {
                Ok(file) => s.log_file = Some(file),
                Err(e) => s.log_error = format!("Could not save logs: {e}"),
            }
        }
        r.event(
            "INFO",
            "SESSION",
            format!(
                "TunnelNest {} on {}/{}; mode={}; routing={}",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH,
                config.mode(),
                if config.tun() { "TUN" } else { "proxy" }
            ),
        );
        r
    }
    pub fn clean(&self, text: &str) -> String {
        self.0.lock().unwrap().redactor.clean(text)
    }
    pub fn log(&self, s: impl AsRef<str>) {
        self.event("INFO", "ENGINE", s);
    }
    pub fn event(&self, level: &str, component: &str, message: impl AsRef<str>) {
        let mut state = self.0.lock().unwrap();
        let clean = state.redactor.clean(message.as_ref());
        for line in clean.lines() {
            let line = if line.len() > 16000 {
                "[oversized log line omitted]"
            } else {
                line
            };
            let record = format!(
                "{} [{level}] [{component}] {line}\n",
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            );
            if let Some(file) = state.log_file.as_mut()
                && let Err(e) = file.append(&record)
            {
                state.log_error = format!("Could not save logs: {e}");
                state.log_file = None;
            }
            state.log_end = state.log_end.saturating_add(record.len() as u64);
            state.logs.push_str(&record);
        }
        while state.logs.len() > 65536 {
            let n = state
                .logs
                .char_indices()
                .nth(1024)
                .map(|x| x.0)
                .unwrap_or(state.logs.len());
            state.logs.drain(..n);
        }
    }
    pub fn state(&self, state: &str) {
        self.event("INFO", "STATE", format!("Connection state: {state}"));
        self.0.lock().unwrap().state = state.into();
    }
    pub fn health(&self, state: &str, error: &str) {
        let error = self.clean(error);
        self.0.lock().unwrap().health =
            json!({"state":state,"error":error,"lastCheck":chrono::Utc::now().to_rfc3339()});
    }
    pub(crate) async fn stage<T>(
        &self,
        name: &str,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let start = std::time::Instant::now();
        self.event("INFO", "STAGE", format!("{name} started"));
        let result = work.await.map_err(|e| {
            if e.downcast_ref::<crate::recovery::FailureCategory>()
                .is_some()
            {
                e
            } else {
                e.context(crate::recovery::stage_category(name))
            }
        });
        let elapsed = start.elapsed().as_millis() as u64;
        self.event(
            if result.is_ok() { "INFO" } else { "WARN" },
            "STAGE",
            format!(
                "{name} {} after {elapsed}ms",
                if result.is_ok() {
                    "completed"
                } else {
                    "failed"
                }
            ),
        );
        let mut status = self.0.lock().unwrap();
        if !status.recovery.is_object() {
            status.recovery = json!({});
        }
        status.recovery["lastStage"] = json!({"name":name,"durationMs":elapsed,"success":result.is_ok(),"category":result.as_ref().err().map(crate::recovery::category)});
        result
    }
    pub(super) fn connected(&self) {
        let now = chrono::Utc::now();
        let (startup_ms, recovery_ms) = {
            let mut status = self.0.lock().unwrap();
            let elapsed = |key: &str| {
                status.recovery[key]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|at| {
                        (now - at.with_timezone(&chrono::Utc))
                            .num_milliseconds()
                            .max(0)
                    })
            };
            let startup = elapsed("attemptStartedAt");
            let recovery = elapsed("recoveryStartedAt");
            status.recovery["startupMs"] = json!(startup);
            status.recovery["recoveryMs"] = json!(recovery);
            status.recovery["recoveryStartedAt"] = Value::Null;
            status.recovery["nextRetryAt"] = Value::Null;
            if status.recovery["lastFailure"].is_object() {
                status.recovery["lastFailure"]["recoveredAt"] = json!(now.to_rfc3339());
            }
            status.error.clear();
            (startup, recovery)
        };
        self.event(
            "INFO",
            "CONNECT",
            format!(
                "Connection verified; startup={}ms; recovery={}ms",
                startup_ms.unwrap_or(0),
                recovery_ms.unwrap_or(0)
            ),
        );
        self.state("connected");
        self.health("healthy", "");
    }
    pub(super) fn traffic_failure(&self, kind: crate::traffic::Failure, message: &str) {
        let (due, notify) = {
            let mut s = self.0.lock().unwrap();
            let reason = s.redactor.clean(message);
            let due = s.traffic.record(kind, std::time::Instant::now(), reason);
            (due, s.probe_requested.clone())
        };
        if due {
            self.health(
                "degraded",
                "Multiple upstream streams failed; checking tunnel connectivity",
            );
            self.event("WARN","TRANSPORT","Upstream error burst: requesting an early connectivity check; keeping the tunnel alive until checks confirm a failure");
            notify.notify_one();
        }
    }
    pub(super) fn core_version(&self, role: &str, core: &CoreProcess) {
        let mut s = self.0.lock().unwrap();
        if !s.cores.is_object() {
            s.cores = json!({});
        }
        s.cores[role] = json!({"version":s.redactor.clean(&core.version)});
    }
    pub fn snapshot(&self) -> Value {
        let s = self.0.lock().unwrap();
        json!({"state":s.state,"error":s.error,"logs":s.logs,"logSession":s.log_session,"logStart":s.log_end.saturating_sub(s.logs.len() as u64),"logEnd":s.log_end,"connection":s.connection,"health":s.health,"cores":s.cores,"checks":s.checks,"recovery":s.recovery,"transportErrors":s.traffic.snapshot(std::time::Instant::now()),"administrator":is_admin(),"logFile":s.log_file.as_ref().map(|f|f.path.file_name().unwrap_or_default().to_string_lossy()),"logError":s.log_error})
    }
}
