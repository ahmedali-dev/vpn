//! Connection session lifecycle
//!
//! Starts, cancels and joins one connection session and its cleanup task.

use super::orchestrator::run;
use super::status::Reporter;
use crate::config::Config;
use crate::recovery::permanent;
use serde_json::Value;
use serde_json::json;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub struct Session {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    pub report: Reporter,
}
impl Session {
    pub fn start(config: Config) -> Self {
        let report = Reporter::persistent(&config);
        Self::start_with_report(config, report)
    }
    pub fn start_with_report(config: Config, report: Reporter) -> Self {
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        report.state("connecting");
        let r = report.clone();
        let task = tokio::spawn(async move {
            let result = run(config, c.clone(), r.clone()).await;
            {
                let mut status = r.0.lock().unwrap();
                if status.recovery.is_object() {
                    status.recovery["nextRetryAt"] = Value::Null;
                }
            }
            if c.is_cancelled()
                && !result.as_ref().err().is_some_and(|e| {
                    crate::recovery::category(e) == crate::recovery::FailureCategory::Cleanup
                })
            {
                r.state("disconnected");
                r.health("disconnected", "");
            } else if let Err(e) = result {
                let message = r.clean(&format!("{e:#}"));
                r.event("ERROR", "SESSION", &message);
                r.health("failed", &message);
                let mut s = r.0.lock().unwrap();
                if !s.recovery.is_object() {
                    s.recovery = json!({});
                }
                s.recovery["lastFailure"] = json!({"reason":message,"terminal":permanent(&e),"category":crate::recovery::category(&e),"at":chrono::Utc::now().to_rfc3339()});
                s.error = message;
                s.state = "error".into();
            } else {
                r.state("disconnected");
            }
        });
        Self {
            cancel,
            task,
            report,
        }
    }
    pub fn active(&self) -> bool {
        !self.task.is_finished()
    }
    pub async fn stop(&mut self) {
        self.report.event(
            "INFO",
            "SHUTDOWN",
            "Disconnect requested; cancelling connection tasks",
        );
        self.report.state("stopping");
        self.cancel.cancel();
        if tokio::time::timeout(Duration::from_secs(45), &mut self.task)
            .await
            .is_err()
        {
            self.report.event(
                "WARN",
                "SHUTDOWN",
                "Graceful shutdown timed out after 45s; cancelling task",
            );
            self.task.abort();
            let _ = (&mut self.task).await;
            let mut status = self.report.0.lock().unwrap();
            let reason = "Shutdown timed out; networking cleanup is not verified. Inspect adapters and routes before reconnecting.";
            status.error = reason.into();
            status.state = "error".into();
            status.recovery["lastFailure"] =
                json!({"category":"cleanup","reason":reason,"terminal":true});
            return;
        }
        if self.report.snapshot()["state"] != "error" {
            self.report.state("disconnected");
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
