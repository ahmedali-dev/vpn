//! Networking core process service.
//!
//! Validates, launches, monitors and stops owned networking-core processes.

use crate::recovery::PermanentFailure;
use anyhow::Result;
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use tokio::process::Child;
use tokio::process::Command;

fn core_arguments(
    sing_box: bool,
    v2ray: bool,
    legacy: bool,
) -> (&'static [&'static str], &'static [&'static str]) {
    if sing_box {
        (&["check", "-c"], &["run", "-c"])
    } else if v2ray && legacy {
        (&["-test", "-config"], &["-config"])
    } else if v2ray {
        (&["test", "-c"], &["run", "-c"])
    } else {
        (&["run", "-test", "-config"], &["run", "-config"])
    }
}
pub struct CoreProcess {
    child: Option<Child>,
    _config: Option<NamedTempFile>,
    started: std::time::Instant,
    pid: Option<u32>,
    pub version: String,
}
impl CoreProcess {
    pub async fn start(
        binary: PathBuf,
        config: Option<Value>,
        custom: &str,
        sing_box: bool,
    ) -> Result<Self> {
        let file = if let Some(config) = config {
            let mut f = tempfile::Builder::new()
                .prefix("tunnelnest-")
                .suffix(".json")
                .tempfile()?;
            f.write_all(&serde_json::to_vec_pretty(&config)?)?;
            f.flush()?;
            Some(f)
        } else {
            None
        };
        let path = file
            .as_ref()
            .map(|f| f.path())
            .unwrap_or_else(|| std::path::Path::new(custom));
        // Validate configuration before starting a long-lived process. A failed
        // schema check is terminal; a validator timeout is still retryable.
        let is_v2ray = binary
            .file_stem()
            .is_some_and(|s| s.to_string_lossy().eq_ignore_ascii_case("v2ray"));
        let v2ray_legacy = if !sing_box && is_v2ray {
            let version = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                Command::new(&binary)
                    .arg("-version")
                    .kill_on_drop(true)
                    .output(),
            )
            .await??;
            version.status.success()
                && String::from_utf8_lossy(&version.stdout).starts_with("V2Ray 4.")
        } else {
            false
        };
        let (validation, run): (&[&str], &[&str]) =
            core_arguments(sing_box, is_v2ray, v2ray_legacy);
        let mut check = Command::new(&binary);
        check.args(validation);
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            check.arg(path).kill_on_drop(true).output(),
        )
        .await??;
        if !out.status.success() {
            let details: String = format!(
                "{} {}",
                String::from_utf8_lossy(&out.stderr),
                String::from_utf8_lossy(&out.stdout)
            )
            .chars()
            .take(8192)
            .collect();
            return Err(anyhow::anyhow!(
                "{} config validation failed ({}): {}",
                if sing_box { "TUN" } else { "Core" },
                out.status,
                details
            )
            .context(PermanentFailure::Configuration));
        }
        // Version metadata never includes the executable path or generated config.
        let version = match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            Command::new(&binary)
                .arg(if v2ray_legacy { "-version" } else { "version" })
                .kill_on_drop(true)
                .output(),
        )
        .await
        {
            Ok(Ok(out)) if out.status.success() => String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .unwrap_or("unknown")
                .chars()
                .take(200)
                .collect(),
            _ => "unavailable".into(),
        };
        let mut cmd = Command::new(binary);
        cmd.args(run)
            .arg(path)
            .kill_on_drop(false)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = cmd.spawn()?;
        let pid = child.id();
        Ok(Self {
            child: Some(child),
            _config: file,
            started: std::time::Instant::now(),
            pid,
            version,
        })
    }
    pub fn check_running(&mut self, name: &str) -> Result<()> {
        if let Some(status) = self.child().try_wait()? {
            return Err(anyhow::anyhow!(
                "{name} exited: {status}; PID={:?}; uptime={}ms",
                self.pid,
                self.started.elapsed().as_millis()
            )
            .context(if name.starts_with("TUN") {
                crate::recovery::FailureCategory::Routing
            } else {
                crate::recovery::FailureCategory::Core
            }));
        }
        Ok(())
    }
    pub fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("live core child")
    }
    pub async fn stop(&mut self) {
        if let Some(child) = self.child.take() {
            stop_child(child).await;
        }
    }
}
async fn stop_child(mut child: Child) {
    #[cfg(unix)]
    if let Some(id) = child.id() {
        unsafe {
            libc::kill(id as i32, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.start_kill();
    }
    if tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
        .await
        .is_err()
    {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}
impl Drop for CoreProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let config = self._config.take();
                runtime.spawn(async move {
                    stop_child(child).await;
                    drop(config);
                });
            } else {
                let mut child = child;
                let _ = child.start_kill();
            }
        }
    }
}

#[cfg(test)]
mod arguments_tests {
    use super::*;
    #[test]
    fn core_commands_match_xray_singbox_and_both_v2ray_generations() {
        assert_eq!(
            core_arguments(false, false, false).0,
            &["run", "-test", "-config"]
        );
        assert_eq!(core_arguments(true, false, false).0, &["check", "-c"]);
        assert_eq!(core_arguments(false, true, false).0, &["test", "-c"]);
        assert_eq!(core_arguments(false, true, true).1, &["-config"]);
    }
}
