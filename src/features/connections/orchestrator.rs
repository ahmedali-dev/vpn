//! Connection retry orchestrator
//!
//! Coordinates attempts, recovery policy, network-change cancellation and transport/core selection.

use super::attempt::run_once;
use super::preparation::prepare;
use super::status::Reporter;
use crate::config::Config;
use crate::infrastructure::privileges::is_admin;
use crate::recovery::RetryPolicy;
use crate::recovery::permanent;
use crate::transport;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(super) async fn run(mut c: Config, cancel: CancellationToken, r: Reporter) -> Result<()> {
    ensure!(
        !c.tun() || is_admin(),
        "full-device TUN requires the administrator helper"
    );
    let (host, port, sni, setting, ca) = if c.mode() == "ssh" {
        (
            c.get("H", "").to_string(),
            c.number("P", 0)? as u16,
            if c.get("S", "").is_empty() {
                c.get("H", "")
            } else {
                c.get("S", "")
            }
            .to_string(),
            c.get("ssh-cert-sha256", "auto").to_string(),
            c.get("tls-ca", "").to_string(),
        )
    } else if c.get("v2ray-config", "").is_empty() {
        let p = c.protocol()?;
        (
            p.address,
            p.port as u16,
            p.effective_sni,
            if p.security == "tls" {
                c.get("v2ray-cert-sha256", "auto")
            } else {
                "none"
            }
            .into(),
            String::new(),
        )
    } else {
        (
            String::new(),
            0,
            String::new(),
            "none".into(),
            String::new(),
        )
    };
    r.0.lock().unwrap().connection =
        json!({"server":transport::authority(&host,port),"sni":sni,"mode":c.mode()});
    r.event(
        "INFO",
        "ROUTING",
        format!(
            "Device routing policy: {} rule(s), LAN bypass={}; {}",
            c.routing_rules()?.len(),
            c.boolean("bypass-lan"),
            if c.tun() {
                "active in full-device mode"
            } else {
                "inactive in proxy mode"
            }
        ),
    );
    {
        let mut status = r.0.lock().unwrap();
        status.connection["sshHost"] = json!(if c.mode() == "ssh" { host.as_str() } else { "" });
        status.connection["sshPort"] = json!(port);
        status.connection["tlsTrust"] = json!(if !c.get("v2ray-config", "").is_empty() {
            "custom_config"
        } else if c.mode() != "ssh" && c.protocol().is_ok_and(|p| p.security == "none") {
            "not_enabled"
        } else if c.mode() != "ssh" && c.protocol().is_ok_and(|p| p.security == "reality") {
            "reality_key"
        } else if setting == "insecure" {
            "session_unverified"
        } else if setting == "auto" || setting == "none" {
            "certificate_verified"
        } else {
            "configured_pin"
        });
    }
    // Explicit compatibility pins survive restarts for this connection session only.
    let mut compatibility_pin = None;
    let tofu_key = Arc::new(Mutex::new(None));
    let (_network_task, mut network) =
        crate::network::watch_network(&c, cancel.clone(), r.clone())?;
    let mut retries = RetryPolicy::default();
    let mut attempt = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        while network.borrow().online == Some(false) {
            r.health(
                "offline",
                "Waiting for a physical network before reconnecting",
            );
            tokio::select! {_=cancel.cancelled()=>return Ok(()),value=network.changed()=>if value.is_err(){return Err(anyhow::anyhow!("network monitor stopped"));}}
        }
        let attempt_cancel = cancel.child_token();
        let _network_guard =
            crate::network::interrupt_on_change(network.clone(), attempt_cancel.clone());
        attempt += 1;
        let started = std::time::Instant::now();
        let mut connected_for = Duration::ZERO;
        r.state(if attempt == 1 {
            "connecting"
        } else {
            "reconnecting"
        });
        r.health("connecting", "");
        if c.mode() == "ssh" {
            let mut status = r.0.lock().unwrap();
            status.connection["sshAuthenticated"] = json!(false);
            status.connection["sshTrust"] = json!("pending");
        }
        r.0.lock().unwrap().checks = json!({"proxyHttps":"pending","systemDns":if c.tun(){"pending"}else{"not_applicable"},"systemIpv4":if c.tun(){"pending"}else{"not_applicable"},"ipv6":"not_verified"});
        {
            let mut status = r.0.lock().unwrap();
            if !status.recovery.is_object() {
                status.recovery = json!({});
            }
            status.recovery["attempt"] = json!(attempt);
            status.recovery["attemptStartedAt"] = json!(chrono::Utc::now().to_rfc3339());
            status.recovery["consecutiveFailures"] = json!(retries.failures());
            status.recovery["nextRetryAt"] = Value::Null;
        }
        r.event(
            "INFO",
            "CONNECT",
            format!(
                "Attempt {attempt}; server={host}:{port}; SNI={sni}; certificate mode={setting}"
            ),
        );
        let result: Result<()> = async {
            let excluded = tokio::select! {
                _ = attempt_cancel.cancelled() => return Ok(()),
                value = r.stage("DNS preparation", prepare(&mut c, &r)) => value.context("upstream DNS preparation failed")?,
            };
            let pin = if setting == "insecure" && compatibility_pin.is_some() {
                compatibility_pin.clone()
            } else {
                tokio::select! {
                    _ = attempt_cancel.cancelled() => return Ok(()),
                    value = r.stage("TLS discovery", async { tokio::time::timeout(Duration::from_secs(45), transport::resolve_pin(&host,port,&sni,&setting,&ca,c.get("tls-version","auto"))).await.context("TLS discovery timed out after 45s")? }) => value.context("TLS certificate discovery/verification failed")?,
                }
            };
            if setting == "insecure" { compatibility_pin = pin.clone(); }
            run_once(&c, &excluded, pin.as_deref(), attempt_cancel.clone(), r.clone(), tofu_key.clone(), &mut connected_for).await
        }.await;
        if cancel.is_cancelled() {
            return match result {
                Err(e)
                    if crate::recovery::category(&e)
                        == crate::recovery::FailureCategory::Cleanup =>
                {
                    Err(e)
                }
                _ => Ok(()),
            };
        }
        let result =
            if attempt_cancel.is_cancelled() && !result.as_ref().err().is_some_and(permanent) {
                Err(anyhow::Error::new(crate::network::NetworkChanged))
            } else {
                result
            };
        let error = match result {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let connected = connected_for;
        r.health("degraded", &error.to_string());
        r.event(
            "ERROR",
            "CONNECT",
            format!(
                "Attempt {attempt} failed after {}ms; connected={}ms: {error:#}",
                started.elapsed().as_millis(),
                connected.as_millis()
            ),
        );
        if error.is::<crate::network::NetworkChanged>() {
            retries = RetryPolicy::default();
            r.event("INFO","RECONNECT", "Network recovery: previous attempt cleaned up; refreshing DNS and route exclusions");
            continue;
        }
        let terminal = permanent(&error);
        let delay = if terminal {
            None
        } else {
            retries.failed(connected, rand::random::<f64>())
        };
        {
            let mut status = r.0.lock().unwrap();
            let reason: String = status
                .redactor
                .clean(&format!("{error:#}"))
                .chars()
                .take(4000)
                .collect();
            status.recovery["lastFailure"] = json!({"reason":reason,"terminal":terminal,"category":crate::recovery::category(&error),"at":chrono::Utc::now().to_rfc3339()});
            status.recovery["consecutiveFailures"] = json!(retries.failures());
            if status.recovery["recoveryStartedAt"].is_null() {
                status.recovery["recoveryStartedAt"] = json!(chrono::Utc::now().to_rfc3339());
            }
            status.recovery["nextRetryAt"] = json!(delay.map(|d| {
                (chrono::Utc::now() + chrono::Duration::milliseconds(d.as_millis() as i64))
                    .to_rfc3339()
            }));
        }
        let Some(delay) = delay else {
            r.event(
                "ERROR",
                "RECONNECT",
                if terminal {
                    "Stopped: credentials, trust, permissions or configuration require attention"
                } else {
                    "Stopped: six consecutive connection failures"
                },
            );
            return Err(error);
        };
        r.event(
            "WARN",
            "RECONNECT",
            format!(
                "Retrying in {}ms; consecutive failures={}/6",
                delay.as_millis(),
                retries.failures()
            ),
        );
        tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = attempt_cancel.cancelled()=>{retries=RetryPolicy::default();}, _ = tokio::time::sleep(delay) => () }
    }
}
