//! Regression tests for connection orchestration and recovery.
use super::core_logs::core_line;
use super::core_logs::pipe_log;
use super::forwarding::socks_connection;
use super::health::check_endpoints;
use super::health::finish_core_logs;
use super::health::matching_exit;
use super::health::monitor_connection;
use super::health::parse_exit;
use super::health::startup_work;
use super::health::wait_ready;
use super::status::Reporter;
use crate::config::Config;
use crate::transport;
use anyhow::Result;
use anyhow::bail;
use serde_json::json;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
#[path = "../../../tests/common/mod.rs"]
mod test_server;

#[cfg(test)]
mod forwarding_tests {
    use super::*;

    #[tokio::test]
    async fn cached_ipv6_requests_recover_hostname_over_verified_tls_ssh() {
        for data in [
            crate::hostname::tests::client_hello(true),
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        ] {
            recovered_request(&data).await;
        }
    }

    async fn recovered_request(data: &[u8]) {
        let server = test_server::server().await;
        let c = Config::parse(&[
            "-H".into(),
            "127.0.0.1".into(),
            "-P".into(),
            server.port.to_string(),
            "-S".into(),
            "localhost".into(),
            "-u".into(),
            "alice".into(),
            "-p".into(),
            "secret".into(),
            "-tls-ca".into(),
            server.ca.path().to_str().unwrap().into(),
            "-ssh-host-key".into(),
            server.ssh_fingerprint.clone(),
        ])
        .unwrap();
        let report = Reporter::default();
        let ssh = Arc::new(
            transport::connect_ssh_logged(
                &c,
                Some(&server.certificate_pin),
                Arc::new(Mutex::new(None)),
                report.clone(),
            )
            .await
            .unwrap(),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let log = report.clone();
        let task = tokio::spawn(async move { socks_connection(stream, ssh, true, &log).await });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 4];
        request.extend_from_slice(
            &"2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        client.write_all(data).await.unwrap();
        let mut echo = vec![0; data.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echo, data);
        drop(client);
        task.await.unwrap().unwrap();
        let snapshot = report.snapshot();
        let text = snapshot["logs"].as_str().unwrap();
        assert!(
            text.contains("Opening TCP channel to example.com:443"),
            "{text}"
        );
        assert!(!text.contains("Opening TCP channel to 2001:db8"), "{text}");
    }
}

#[cfg(test)]
mod recovery_monitor_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn pending_probe_does_not_block_liveness_or_leak_on_exit() {
        let probes = Arc::new(AtomicUsize::new(0));
        let active = probes.clone();
        let mut ticks = 0;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            monitor_connection(
                CancellationToken::new(),
                Reporter::default(),
                || {
                    ticks += 1;
                    if ticks >= 5 {
                        bail!("child stopped")
                    }
                    Ok(())
                },
                move || {
                    let active = active.clone();
                    async move {
                        struct Guard(Arc<AtomicUsize>);
                        impl Drop for Guard {
                            fn drop(&mut self) {
                                self.0.fetch_sub(1, Ordering::SeqCst);
                            }
                        }
                        active.fetch_add(1, Ordering::SeqCst);
                        let _guard = Guard(active);
                        std::future::pending::<Result<()>>().await
                    }
                },
                Duration::from_millis(10),
                Duration::from_millis(1),
            ),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("child stopped"));
        assert_eq!(probes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn intermittent_failures_recover_and_only_three_consecutive_failures_restart() {
        let report = Reporter::default();
        let mut cycle = 0;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            monitor_connection(
                CancellationToken::new(),
                report.clone(),
                || Ok(()),
                || {
                    cycle += 1;
                    let pass = cycle == 3;
                    async move {
                        if pass {
                            Ok(())
                        } else {
                            bail!("temporary probe failure")
                        }
                    }
                },
                Duration::from_millis(1),
                Duration::from_millis(2),
            ),
        )
        .await
        .unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("three consecutive")
        );
        assert_eq!(cycle, 6);
        assert_eq!(report.snapshot()["health"]["state"], "degraded");
    }
    #[tokio::test]
    async fn cancellation_stops_pending_health_work() {
        let token = CancellationToken::new();
        let stop = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            stop.cancel();
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            monitor_connection(
                token,
                Reporter::default(),
                || Ok(()),
                std::future::pending::<Result<()>>,
                Duration::from_millis(1),
                Duration::from_millis(1),
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }
}

#[cfg(test)]
mod recovery_diagnostics_tests {
    use super::*;
    #[tokio::test]
    async fn completed_stages_and_recovery_timing_are_exported() {
        let r = Reporter::default();
        {
            let mut s = r.0.lock().unwrap();
            s.recovery = json!({"attempt":2,"attemptStartedAt":(chrono::Utc::now()-chrono::Duration::seconds(2)).to_rfc3339(),
                "recoveryStartedAt":(chrono::Utc::now()-chrono::Duration::seconds(5)).to_rfc3339(),
                "lastFailure":{"reason":"temporary failure"},"nextRetryAt":"old retry"});
        }
        r.stage("test stage", async { Ok(()) }).await.unwrap();
        r.connected();
        let snapshot = r.snapshot();
        assert_eq!(snapshot["recovery"]["lastStage"]["name"], "test stage");
        assert_eq!(snapshot["recovery"]["lastStage"]["success"], true);
        assert!(snapshot["recovery"]["startupMs"].as_i64().unwrap() >= 2000);
        assert!(snapshot["recovery"]["recoveryMs"].as_i64().unwrap() >= 5000);
        assert_eq!(
            snapshot["recovery"]["lastFailure"]["reason"],
            "temporary failure"
        );
        assert!(snapshot["recovery"]["nextRetryAt"].is_null());
        assert_eq!(snapshot["state"], "connected");
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    #[test]
    fn ordinary_internet_access_cannot_pass_as_working_vpn_routing() {
        assert_eq!(
            parse_exit(b"192.0.2.1", false).unwrap().to_string(),
            "192.0.2.1"
        );
        assert_eq!(
            parse_exit(b"fl=1\nip=192.0.2.2\nhttp=h2\n", true)
                .unwrap()
                .to_string(),
            "192.0.2.2"
        );
        assert!(parse_exit(b"::1", false).is_err());
        assert!(parse_exit(b"a web page instead of an IP", false).is_err());
        let proxy = "192.0.2.1".parse().unwrap();
        assert!(matching_exit(proxy, "192.0.2.2".parse().unwrap()).is_err());
        matching_exit(proxy, proxy).unwrap();
    }
    #[tokio::test]
    async fn readiness_retries_temporary_failures_without_a_fixed_startup_delay() {
        let mut calls = 0;
        assert!(
            wait_ready(
                CancellationToken::new(),
                Duration::from_secs(2),
                || Ok(()),
                || {
                    calls += 1;
                    let ready = calls >= 3;
                    async move {
                        if ready {
                            Ok(true)
                        } else {
                            bail!("routes not ready")
                        }
                    }
                }
            )
            .await
            .unwrap()
        );
        assert_eq!(calls, 3);
    }
    #[tokio::test]
    async fn readiness_monitors_core_death_while_probe_is_stuck() {
        let mut checks = 0;
        let error = wait_ready(
            CancellationToken::new(),
            Duration::from_secs(5),
            || {
                checks += 1;
                if checks == 2 {
                    bail!("core exited")
                }
                Ok(())
            },
            std::future::pending::<Result<bool>>,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("core exited"));
    }
    #[tokio::test]
    async fn readiness_deadline_and_cancel_bound_pending_work() {
        let error = wait_ready(
            CancellationToken::new(),
            Duration::from_millis(25),
            || Ok(()),
            std::future::pending::<Result<bool>>,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("readiness deadline"));
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            !wait_ready(
                cancel,
                Duration::from_secs(10),
                || Ok(()),
                std::future::pending::<Result<bool>>
            )
            .await
            .unwrap()
        );
    }
}

#[cfg(test)]
mod transport_probe_tests {
    use super::*;
    #[tokio::test]
    async fn error_burst_checks_a_live_transport_without_restarting_it() {
        let r = Reporter::default();
        let cancel = CancellationToken::new();
        let monitor = cancel.clone();
        let report = r.clone();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let probes = count.clone();
        let task = tokio::spawn(async move {
            monitor_connection(
                monitor,
                report,
                || Ok(()),
                move || {
                    let count = probes.clone();
                    async move {
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    }
                },
                Duration::from_millis(1),
                Duration::from_secs(3600),
            )
            .await
        });
        for _ in 0..3 {
            core_line(
                &r,
                "CORE/STDOUT",
                b"connection ends > websocket: close 1006 (abnormal closure): unexpected EOF",
                false,
            );
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while count.load(std::sync::atomic::Ordering::SeqCst) == 0
                || r.snapshot()["health"]["state"] != "healthy"
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            !task.is_finished(),
            "successful probes must keep the existing transport alive"
        );
        assert_eq!(r.snapshot()["transportErrors"]["websocketClosures"], 3);
        assert!(
            r.snapshot()["logs"]
                .as_str()
                .unwrap()
                .contains("[WARN] [CORE/STDOUT]")
        );
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
    #[test]
    fn cursors_remain_valid_when_unicode_logs_roll_over() {
        let r = Reporter::default();
        for n in 0..1500 {
            r.event("INFO", "TEST", format!("{n} مرحبا {}", "x".repeat(80)));
        }
        let s = r.snapshot();
        assert!(s["logStart"].as_u64().unwrap() > 0);
        assert_eq!(
            s["logEnd"].as_u64().unwrap() - s["logStart"].as_u64().unwrap(),
            s["logs"].as_str().unwrap().len() as u64
        );
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;
    async fn response(status: u16, wait: Duration) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await;
            tokio::time::sleep(wait).await;
            let _ = stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await;
        });
        (format!("http://{addr}/"), task)
    }
    #[tokio::test]
    async fn passing_endpoint_does_not_wait_for_a_stalled_endpoint() {
        let (slow, slow_task) = response(200, Duration::from_secs(3)).await;
        let (fast, fast_task) = response(200, Duration::ZERO).await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            check_endpoints(
                client,
                &[&slow, &fast],
                None,
                "test proxy",
                Duration::from_secs(2),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        slow_task.abort();
        fast_task.await.unwrap();
    }
    #[tokio::test]
    async fn failure_includes_http_status_timeout_endpoint_and_cause() {
        let (bad, bad_task) = response(503, Duration::ZERO).await;
        let (slow, slow_task) = response(200, Duration::from_secs(3)).await;
        let deadline = Duration::from_millis(100);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(deadline)
            .build()
            .unwrap();
        let error = check_endpoints(client, &[&bad, &slow], None, "test proxy", deadline)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("503"), "{error}");
        assert!(error.contains("timeout"), "{error}");
        assert!(error.contains(&bad));
        assert!(error.contains(&slow));
        bad_task.await.unwrap();
        slow_task.abort();
    }
    #[test]
    fn xray_deprecation_warnings_are_not_promoted_by_the_common_errors_package_name() {
        let r = Reporter::default();
        core_line(
            &r,
            "CORE/STDOUT",
            b"2026/10/27 21:47:01 [Warning] common/errors: The feature VMess is deprecated",
            false,
        );
        assert!(
            r.snapshot()["logs"]
                .as_str()
                .unwrap()
                .contains("[WARN] [CORE/STDOUT]")
        );
        assert!(!r.snapshot()["logs"].as_str().unwrap().contains("[ERROR]"));
    }
}

#[cfg(test)]
mod startup_guard_tests {
    use super::*;
    #[tokio::test]
    async fn core_exit_interrupts_a_pending_verification_and_cancellation_is_not_success() {
        let started = std::time::Instant::now();
        let result = startup_work(
            CancellationToken::new(),
            || Err(anyhow::anyhow!("core exited").context(crate::recovery::FailureCategory::Core)),
            std::future::pending::<Result<()>>(),
        )
        .await;
        assert_eq!(
            crate::recovery::category(&result.unwrap_err()),
            crate::recovery::FailureCategory::Core
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            startup_work(cancel, || Ok(()), async { Ok(()) })
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn readiness_preserves_dns_origin_through_the_deadline_and_outer_stage() {
        let report = Reporter::default();
        let error = report
            .stage(
                "TUN interface and route readiness",
                wait_ready(
                    CancellationToken::new(),
                    Duration::from_millis(20),
                    || Ok(()),
                    || async {
                        Err(anyhow::anyhow!("system DNS failed")
                            .context(crate::recovery::FailureCategory::Dns))
                    },
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(
            crate::recovery::category(&error),
            crate::recovery::FailureCategory::Dns
        );
        assert_eq!(
            report.snapshot()["recovery"]["lastStage"]["category"],
            "dns"
        );
    }
    #[tokio::test]
    async fn verification_result_and_failure_are_preserved() {
        assert_eq!(
            startup_work(CancellationToken::new(), || Ok(()), async { Ok(42) })
                .await
                .unwrap(),
            Some(42)
        );
        let error = startup_work(CancellationToken::new(), || Ok(()), async {
            Err::<(), _>(
                anyhow::anyhow!("DNS failed").context(crate::recovery::FailureCategory::Dns),
            )
        })
        .await
        .unwrap_err();
        assert_eq!(
            crate::recovery::category(&error),
            crate::recovery::FailureCategory::Dns
        );
    }
}

#[cfg(test)]
mod recovered_failure_tests {
    use super::*;
    #[test]
    fn successful_retry_marks_historical_failure_recovered_without_erasing_diagnostics() {
        let r = Reporter::default();
        r.0.lock().unwrap().recovery =
            json!({"lastFailure":{"category":"routing","reason":"TUN exited: exit status 0"}});
        r.connected();
        let status = r.snapshot();
        assert_eq!(status["state"], "connected");
        assert_eq!(status["health"]["state"], "healthy");
        assert!(status["recovery"]["lastFailure"]["recoveredAt"].is_string());
        assert_eq!(
            status["recovery"]["lastFailure"]["reason"],
            "TUN exited: exit status 0"
        );
    }
    #[tokio::test]
    async fn final_core_output_is_drained_before_cleanup_finishes() {
        let r = Reporter::default();
        let (reader, mut writer) = tokio::io::duplex(1024);
        let mut jobs = JoinSet::new();
        jobs.spawn(pipe_log(reader, r.clone(), "TUN/STDERR"));
        let write = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            writer
                .write_all(b"final TUN shutdown detail\n")
                .await
                .unwrap();
        });
        finish_core_logs(&mut jobs, &r).await;
        write.await.unwrap();
        assert!(
            r.snapshot()["logs"]
                .as_str()
                .unwrap()
                .contains("final TUN shutdown detail")
        );
        assert!(jobs.is_empty());
    }
}
