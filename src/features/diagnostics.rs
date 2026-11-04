//! Profile diagnostics feature.
//!
//! Runs bounded read-only checks and builds sanitized troubleshooting reports.

//! Bounded profile preflight. Never authenticates, starts cores, or modifies routes.
use crate::{config::Config, transport};
use anyhow::{Context, Result, ensure};
use openssl::{
    asn1::Asn1Time,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    cmp::Ordering,
    pin::Pin,
    time::{Duration, Instant},
};
use tokio::net::{TcpStream, lookup_host};
use tokio_openssl::SslStream;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    stage: &'static str,
    state: &'static str,
    message: String,
    next_action: &'static str,
    duration_ms: u128,
}
fn check(
    stage: &'static str,
    state: &'static str,
    message: impl Into<String>,
    next_action: &'static str,
    start: Instant,
) -> Check {
    Check {
        stage,
        state,
        message: message.into(),
        next_action,
        duration_ms: start.elapsed().as_millis(),
    }
}
struct Target {
    host: String,
    port: u16,
    sni: String,
    tls: bool,
    setting: String,
    ca: String,
}
fn target(c: &Config) -> Result<Target> {
    ensure!(
        c.get("v2ray-config", "").is_empty(),
        "Custom core configurations require a live connection to diagnose"
    );
    ensure!(
        c.get("proxy", "").is_empty() && c.get("payload-file", "").is_empty(),
        "Profiles using HTTP CONNECT or custom payloads require a live connection to diagnose"
    );
    let t = if c.mode() == "ssh" {
        let host = c.get("H", "").to_owned();
        Target {
            sni: if c.get("S", "").is_empty() {
                host.clone()
            } else {
                c.get("S", "").to_owned()
            },
            host,
            port: c.number("P", 0)? as u16,
            tls: true,
            setting: c.get("ssh-cert-sha256", "auto").into(),
            ca: c.get("tls-ca", "").into(),
        }
    } else {
        let p = c.protocol()?;
        ensure!(
            p.security != "reality",
            "REALITY identity requires a live protocol connection to diagnose"
        );
        Target {
            host: p.address,
            port: p.port as u16,
            sni: p.effective_sni,
            tls: p.security == "tls",
            setting: c.get("v2ray-cert-sha256", "auto").into(),
            ca: String::new(),
        }
    };
    ensure!(
        !t.host.is_empty() && t.port > 0,
        "Set a server address and port in this profile"
    );
    Ok(t)
}
fn certificate_check(cert: &X509) -> Result<(&'static str, String, &'static str)> {
    let now = Asn1Time::days_from_now(0)?;
    if cert.not_after().compare(&now)? == Ordering::Less {
        Ok((
            "failed",
            format!("Server certificate expired on {}.", cert.not_after()),
            "Ask the server operator to renew the certificate. Compatibility mode does not repair expiry.",
        ))
    } else if cert.not_before().compare(&now)? == Ordering::Greater {
        Ok((
            "failed",
            format!(
                "Server certificate is not valid until {}.",
                cert.not_before()
            ),
            "Check the device clock and the server certificate.",
        ))
    } else {
        Ok((
            "passed",
            format!(
                "Server certificate dates are valid; expires {}. This does not establish trust.",
                cert.not_after()
            ),
            "",
        ))
    }
}
async fn inspect_certificate(t: &Target, version: &str) -> Result<X509> {
    let stream = TcpStream::connect(transport::authority(&t.host, t.port)).await?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
    if version == "tls1.2" {
        builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
    }
    if version == "tls1.3" {
        builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))?;
    }
    // Metadata inspection only. Profile policy is verified separately below.
    builder.set_verify(SslVerifyMode::NONE);
    let mut config = builder.build().configure()?;
    config.set_verify_hostname(false);
    let mut stream = SslStream::new(config.into_ssl(&t.sni)?, stream)?;
    Pin::new(&mut stream).connect().await?;
    stream
        .ssl()
        .peer_certificate()
        .context("server sent no certificate")
}
async fn preflight(c: &Config) -> Vec<Check> {
    let start = Instant::now();
    let t = match target(c) {
        Ok(t) => t,
        Err(error) => {
            return vec![check(
                "Profile preflight",
                "skipped",
                error.to_string(),
                "Connect this profile and inspect the session diagnostics below.",
                start,
            )];
        }
    };
    let mut checks = vec![];
    let addresses = match tokio::time::timeout(
        Duration::from_secs(3),
        lookup_host((t.host.as_str(), t.port)),
    )
    .await
    {
        Ok(Ok(addresses)) => addresses.collect::<Vec<_>>(),
        _ => {
            checks.push(check(
                "DNS",
                "failed",
                "Server name could not be resolved within 3 seconds.",
                "Check the server address and system DNS resolver.",
                start,
            ));
            return checks;
        }
    };
    if addresses.is_empty() {
        checks.push(check(
            "DNS",
            "failed",
            "Server name returned no addresses.",
            "Check the server address and system DNS resolver.",
            start,
        ));
        return checks;
    }
    checks.push(check(
        "DNS",
        "passed",
        format!(
            "Resolved {} address(es) using the current system resolver.",
            addresses.len()
        ),
        "",
        start,
    ));
    let start = Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(addresses.as_slice()),
    )
    .await
    {
        Ok(Ok(_)) => checks.push(check(
            "TCP",
            "passed",
            "Server port accepted a TCP connection.",
            "",
            start,
        )),
        _ => {
            checks.push(check(
                "TCP",
                "failed",
                "Server port refused the connection or did not respond within 5 seconds.",
                "Check server availability, port, firewall and network access.",
                start,
            ));
            return checks;
        }
    }
    if !t.tls {
        checks.push(check(
            "TLS",
            "skipped",
            "TLS is disabled for this profile.",
            "",
            Instant::now(),
        ));
        return checks;
    }
    let start = Instant::now();
    let version = c.get("tls-version", "auto");
    match tokio::time::timeout(Duration::from_secs(8), inspect_certificate(&t, version)).await {
        Ok(Ok(cert)) => match certificate_check(&cert) {
            Ok((state, message, action)) => {
                checks.push(check("Certificate dates", state, message, action, start))
            }
            Err(_) => checks.push(check(
                "Certificate dates",
                "failed",
                "Certificate dates could not be read.",
                "Check the server certificate.",
                start,
            )),
        },
        _ => {
            checks.push(check(
                "TLS",
                "failed",
                "TLS handshake or certificate inspection failed within the 8-second deadline.",
                "Check TLS SNI, server TLS configuration and network filtering.",
                start,
            ));
            return checks;
        }
    }
    let start = Instant::now();
    let verified = tokio::time::timeout(Duration::from_secs(8), async {
        let pin =
            transport::resolve_pin(&t.host, t.port, &t.sni, &t.setting, &t.ca, version).await?;
        let stream = TcpStream::connect(transport::authority(&t.host, t.port)).await?;
        transport::tls(Box::new(stream), &t.sni, pin.as_deref(), &t.ca, version).await?;
        anyhow::Ok(())
    })
    .await;
    match verified {
        Ok(Ok(())) if t.setting == "insecure" => checks.push(check("TLS policy", "warning", "Compatibility mode accepted an unverified certificate for this probe. Server identity is not established.", "Use standard certificate verification or a separately verified certificate pin.", start)),
        Ok(Ok(())) => checks.push(check("TLS policy", "passed", "TLS handshake passed the profile's configured certificate policy.", "", start)),
        _ => checks.push(check("TLS policy", "failed", "TLS did not pass the profile's certificate policy within 8 seconds.", "Check certificate trust, expiry, hostname/SNI, trusted pin and custom CA settings.", start)),
    }
    checks
}
/// Only allowlisted results are exported; no arguments, paths, names or credentials.
pub async fn run(c: &Config) -> Value {
    let mut checks = preflight(c).await;
    checks.push(check(
        "Authentication / protocol",
        "skipped",
        "Preflight does not send login credentials or establish SSH/WebSocket protocol sessions.",
        "Connect this profile to test authentication and the full transport.",
        Instant::now(),
    ));
    checks.push(check("Proxy / VPN routing", "skipped", "Preflight does not start cores, change routes or test a local proxy listener.", "Connect this profile, then review current session checks below. IPv6 and DNS leak protection require separate testing.", Instant::now()));
    json!({"schemaVersion":1,"version":env!("CARGO_PKG_VERSION"),"createdAt":chrono::Utc::now().to_rfc3339(),
        "platform":std::env::consts::OS,"arch":std::env::consts::ARCH,"mode":c.mode(),"scope":"Selected saved profile preflight; uses the device's current network routes.",
        "result":if checks.iter().any(|c|c.state=="failed"){"failed"}else if checks.iter().any(|c|c.state=="warning"){"warning"}else{"partial"},"checks":checks})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn special_transports_do_not_trigger_misleading_direct_probes() {
        for args in [
            vec!["-proxy", "http://127.0.0.1:8080"],
            vec!["-payload-file", "/private/payload"],
            vec!["-v2ray-config", "/private/config"],
        ] {
            let mut input = vec![
                "-H",
                "server.invalid",
                "-P",
                "443",
                "-u",
                "tester",
                "-p",
                "credential",
            ];
            input.extend(args);
            let c =
                Config::parse(&input.into_iter().map(String::from).collect::<Vec<_>>()).unwrap();
            assert!(target(&c).is_err());
        }
    }
    #[tokio::test]
    async fn skipped_reports_exclude_credentials_and_paths() {
        let c = Config::parse(
            &[
                "-H",
                "server.invalid",
                "-P",
                "443",
                "-proxy",
                "http://secret:password@127.0.0.1:8080",
                "-payload-file",
                "/private/secret-path",
                "-u",
                "private-user",
                "-p",
                "private-password",
            ]
            .map(String::from),
        )
        .unwrap();
        let report = run(&c).await.to_string();
        for secret in [
            "secret",
            "password",
            "private-user",
            "private-password",
            "/private",
            "127.0.0.1",
        ] {
            assert!(!report.contains(secret), "{report}");
        }
    }
    #[test]
    fn certificate_dates_detect_expired_and_not_yet_valid_certificates() {
        let now = chrono::Utc::now().timestamp();
        for (before, after, state) in [
            (now - 7200, now - 3600, "failed"),
            (now + 3600, now + 7200, "failed"),
            (now - 3600, now + 3600, "passed"),
        ] {
            let mut builder = X509::builder().unwrap();
            builder
                .set_not_before(&Asn1Time::from_unix(before).unwrap())
                .unwrap();
            builder
                .set_not_after(&Asn1Time::from_unix(after).unwrap())
                .unwrap();
            assert_eq!(certificate_check(&builder.build()).unwrap().0, state);
        }
    }
    #[tokio::test]
    async fn reachable_tcp_does_not_imply_working_tls_or_authentication() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let server = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let c = Config::parse(
            &[
                "-H",
                "127.0.0.1",
                "-P",
                &port,
                "-u",
                "private-user",
                "-p",
                "private-password",
            ]
            .map(String::from),
        )
        .unwrap();
        let report = run(&c).await;
        server.abort();
        assert_eq!(report["checks"][0]["state"], "passed");
        assert_eq!(report["checks"][1]["state"], "passed");
        assert_eq!(report["checks"][2]["state"], "failed");
        assert_eq!(report["checks"][3]["state"], "skipped");
        assert_eq!(report["result"], "failed");
        assert!(!report.to_string().contains("private-password"));
    }
}
