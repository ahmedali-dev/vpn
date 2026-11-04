//! SSH transport and identity service.
//!
//! Selects direct/proxied transport, verifies host identity and authenticates the SSH connection.

use super::BoxStream;
use super::authority;
use super::http_proxy::expand_payload;
use super::http_proxy::http_connect;
use super::tls::tls_logged;
use crate::config::Config;
use crate::config::parse_proxy;
use crate::config::unescape;
use crate::recovery::PermanentFailure;
use crate::runtime::Reporter;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use russh::client;
use russh::keys::HashAlg;
use russh::keys::PublicKey;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::TcpStream;

pub async fn ssh_transport(c: &Config, pin: Option<&str>) -> Result<BoxStream> {
    ssh_transport_logged(c, pin, &Reporter::default()).await
}
pub(super) async fn ssh_transport_logged(
    c: &Config,
    pin: Option<&str>,
    r: &Reporter,
) -> Result<BoxStream> {
    let host = c.get("H", "");
    let port = c.number("P", 0)? as u16;
    let dial = c.get("dial-address", host);
    let payload = if !c.get("payload-file", "").is_empty() {
        let data = tokio::fs::read(c.get("payload-file", "")).await?;
        ensure!(data.len() <= 65536, "payload too large");
        String::from_utf8(data)?
    } else {
        String::new()
    };
    let before = !payload.is_empty() && c.get("payload-stage", "before-tls") == "before-tls";
    let mut stream: BoxStream;
    r.event(
        "INFO",
        "TCP",
        format!(
            "Opening transport to {dial}:{port}; timeout={}s; upstream proxy={}",
            c.number("ssh-connect-timeout", 45)?,
            !c.get("proxy", "").is_empty()
        ),
    );
    if !c.get("proxy", "").is_empty() {
        let u = parse_proxy(c.get("proxy", ""))?;
        let ph = u.host_str().unwrap().trim_matches(['[', ']']);
        let pp = u.port_or_known_default().unwrap();
        stream = Box::new(
            r.stage("Proxy TCP connection", async {
                let stream =
                    TcpStream::connect(authority(c.get("proxy-dial-address", ph), pp)).await?;
                stream.set_nodelay(true)?;
                Ok(stream)
            })
            .await?,
        );
        if u.scheme() == "https" {
            stream = tls_logged(stream, ph, None, "", "auto", Some(r))
                .await
                .context("HTTPS upstream proxy TLS failed")?;
        }
        let auth = if !u.username().is_empty() {
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                STANDARD.encode(format!(
                    "{}:{}",
                    unescape(u.username())?,
                    unescape(u.password().unwrap_or(""))?
                ))
            )
        } else {
            String::new()
        };
        let request = if before {
            expand_payload(&payload, host, port, &auth)
        } else {
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}\r\n",
                authority(dial, port),
                authority(host, port),
                auth
            )
        };
        r.event(
            "INFO",
            "PROXY",
            format!(
                "Sending CONNECT via {ph}:{pp}; custom payload={before}; credentials configured={}",
                !u.username().is_empty()
            ),
        );
        http_connect(&mut stream, &request)
            .await
            .context("upstream proxy CONNECT failed")?;
        r.event("INFO", "PROXY", "CONNECT accepted (2xx)");
    } else {
        stream = Box::new(
            r.stage("TCP connection", async {
                let stream = TcpStream::connect(authority(dial, port)).await?;
                stream.set_nodelay(true)?;
                Ok(stream)
            })
            .await?,
        );
    }
    r.event("INFO", "TCP", "Transport socket established");
    if before && c.get("proxy", "").is_empty() {
        r.event(
            "INFO",
            "PAYLOAD",
            "Sending custom CONNECT before TLS (payload contents omitted)",
        );
        http_connect(&mut stream, &expand_payload(&payload, host, port, "")).await?;
    }
    stream = r
        .stage(
            "TLS handshake",
            tls_logged(
                stream,
                if c.get("S", "").is_empty() {
                    host
                } else {
                    c.get("S", "")
                },
                pin,
                c.get("tls-ca", ""),
                c.get("tls-version", "auto"),
                Some(r),
            ),
        )
        .await
        .context("SSH TLS handshake failed")?;
    if !payload.is_empty() && c.get("payload-stage", "before-tls") == "after-tls" {
        r.event(
            "INFO",
            "PAYLOAD",
            "Sending custom CONNECT inside TLS (payload contents omitted)",
        );
        http_connect(&mut stream, &expand_payload(&payload, host, port, "")).await?;
    }
    Ok(stream)
}

pub struct HostVerifier {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub known_hosts: String,
    pub tofu: bool,
    pub first: Arc<Mutex<Option<String>>>,
    pub report: Option<Reporter>,
}
impl HostVerifier {
    fn record_trust(&self, fingerprint: &str, method: &str) {
        if let Some(r) = &self.report {
            let mut status = r.0.lock().unwrap();
            if !status.connection.is_object() {
                status.connection = serde_json::json!({});
            }
            status.connection["sshFingerprint"] = serde_json::json!(fingerprint);
            status.connection["sshTrust"] = serde_json::json!(method);
        }
    }
}
impl client::Handler for HostVerifier {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool> {
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        if let Some(r) = &self.report {
            r.event(
                "INFO",
                "SSH",
                format!(
                    "Server host key: {fingerprint}; algorithm={}",
                    key.algorithm()
                ),
            );
        }
        if !self.fingerprint.is_empty() {
            let trusted = fingerprint == self.fingerprint;
            if let Some(r) = &self.report {
                r.event(
                    if trusted { "INFO" } else { "ERROR" },
                    "SSH",
                    if trusted {
                        "Trusted SSH fingerprint matched"
                    } else {
                        "SSH fingerprint mismatch; refusing connection"
                    },
                );
            }
            if !trusted {
                return Err(
                    anyhow::anyhow!("SSH host key mismatch").context(PermanentFailure::Identity)
                );
            }
            self.record_trust(&fingerprint, "verified_fingerprint");
            return Ok(true);
        }
        if self.tofu {
            let mut first = self.first.lock().unwrap();
            if let Some(first) = first.as_ref() {
                let trusted = first == &fingerprint;
                if let Some(r) = &self.report {
                    r.event(if trusted{"INFO"}else{"ERROR"},"SSH",if trusted{"Session-trusted host key matched"}else{"SSH host key changed during this connection session; refusing reconnect"});
                }
                if !trusted {
                    return Err(anyhow::anyhow!("SSH host key mismatch")
                        .context(PermanentFailure::Identity));
                }
                self.record_trust(&fingerprint, "session_only");
                return Ok(true);
            }
            if let Some(r) = &self.report {
                r.event(
                    "WARN",
                    "SSH",
                    "Explicit first-use trust: retaining the host key for this connection session",
                );
            }
            self.record_trust(&fingerprint, "session_only");
            *first = Some(fingerprint);
            return Ok(true);
        }
        let path = std::path::Path::new(&self.known_hosts);
        let trusted = russh::keys::check_known_hosts_path(&self.host, self.port, key, path)
            .context("SSH known_hosts verification failed (unknown or changed key)")
            .context(PermanentFailure::Identity)?;
        if let Some(r) = &self.report {
            r.event(if trusted{"INFO"}else{"ERROR"},"SSH",if trusted{"SSH host key verified against known_hosts"}else{"SSH host key not found in known_hosts; add a trusted fingerprint or known_hosts entry"});
        }
        if !trusted {
            return Err(
                anyhow::anyhow!("SSH host key is not trusted").context(PermanentFailure::Identity)
            );
        }
        self.record_trust(&fingerprint, "verified_known_hosts");
        Ok(true)
    }
}
pub async fn connect_ssh(
    c: &Config,
    pin: Option<&str>,
    first: Arc<Mutex<Option<String>>>,
) -> Result<client::Handle<HostVerifier>> {
    connect_ssh_logged(c, pin, first, Reporter::default()).await
}
pub async fn connect_ssh_logged(
    c: &Config,
    pin: Option<&str>,
    first: Arc<Mutex<Option<String>>>,
    r: Reporter,
) -> Result<client::Handle<HostVerifier>> {
    let started = std::time::Instant::now();
    let stream = tokio::time::timeout(
        Duration::from_secs(c.number("ssh-connect-timeout", 45)? as u64),
        ssh_transport_logged(c, pin, &r),
    )
    .await
    .context("SSH transport exceeded configured connection timeout")??;
    let known = c.flags.get("ssh-known-hosts").cloned().unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".ssh/known_hosts")
            .to_string_lossy()
            .into()
    });
    let handler = HostVerifier {
        host: c.get("H", "").into(),
        port: c.number("P", 0)? as u16,
        fingerprint: c.get("ssh-host-key", "").into(),
        known_hosts: known,
        tofu: c.boolean("ssh-trust-on-first-use"),
        first,
        report: Some(r.clone()),
    };
    let cfg = client::Config {
        inactivity_timeout: match c.number("ssh-inactivity-timeout", 90)? {
            0 => None,
            n => Some(Duration::from_secs(n as u64)),
        },
        keepalive_interval: match c.number("ssh-keepalive-interval", 15)? {
            0 => None,
            n => Some(Duration::from_secs(n as u64)),
        },
        keepalive_max: c.number("ssh-keepalive-max", 3)? as usize,
        ..Default::default()
    };
    r.event(
        "INFO",
        "SSH",
        format!("Starting SSH key exchange; handshake timeout={}s; keepalive={}s; missed keepalive limit={}",c.number("ssh-handshake-timeout",30)?,c.number("ssh-keepalive-interval",15)?,c.number("ssh-keepalive-max",3)?),
    );
    let mut session = r
        .stage("SSH key exchange", async {
            tokio::time::timeout(
                Duration::from_secs(c.number("ssh-handshake-timeout", 30)? as u64),
                client::connect_stream(Arc::new(cfg), stream, handler),
            )
            .await
            .context("SSH key exchange exceeded configured handshake timeout")?
            .context("SSH key exchange or host-key verification failed")
        })
        .await?;
    r.event(
        "INFO",
        "SSH",
        "SSH handshake complete; starting password authentication (credentials omitted)",
    );
    let result = r
        .stage("SSH authentication", async {
            tokio::time::timeout(
                Duration::from_secs(c.number("ssh-handshake-timeout", 30)? as u64),
                session.authenticate_password(c.get("u", ""), c.get("p", "")),
            )
            .await
            .context("SSH authentication exceeded configured handshake timeout")?
            .context("SSH authentication exchange failed")
        })
        .await?;
    if !result.success() {
        r.event(
            "ERROR",
            "SSH",
            "Password authentication rejected; check account credentials and server policy",
        );
        return Err(anyhow::anyhow!("SSH password authentication failed")
            .context(PermanentFailure::Authentication));
    }
    r.0.lock().unwrap().connection["sshAuthenticated"] = serde_json::json!(true);
    r.event(
        "INFO",
        "SSH",
        format!(
            "Authentication succeeded; SSH transport ready in {}ms",
            started.elapsed().as_millis()
        ),
    );
    Ok(session)
}
