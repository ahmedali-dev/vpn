use crate::recovery::PermanentFailure;
use crate::{
    config::{Config, parse_proxy, unescape},
    runtime::Reporter,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use russh::{
    client,
    keys::{HashAlg, PublicKey},
};
use sha2::{Digest, Sha256};
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_openssl::SslStream;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;
pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub async fn tls(
    stream: BoxStream,
    name: &str,
    pin: Option<&str>,
    ca: &str,
    version: &str,
) -> Result<BoxStream> {
    tls_logged(stream, name, pin, ca, version, None).await
}
async fn tls_logged(
    stream: BoxStream,
    name: &str,
    pin: Option<&str>,
    ca: &str,
    version: &str,
    report: Option<&Reporter>,
) -> Result<BoxStream> {
    if let Some(r) = report {
        r.event(
            "INFO",
            "TLS",
            format!(
                "Starting handshake; SNI={name}; verification={}",
                if pin.is_some() {
                    "certificate pin"
                } else {
                    "trusted CA and hostname"
                }
            ),
        );
    }
    let mut b = SslConnector::builder(SslMethod::tls_client())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    match version {
        "tls1.2" => b.set_max_proto_version(Some(SslVersion::TLS1_2))?,
        "tls1.3" => b.set_min_proto_version(Some(SslVersion::TLS1_3))?,
        _ => (),
    }
    if pin.is_some() {
        b.set_verify(SslVerifyMode::NONE);
    } else {
        for cert in rustls_native_certs::load_native_certs().certs {
            if let Ok(x) = X509::from_der(cert.as_ref()) {
                let _ = b.cert_store_mut().add_cert(x);
            }
        }
        if !ca.is_empty() {
            b.set_ca_file(ca).context(PermanentFailure::Configuration)?;
        }
    }
    let mut conf = b.build().configure()?;
    if pin.is_some() {
        conf.set_verify_hostname(false);
    }
    let mut stream = SslStream::new(conf.into_ssl(name)?, stream)?;
    if let Err(error) =
        tokio::time::timeout(Duration::from_secs(30), Pin::new(&mut stream).connect()).await?
    {
        let invalid_certificate =
            stream.ssl().verify_result() != openssl::x509::X509VerifyResult::OK;
        let error = anyhow::Error::new(error);
        return Err(if invalid_certificate {
            error.context(PermanentFailure::Identity)
        } else {
            error
        });
    }
    if let Some(pin) = pin {
        let cert = stream
            .ssl()
            .peer_certificate()
            .context("server sent no certificate")?;
        let actual = hex::encode(Sha256::digest(cert.to_der()?));
        if !actual.eq_ignore_ascii_case(pin) {
            return Err(
                anyhow::anyhow!("TLS certificate pin mismatch").context(PermanentFailure::Identity)
            );
        }
    }
    if let Some(r) = report {
        r.event(
            "INFO",
            "TLS",
            format!(
                "Handshake verified; protocol={}; cipher={}",
                stream.ssl().version_str(),
                stream
                    .ssl()
                    .current_cipher()
                    .map(|c| c.name())
                    .unwrap_or("unknown")
            ),
        );
    }
    Ok(Box::new(stream))
}

pub async fn certificate_pin(
    host: &str,
    port: u16,
    name: &str,
    verify: bool,
    ca: &str,
    version: &str,
) -> Result<String> {
    let stream: BoxStream = Box::new(TcpStream::connect(authority(host, port)).await?);
    let mut b = SslConnector::builder(SslMethod::tls_client())?;
    b.set_min_proto_version(Some(if version == "tls1.3" {
        SslVersion::TLS1_3
    } else {
        SslVersion::TLS1_2
    }))?;
    if version == "tls1.2" {
        b.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    }
    if !verify {
        b.set_verify(SslVerifyMode::NONE);
    } else {
        for cert in rustls_native_certs::load_native_certs().certs {
            if let Ok(x) = X509::from_der(cert.as_ref()) {
                let _ = b.cert_store_mut().add_cert(x);
            }
        }
        if !ca.is_empty() {
            b.set_ca_file(ca).context(PermanentFailure::Configuration)?;
        }
    }
    let mut conf = b.build().configure()?;
    conf.set_verify_hostname(verify);
    let mut stream = SslStream::new(conf.into_ssl(name)?, stream)?;
    if let Err(error) =
        tokio::time::timeout(Duration::from_secs(30), Pin::new(&mut stream).connect()).await?
    {
        let invalid_certificate =
            stream.ssl().verify_result() != openssl::x509::X509VerifyResult::OK;
        let error = anyhow::Error::new(error);
        return Err(if invalid_certificate {
            error.context(PermanentFailure::Identity)
        } else {
            error
        });
    }
    Ok(hex::encode(Sha256::digest(
        stream
            .ssl()
            .peer_certificate()
            .context("missing certificate")?
            .to_der()?,
    )))
}
pub async fn resolve_pin(
    host: &str,
    port: u16,
    sni: &str,
    setting: &str,
    ca: &str,
    version: &str,
) -> Result<Option<String>> {
    match setting {
        "none" => Ok(None),
        "auto" if host.eq_ignore_ascii_case(sni) => Ok(None),
        "auto" => Ok(Some(
            certificate_pin(host, port, host, true, ca, version).await?,
        )),
        "insecure" => Ok(Some(
            certificate_pin(host, port, sni, false, ca, version).await?,
        )),
        pin => {
            let decoded = hex::decode(pin).context(PermanentFailure::Configuration)?;
            if decoded.len() != 32 {
                return Err(anyhow::anyhow!("invalid pin").context(PermanentFailure::Configuration));
            }
            Ok(Some(pin.to_lowercase()))
        }
    }
}

pub fn expand_payload(template: &str, host: &str, port: u16, auth: &str) -> String {
    let mut s = template.to_owned();
    for (key, value) in [
        ("[host_port]", authority(host, port)),
        ("[host]", host.into()),
        ("[port]", port.to_string()),
        ("[protocol]", "HTTP/1.1".into()),
        ("[crlf]", "\r\n".into()),
        ("[cr]", "\r".into()),
        ("[lf]", "\n".into()),
        ("[ua]", "TunnelNest/1.3".into()),
        ("[proxy_auth]", auth.into()),
    ] {
        s = s.replace(key, &value);
    }
    s
}
pub async fn http_connect(stream: &mut BoxStream, request: &str) -> Result<()> {
    for piece in request.split("[split]") {
        stream.write_all(piece.as_bytes()).await?;
        stream.flush().await?;
    }
    // Read exactly through the terminator, preserving any tunnel bytes in the socket.
    let mut header = Vec::new();
    loop {
        ensure!(header.len() < 65536, "CONNECT headers too large");
        header.push(stream.read_u8().await?);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let line = std::str::from_utf8(&header)?
        .lines()
        .next()
        .context("missing CONNECT status")?;
    let mut parts = line.split_whitespace();
    ensure!(
        parts.next().is_some_and(|x| x.starts_with("HTTP/1.")),
        "invalid CONNECT response"
    );
    let status: u16 = parts.next().context("missing CONNECT status")?.parse()?;
    if status == 401 || status == 403 || status == 407 {
        return Err(anyhow::anyhow!("CONNECT request rejected ({status})")
            .context(PermanentFailure::Authentication));
    }
    ensure!(
        (200..300).contains(&status),
        "CONNECT request rejected ({status})"
    );
    Ok(())
}
pub async fn ssh_transport(c: &Config, pin: Option<&str>) -> Result<BoxStream> {
    ssh_transport_logged(c, pin, &Reporter::default()).await
}
async fn ssh_transport_logged(c: &Config, pin: Option<&str>, r: &Reporter) -> Result<BoxStream> {
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
            "Opening transport to {dial}:{port}; timeout=45s; upstream proxy={}",
            !c.get("proxy", "").is_empty()
        ),
    );
    if !c.get("proxy", "").is_empty() {
        let u = parse_proxy(c.get("proxy", ""))?;
        let ph = u.host_str().unwrap().trim_matches(['[', ']']);
        let pp = u.port_or_known_default().unwrap();
        stream = Box::new(
            r.stage("Proxy TCP connection", async {
                Ok(TcpStream::connect(authority(c.get("proxy-dial-address", ph), pp)).await?)
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
                Ok(TcpStream::connect(authority(dial, port)).await?)
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
                return Ok(true);
            }
            if let Some(r) = &self.report {
                r.event(
                    "WARN",
                    "SSH",
                    "Explicit first-use trust: retaining the host key for this connection session",
                );
            }
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
    let stream = tokio::time::timeout(Duration::from_secs(45), ssh_transport_logged(c, pin, &r))
        .await
        .context("SSH transport timed out after 45s")??;
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
        inactivity_timeout: Some(Duration::from_secs(90)),
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Default::default()
    };
    r.event(
        "INFO",
        "SSH",
        "Starting SSH key exchange; handshake timeout=30s; keepalive=15s; missed keepalive limit=3",
    );
    let mut session = r
        .stage("SSH key exchange", async {
            tokio::time::timeout(
                Duration::from_secs(30),
                client::connect_stream(Arc::new(cfg), stream, handler),
            )
            .await
            .context("SSH key exchange timed out after 30s")?
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
                Duration::from_secs(30),
                session.authenticate_password(c.get("u", ""), c.get("p", "")),
            )
            .await
            .context("SSH authentication timed out after 30s")?
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
