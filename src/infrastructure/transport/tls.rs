//! TLS verification service.
//!
//! Performs TLS handshakes, certificate validation, temporary compatibility pins and explicit trusted-pin checks.

use super::BoxStream;
use super::authority;
use crate::recovery::PermanentFailure;
use crate::runtime::Reporter;
use anyhow::Context;
use anyhow::Result;
use openssl::ssl::SslConnector;
use openssl::ssl::SslMethod;
use openssl::ssl::SslVerifyMode;
use openssl::ssl::SslVersion;
use openssl::x509::X509;
use sha2::Digest;
use sha2::Sha256;
use std::pin::Pin;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

pub async fn tls(
    stream: BoxStream,
    name: &str,
    pin: Option<&str>,
    ca: &str,
    version: &str,
) -> Result<BoxStream> {
    tls_logged(stream, name, pin, ca, version, None).await
}
pub(super) async fn tls_logged(
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
