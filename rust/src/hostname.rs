//! Recover a hostname from an initial client request without terminating TLS.
use anyhow::{Context, Result, bail, ensure};
use std::{io::Cursor, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt};

fn domain(authority: &str) -> Result<String> {
    let authority = authority.trim();
    ensure!(
        !authority.contains(['/', '@', '?', '#']),
        "invalid hostname"
    );
    let url = url::Url::parse(&format!("http://{authority}"))?;
    let name = url.host_str().context("missing hostname")?;
    ensure!(
        matches!(url.host(), Some(url::Host::Domain(_))),
        "literal IP has no hostname fallback"
    );
    ensure!(
        name.len() <= 253
            && name.contains('.')
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
        "invalid DNS hostname"
    );
    Ok(name.to_owned())
}

/// Bytes read here must be replayed verbatim to the SSH channel. The client
/// still negotiates and verifies TLS directly with its destination server.
pub async fn recover<R: AsyncRead + Unpin>(stream: &mut R) -> Result<(String, Vec<u8>)> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        let mut acceptor = rustls::server::Acceptor::default();
        loop {
            ensure!(
                bytes.len() < 65536,
                "initial request exceeds hostname recovery limit"
            );
            let mut chunk = [0; 4096];
            let size = stream.read(&mut chunk).await?;
            ensure!(size > 0, "connection closed before hostname was available");
            ensure!(
                bytes.len() + size <= 65536,
                "initial request exceeds hostname recovery limit"
            );
            bytes.extend_from_slice(&chunk[..size]);
            if bytes[0] == 0x16 {
                let mut cursor = Cursor::new(&chunk[..size]);
                while (cursor.position() as usize) < size {
                    acceptor.read_tls(&mut cursor)?;
                }
                match acceptor.accept() {
                    Ok(Some(accepted)) => {
                        let name = domain(
                            accepted
                                .client_hello()
                                .server_name()
                                .context("TLS request has no visible server name")?,
                        )?;
                        return Ok((name, bytes));
                    }
                    Ok(None) => continue,
                    Err((error, _)) => bail!("invalid TLS ClientHello: {error}"),
                }
            } else {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut request = httparse::Request::new(&mut headers);
                match request.parse(&bytes)? {
                    httparse::Status::Partial => continue,
                    httparse::Status::Complete(_) => {
                        let mut hosts = request
                            .headers
                            .iter()
                            .filter(|h| h.name.eq_ignore_ascii_case("host"));
                        let host = hosts.next().context("HTTP request has no Host header")?;
                        ensure!(hosts.next().is_none(), "ambiguous HTTP Host headers");
                        let name = domain(std::str::from_utf8(host.value)?)?;
                        return Ok((name, bytes));
                    }
                }
            }
        }
    })
    .await
    .context("timed out waiting for a TLS or HTTP hostname")?
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    pub(crate) fn client_hello(sni: bool) -> Vec<u8> {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.enable_sni = sni;
        let mut client = rustls::ClientConnection::new(
            std::sync::Arc::new(config),
            "example.com".try_into().unwrap(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        bytes
    }

    #[tokio::test]
    async fn fragmented_tls_and_http_preserve_every_byte() {
        for bytes in [
            client_hello(true),
            b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".to_vec(),
        ] {
            let (mut reader, mut writer) = tokio::io::duplex(8192);
            let sent = bytes.clone();
            let task = tokio::spawn(async move {
                for byte in sent {
                    writer.write_all(&[byte]).await.unwrap();
                    tokio::task::yield_now().await;
                }
            });
            let (name, replay) = recover(&mut reader).await.unwrap();
            assert_eq!(name, "example.com");
            assert_eq!(replay, bytes);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn missing_sni_ambiguous_http_and_raw_protocols_fail_closed() {
        for bytes in [
            client_hello(false),
            b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n".to_vec(),
            b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: other.example\r\n\r\n".to_vec(),
            b"SSH-2.0-test\r\n".to_vec(),
            vec![b'A'; 65536],
        ] {
            assert!(recover(&mut bytes.as_slice()).await.is_err());
        }
    }
}
