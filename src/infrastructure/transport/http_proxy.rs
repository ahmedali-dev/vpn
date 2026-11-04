//! HTTP CONNECT and payload service.
//!
//! Expands user payload templates and validates bounded upstream proxy responses before SSH starts.

use super::BoxStream;
use super::authority;
use crate::recovery::PermanentFailure;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

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
