//! SSH SOCKS forwarding service
//!
//! Parses local SOCKS requests and forwards TCP over the verified SSH session.

use super::status::Reporter;
use crate::transport::HostVerifier;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(super) async fn socks_server(
    listener: TcpListener,
    session: Arc<russh::client::Handle<HostVerifier>>,
    max: usize,
    ipv4: bool,
    cancel: CancellationToken,
    r: Reporter,
    channel_timeout: Duration,
) {
    let permits = Arc::new(Semaphore::new(max));
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            v=listener.accept()=>{match v{Ok((stream,_))=>{if let Ok(permit)=permits.clone().try_acquire_owned(){let s=session.clone();let r=r.clone();jobs.spawn(async move{let _permit=permit;if let Err(e)=socks_connection_timed(stream,s,ipv4,&r,channel_timeout).await{r.event("ERROR","SOCKS",format!("{e:#}"));}});}else{r.event("WARN","SOCKS","Connection limit reached; refusing this socket without restarting the SSH session");}},Err(error)=>{r.event("ERROR","SOCKS",format!("Accept failed: {error}"));break}}},
            _=jobs.join_next(),if !jobs.is_empty()=>(),
        }
    }
}
#[cfg(test)]
pub(super) async fn socks_connection(
    stream: TcpStream,
    session: Arc<russh::client::Handle<HostVerifier>>,
    ipv4: bool,
    r: &Reporter,
) -> Result<()> {
    socks_connection_timed(stream, session, ipv4, r, Duration::from_secs(30)).await
}
pub(super) async fn socks_connection_timed(
    mut stream: TcpStream,
    session: Arc<russh::client::Handle<HostVerifier>>,
    ipv4: bool,
    r: &Reporter,
    channel_timeout: Duration,
) -> Result<()> {
    let (mut host, port) = tokio::time::timeout(Duration::from_secs(15), async {
        ensure!(stream.read_u8().await? == 5, "unsupported SOCKS version");
        let count = stream.read_u8().await? as usize;
        let mut methods = vec![0; count];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            stream.write_all(&[5, 255]).await?;
            bail!("SOCKS requires no-auth method")
        }
        stream.write_all(&[5, 0]).await?;
        let mut request = [0; 4];
        stream.read_exact(&mut request).await?;
        ensure!(request[0] == 5 && request[2] == 0, "invalid SOCKS request");
        if request[1] != 1 {
            stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            bail!("only TCP CONNECT is supported")
        }
        let host = match request[3] {
            1 => {
                let mut ip = [0; 4];
                stream.read_exact(&mut ip).await?;
                std::net::Ipv4Addr::from(ip).to_string()
            }
            4 => {
                let mut ip = [0; 16];
                stream.read_exact(&mut ip).await?;
                std::net::Ipv6Addr::from(ip).to_string()
            }
            3 => {
                let n = stream.read_u8().await? as usize;
                ensure!(n > 0, "empty SOCKS hostname");
                let mut name = vec![0; n];
                stream.read_exact(&mut name).await?;
                String::from_utf8(name)?
            }
            _ => {
                stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                bail!("unsupported SOCKS address")
            }
        };
        let port = stream.read_u16().await?;
        Ok::<_, anyhow::Error>((host, port))
    })
    .await??;
    let recover_hostname = ipv4 && host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6());
    let mut initial = Vec::new();
    if recover_hostname {
        // TUN clients may use IPv6 cached before activation, or DoH IPv6 hints.
        // Acknowledge the local connection so the client sends its initial
        // request, then use its hostname for remote SSH resolution (as Firefox
        // does with SOCKS remote DNS). Never send the TLS data to a local TLS
        // endpoint or retry the rejected literal IPv6 address directly.
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let (name, bytes) = crate::hostname::recover(&mut stream).await
            .with_context(|| format!("IPv4 compatibility could not recover a hostname for [{host}]:{port}; restart the app using this destination to clear cached IPv6 addresses, or disable IPv4 compatibility if the SSH server supports IPv6"))?;
        r.event(
            "INFO",
            "SSH-FORWARD",
            format!(
                "IPv4 compatibility: recovering [{host}]:{port} via hostname {name}; remote DNS"
            ),
        );
        host = name;
        initial = bytes;
    }
    let started = std::time::Instant::now();
    r.event(
        "INFO",
        "SSH-FORWARD",
        format!("Opening TCP channel to {host}:{port}"),
    );
    let channel = match tokio::time::timeout(
        channel_timeout,
        session.channel_open_direct_tcpip(host.clone(), port.into(), "127.0.0.1", 0),
    )
    .await
    {
        Ok(Ok(channel)) => channel,
        error => {
            if !recover_hostname {
                stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            }
            match error {
                Err(_) => bail!(
                    "SSH forwarding to {host}:{port} timed out after {}s",
                    channel_timeout.as_secs()
                ),
                Ok(Err(e)) => bail!("SSH forwarding to {host}:{port} refused: {e}"),
                _ => unreachable!(),
            }
        }
    };
    if !recover_hostname {
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    }
    let mut channel = channel.into_stream();
    channel.write_all(&initial).await?;
    r.event(
        "INFO",
        "SSH-FORWARD",
        format!("Channel established in {}ms", started.elapsed().as_millis()),
    );
    let (uploaded, downloaded) = tokio::io::copy_bidirectional(&mut stream, &mut channel)
        .await
        .context("SSH data forwarding interrupted")?;
    let uploaded = uploaded + initial.len() as u64;
    r.event("INFO","SSH-FORWARD",format!("Closed {host}:{port}; uploaded={uploaded} bytes; downloaded={downloaded} bytes; duration={}ms",started.elapsed().as_millis()));
    Ok(())
}
