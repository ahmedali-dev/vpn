mod common;
use russh::client::Handler;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tunnelnest::{
    config::Config,
    transport::{self, BoxStream, HostVerifier},
};

#[tokio::test]
async fn tls_and_ssh_verify_identity_and_forward_bytes() {
    let server = common::server().await;
    let ca = server.ca.path().to_str().unwrap();
    let pin = transport::certificate_pin("127.0.0.1", server.port, "localhost", false, "", "auto")
        .await
        .unwrap();
    assert_eq!(pin, server.certificate_pin);
    assert_eq!(
        transport::certificate_pin("127.0.0.1", server.port, "localhost", true, ca, "auto")
            .await
            .unwrap(),
        pin
    );
    assert!(
        transport::certificate_pin("127.0.0.1", server.port, "wrong.example", true, ca, "auto")
            .await
            .is_err()
    );
    assert!(
        transport::certificate_pin("127.0.0.1", server.port, "localhost", true, "", "auto")
            .await
            .is_err()
    );
    let stream: BoxStream = Box::new(
        TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap(),
    );
    assert!(
        transport::tls(stream, "localhost", Some(&"ff".repeat(32)), "", "auto")
            .await
            .is_err()
    );
    let a = vec![
        "-mode".into(),
        "ssh".into(),
        "-H".into(),
        "127.0.0.1".into(),
        "-P".into(),
        server.port.to_string(),
        "-u".into(),
        "alice".into(),
        "-p".into(),
        "secret".into(),
        "-S".into(),
        "localhost".into(),
        "-tls-ca".into(),
        ca.into(),
        "-ssh-host-key".into(),
        server.ssh_fingerprint.clone(),
    ];
    let c = Config::parse(&a).unwrap();
    let log_dir = tempfile::tempdir().unwrap();
    let reporter = tunnelnest::runtime::Reporter::persistent_in(log_dir.path(), &c);
    let ssh = transport::connect_ssh_logged(&c, None, Arc::new(Mutex::new(None)), reporter.clone())
        .await
        .unwrap();
    let saved = reporter.snapshot();
    assert_eq!(saved["connection"]["sshAuthenticated"], true);
    assert_eq!(saved["connection"]["sshTrust"], "verified_fingerprint");
    assert_eq!(
        saved["connection"]["sshFingerprint"],
        server.ssh_fingerprint
    );
    let text = saved["logs"].as_str().unwrap();
    for event in [
        "[TCP]",
        "[TLS]",
        "protocol=TLS",
        "Starting SSH key exchange",
        "Trusted SSH fingerprint matched",
        "Authentication succeeded",
    ] {
        assert!(text.contains(event), "missing log event: {event}");
    }
    assert!(!text.contains("secret"));
    let channel = ssh
        .channel_open_direct_tcpip("echo.example", 443, "127.0.0.1", 0)
        .await
        .unwrap();
    let mut stream = channel.into_stream();
    stream
        .write_all(b"bytes through TLS and SSH")
        .await
        .unwrap();
    let mut reply = [0; 25];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"bytes through TLS and SSH");
    drop(stream);
    let mut bad = c.clone();
    bad.flags
        .insert("ssh-host-key".into(), "SHA256:wrong".into());
    assert!(
        transport::connect_ssh(&bad, None, Arc::new(Mutex::new(None)))
            .await
            .is_err()
    );
    bad.flags.remove("ssh-host-key");
    let known = tempfile::NamedTempFile::new().unwrap();
    bad.flags.insert(
        "ssh-known-hosts".into(),
        known.path().to_string_lossy().into(),
    );
    assert!(
        transport::connect_ssh(&bad, None, Arc::new(Mutex::new(None)))
            .await
            .is_err()
    );
    bad.flags
        .insert("ssh-host-key".into(), server.ssh_fingerprint.clone());
    bad.flags.insert("p".into(), "wrong".into());
    assert!(
        transport::connect_ssh(&bad, None, Arc::new(Mutex::new(None)))
            .await
            .is_err()
    );
    let _ = ssh
        .disconnect(russh::Disconnect::ByApplication, "test complete", "")
        .await;
}
#[tokio::test]
async fn tofu_remembers_the_key_for_the_connection_session() {
    let key =
        russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .unwrap();
    let other =
        russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .unwrap();
    let state = Arc::new(Mutex::new(None));
    let mut h = HostVerifier {
        host: "localhost".into(),
        port: 443,
        fingerprint: String::new(),
        known_hosts: String::new(),
        tofu: true,
        first: state.clone(),
        report: None,
    };
    assert!(h.check_server_key(key.public_key()).await.unwrap());
    assert!(h.check_server_key(key.public_key()).await.unwrap());
    assert!(tunnelnest::recovery::permanent(
        &h.check_server_key(other.public_key()).await.unwrap_err()
    ));
    let mut reconnected = HostVerifier { first: state, ..h };
    assert!(tunnelnest::recovery::permanent(
        &reconnected
            .check_server_key(other.public_key())
            .await
            .unwrap_err()
    ));
}
#[tokio::test]
async fn connect_preserves_bytes_after_response_and_rejects_failure() {
    for status in [200, 407] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = vec![];
            loop {
                req.push(s.read_u8().await.unwrap());
                if req.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            s.write_all(format!("HTTP/1.1 {status} Test\r\n\r\nSSH-buffered").as_bytes())
                .await
                .unwrap();
        });
        let mut stream: BoxStream = Box::new(TcpStream::connect(addr).await.unwrap());
        let result =
            transport::http_connect(&mut stream, "CONNECT host:443 HTTP/1.1\r\n\r\n").await;
        if status == 200 {
            result.unwrap();
            let mut bytes = [0; 12];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"SSH-buffered");
        } else {
            assert!(result.is_err());
        }
        task.await.unwrap();
    }
    let payload = transport::expand_payload(
        "CONNECT [host_port] [protocol][crlf][proxy_auth][crlf][split][host]",
        "::1",
        443,
        "Proxy-Authorization: Basic abc\r\n",
    );
    assert!(payload.contains("[::1]:443 HTTP/1.1\r\nProxy-Authorization: Basic abc"));
    assert!(payload.ends_with("[split]::1"));
}

#[tokio::test]
async fn custom_payload_replaces_the_proxy_connect_request() {
    use std::io::Write;
    let server = common::server().await;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_port = server.port;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut request = vec![];
        loop {
            request.push(client.read_u8().await.unwrap());
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        tx.send(String::from_utf8(request).unwrap()).unwrap();
        client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let mut upstream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });
    let mut payload = tempfile::NamedTempFile::new().unwrap();
    payload
        .write_all(b"CONNECT [host_port] [protocol][crlf]X-Custom: yes[crlf][proxy_auth][crlf]")
        .unwrap();
    payload.flush().unwrap();
    let args = vec![
        "-H".into(),
        "127.0.0.1".into(),
        "-P".into(),
        server.port.to_string(),
        "-u".into(),
        "alice".into(),
        "-p".into(),
        "secret".into(),
        "-S".into(),
        "localhost".into(),
        "-tls-ca".into(),
        server.ca.path().to_string_lossy().into(),
        "-ssh-host-key".into(),
        server.ssh_fingerprint.clone(),
        "-proxy".into(),
        format!("http://u:p@127.0.0.1:{port}"),
        "-payload-file".into(),
        payload.path().to_string_lossy().into(),
    ];
    let ssh = transport::connect_ssh(
        &Config::parse(&args).unwrap(),
        None,
        Arc::new(Mutex::new(None)),
    )
    .await
    .unwrap();
    let request = rx.await.unwrap();
    assert!(request.contains("X-Custom: yes"));
    assert!(request.contains("Proxy-Authorization: Basic dTpw"));
    let _ = ssh
        .disconnect(russh::Disconnect::ByApplication, "test done", "")
        .await;
    proxy.abort();
}

#[tokio::test]
async fn identity_and_authentication_failures_are_terminal() {
    let server = common::server().await;
    let mut config = Config::parse(&[
        "-H".into(),
        "127.0.0.1".into(),
        "-P".into(),
        server.port.to_string(),
        "-S".into(),
        "localhost".into(),
        "-u".into(),
        "alice".into(),
        "-p".into(),
        "wrong-password".into(),
        "-tls-ca".into(),
        server.ca.path().to_string_lossy().into(),
        "-ssh-host-key".into(),
        server.ssh_fingerprint.clone(),
    ])
    .unwrap();
    let rejected = transport::connect_ssh(&config, None, Arc::new(Mutex::new(None)))
        .await
        .err()
        .unwrap();
    assert!(tunnelnest::recovery::permanent(&rejected), "{rejected:#}");
    config.flags.insert("p".into(), "secret".into());
    config
        .flags
        .insert("ssh-host-key".into(), "SHA256:wrong-key".into());
    let changed = transport::connect_ssh(&config, None, Arc::new(Mutex::new(None)))
        .await
        .err()
        .unwrap();
    assert!(tunnelnest::recovery::permanent(&changed), "{changed:#}");
    let invalid_cert = transport::certificate_pin(
        "127.0.0.1",
        server.port,
        "wrong.example",
        true,
        server.ca.path().to_str().unwrap(),
        "auto",
    )
    .await
    .unwrap_err();
    assert!(
        tunnelnest::recovery::permanent(&invalid_cert),
        "{invalid_cert:#}"
    );
}

#[tokio::test]
async fn tls_discovery_failure_retries_and_backoff_can_be_cancelled() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fake = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
        }
    });
    let config = Config::parse(&[
        "-H".into(),
        "127.0.0.1".into(),
        "-P".into(),
        port.to_string(),
        "-u".into(),
        "alice".into(),
        "-p".into(),
        "secret".into(),
        "-ssh-cert-sha256".into(),
        "insecure".into(),
    ])
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let report = tunnelnest::runtime::Reporter::persistent_in(directory.path(), &config);
    let mut session = tunnelnest::runtime::Session::start_with_report(config, report.clone());
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if report.snapshot()["recovery"]["attempt"]
                .as_u64()
                .unwrap_or(0)
                >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), session.stop())
        .await
        .unwrap();
    let snapshot = report.snapshot();
    assert_eq!(snapshot["state"], "disconnected");
    assert!(
        snapshot["logs"]
            .as_str()
            .unwrap()
            .contains("TLS discovery failed after")
    );
    assert!(!snapshot.to_string().contains("secret"));
    fake.abort();
}

#[tokio::test]
async fn configured_keepalives_survive_idle_and_detect_a_blackholed_transport() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let server = common::server().await;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream_port = server.port;
    let paused = Arc::new(AtomicBool::new(false));
    let pause = paused.clone();
    let relay = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        loop {
            header.push(client.read_u8().await.unwrap());
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let upstream = TcpStream::connect(("127.0.0.1", upstream_port))
            .await
            .unwrap();
        client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let (mut cr, mut cw) = client.into_split();
        let (mut sr, mut sw) = upstream.into_split();
        async fn copy<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
            reader: &mut R,
            writer: &mut W,
            paused: Arc<AtomicBool>,
        ) {
            let mut data = [0; 4096];
            loop {
                let count = match reader.read(&mut data).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => count,
                };
                while paused.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                if writer.write_all(&data[..count]).await.is_err() {
                    break;
                }
            }
        }
        tokio::join!(
            copy(&mut cr, &mut sw, pause.clone()),
            copy(&mut sr, &mut cw, pause)
        );
    });
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
        "-ssh-host-key".into(),
        server.ssh_fingerprint.clone(),
        "-proxy".into(),
        format!("http://127.0.0.1:{port}"),
        "-ssh-keepalive-interval".into(),
        "1".into(),
        "-ssh-keepalive-max".into(),
        "2".into(),
        "-ssh-inactivity-timeout".into(),
        "8".into(),
    ])
    .unwrap();
    let ssh = transport::connect_ssh(
        &c,
        Some(&server.certificate_pin),
        Arc::new(Mutex::new(None)),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!ssh.is_closed(), "idle session should answer keepalives");
    paused.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ssh.is_closed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("unresponsive transport should close after its keepalive budget");
    relay.abort();
}
