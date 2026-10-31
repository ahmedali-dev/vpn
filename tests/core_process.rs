#[cfg(unix)]
use serde_json::json;
use std::{io::Write, time::Duration};
#[cfg(unix)]
use tunnelnest::core::CoreProcess;
use tunnelnest::{
    config::Config,
    core::{tun_config, xray_config},
    runtime::Session,
};

#[tokio::test]
async fn bundled_dns_filters_ipv6_and_https_hints_without_breaking_a_records() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
    };
    let key = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("windows", "x86_64") => "win32-x64",
        _ => return,
    };
    let cores = std::env::var_os("TUNNELNEST_CORE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("dist/runtime")
                .join(key)
                .join("cores")
        });
    let binary = cores.join(format!("sing-box{}", std::env::consts::EXE_SUFFIX));
    if !binary.is_file() {
        eprintln!("DNS behavior check skipped: no bundled sing-box");
        return;
    }
    let resolver = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let resolver_port = resolver.local_addr().unwrap().port();
    let mock = tokio::spawn(async move {
        while let Ok((mut stream, _)) = resolver.accept().await {
            tokio::spawn(async move {
                let size = stream.read_u16().await.unwrap();
                let mut query = vec![0; size as usize];
                stream.read_exact(&mut query).await.unwrap();
                let qtype =
                    u16::from_be_bytes(query[query.len() - 4..query.len() - 2].try_into().unwrap());
                let v6 = "2001:db8::10"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets();
                let record = match qtype {
                    1 => vec![198, 51, 100, 10],
                    28 => v6.to_vec(),
                    // priority=1, target='.', ipv6hint parameter containing one address.
                    64 | 65 => [vec![0, 1, 0, 0, 6, 0, 16], v6.to_vec()].concat(),
                    _ => panic!("unexpected DNS type {qtype}"),
                };
                query[2] = 0x81;
                query[3] = 0x80;
                query[7] = 1;
                query.extend_from_slice(&[0xc0, 0x0c]);
                query.extend_from_slice(&qtype.to_be_bytes());
                query.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                query.extend_from_slice(&(record.len() as u16).to_be_bytes());
                query.extend(record);
                stream.write_u16(query.len() as u16).await.unwrap();
                stream.write_all(&query).await.unwrap();
            });
        }
    });
    let proxy = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let proxy_mock = tokio::spawn(async move {
        while let Ok((mut stream, _)) = proxy.accept().await {
            tokio::spawn(async move {
                assert_eq!(stream.read_u8().await.unwrap(), 5);
                let count = stream.read_u8().await.unwrap();
                let mut methods = vec![0; count as usize];
                stream.read_exact(&mut methods).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [5, 1, 0, 1, 1, 1, 1, 1, 0, 53]);
                let mut upstream = TcpStream::connect(("127.0.0.1", resolver_port))
                    .await
                    .unwrap();
                stream
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                tokio::io::copy_bidirectional(&mut stream, &mut upstream)
                    .await
                    .ok();
            });
        }
    });
    for ipv4 in [false, true] {
        let port_reservation = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = port_reservation.local_addr().unwrap().port();
        let mut c = Config::default();
        c.flags.insert("mode".into(), "ssh".into());
        c.flags.insert("ssh-ipv4-only".into(), ipv4.to_string());
        let mut config = tun_config(&c, &[], std::env::consts::OS);
        // Exercise the production DNS policy through an unprivileged inbound.
        config["inbounds"] = serde_json::json!([{"type":"direct","listen":"127.0.0.1","listen_port":port,"network":"udp","override_address":"1.1.1.1","override_port":53}]);
        config["outbounds"][0]["server_port"] = proxy_port.into();
        let mut file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        file.write_all(&serde_json::to_vec(&config).unwrap())
            .unwrap();
        file.flush().unwrap();
        drop(port_reservation);
        let mut core = tokio::process::Command::new(&binary)
            .args(["run", "-c"])
            .arg(file.path())
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        socket.connect(("127.0.0.1", port)).await.unwrap();
        for qtype in [1u16, 28, 64, 65] {
            let mut query = vec![
                0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
                b'e', 4, b't', b'e', b's', b't', 0,
            ];
            query.extend_from_slice(&qtype.to_be_bytes());
            query.extend_from_slice(&[0, 1]);
            let mut answer = [0; 1024];
            let mut received = None;
            for _ in 0..50 {
                socket.send(&query).await.unwrap();
                if let Ok(Ok(size)) =
                    tokio::time::timeout(Duration::from_millis(100), socket.recv(&mut answer)).await
                {
                    received = Some(size);
                    break;
                }
                if core.try_wait().unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if received.is_none() {
                core.kill().await.ok();
                let output = core.wait_with_output().await.unwrap();
                panic!(
                    "DNS query failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert!(received.unwrap() >= 12);
            assert_eq!(answer[3] & 15, 0, "DNS error for {qtype}");
            assert_eq!(
                u16::from_be_bytes([answer[6], answer[7]]),
                u16::from(!ipv4 || qtype == 1),
                "type={qtype}, ipv4={ipv4}"
            );
        }
        core.kill().await.unwrap();
        core.wait().await.unwrap();
    }
    mock.abort();
    proxy_mock.abort();
}

#[tokio::test]
async fn generated_configs_pass_bundled_core_validation_when_available() {
    let key = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("windows", "x86_64") => "win32-x64",
        _ => return,
    };
    let cores = std::env::var_os("TUNNELNEST_CORE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("dist/runtime")
                .join(key)
                .join("cores")
        });
    if !cores.exists() {
        assert_ne!(
            std::env::var("TUNNELNEST_REQUIRE_CORES").as_deref(),
            Ok("1"),
            "bundled cores are required for this validation job"
        );
        eprintln!(
            "core schema check skipped: no networking cores in {}",
            cores.display()
        );
        return;
    }
    let mut c=Config::parse(&["-mode","xray","-v2ray-link","vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&type=ws&sni=example.com"].map(str::to_owned)).unwrap();
    c.flags.insert("block-quic".into(), "true".into());
    for stack in ["auto", "system", "gvisor", "mixed"] {
        c.flags.insert("tun-stack".into(), stack.into());
        c.flags.insert("tun-address4".into(), "10.83.0.1/30".into());
        c.flags
            .insert("tun-address6".into(), "fd23:4567::1/126".into());
        let platform = std::env::consts::OS;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(
            &serde_json::to_vec(&tun_config(&c, &["192.0.2.1/32".into()], platform)).unwrap(),
        )
        .unwrap();
        file.flush().unwrap();
        let output = tokio::process::Command::new(
            cores.join(format!("sing-box{}", std::env::consts::EXE_SUFFIX)),
        )
        .args(["check", "-c"])
        .arg(file.path())
        .output()
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    use base64::{Engine, engine::general_purpose::STANDARD};
    let links = [
        c.get("v2ray-link", "").to_owned(),
        format!("vmess://{}", STANDARD.encode(json!({"add":"example.com","port":443,"id":"00000000-0000-0000-0000-000000000001","net":"grpc","path":"/service","tls":true}).to_string())),
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?type=xhttp&security=tls&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A12345%7D".into(),
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?type=tcp&security=reality&sni=example.com&pbk=qR9bb5s1e4p7Afvz30C_BM1Ww6qg1EWhC2xLr6vj4Gs&spx=%2Fspider".into(),
        format!("ss://{}@example.com:443", STANDARD.encode("aes-256-gcm:password")),
    ];
    for link in links {
        let p = tunnelnest::config::Protocol::parse(&link).unwrap();
        let mut file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        file.write_all(&serde_json::to_vec(&xray_config(&c, &p, None)).unwrap())
            .unwrap();
        file.flush().unwrap();
        let output = tokio::process::Command::new(
            cores.join(format!("xray{}", std::env::consts::EXE_SUFFIX)),
        )
        .args(["run", "-test", "-config"])
        .arg(file.path())
        .current_dir(&cores)
        .output()
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}: {} {}",
            p.protocol,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
#[cfg(unix)]
#[tokio::test]
async fn core_shutdown_waits_and_removes_only_generated_config() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("fake-core");
    let marker = dir.path().join("marker");
    let stopped = dir.path().join("stopped");
    std::fs::write(&binary,format!("#!/usr/bin/env python3\nimport sys,signal,time,pathlib\nif 'version' in sys.argv: print('Fake core 1.0'); sys.exit(0)\nif '-test' in sys.argv: sys.exit(0)\npathlib.Path({:?}).write_text(sys.argv[-1])\ndef stop(*args):\n pathlib.Path({:?}).write_text('stopped')\n sys.exit(0)\nsignal.signal(signal.SIGTERM,stop)\nwhile True: time.sleep(0.01)\n",marker.to_str().unwrap(),stopped.to_str().unwrap())).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut p = CoreProcess::start(binary.clone(), Some(json!({"test":"secret"})), "", false)
        .await
        .unwrap();
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(p.version, "Fake core 1.0");
    let path = std::path::PathBuf::from(std::fs::read_to_string(&marker).unwrap());
    assert!(path.exists());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    p.stop().await;
    assert!(stopped.exists());
    drop(p);
    assert!(!path.exists());
    let custom = dir.path().join("user.json");
    std::fs::write(&custom, "{}").unwrap();
    let mut p = CoreProcess::start(binary, None, custom.to_str().unwrap(), false)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    p.stop().await;
    drop(p);
    assert!(custom.exists());
}
#[tokio::test]
async fn occupied_port_is_rejected_before_core_launch() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let c = Config::parse(&[
        "-mode".into(),
        "xray".into(),
        "-v2ray-config".into(),
        "nonexistent-config".into(),
        "-v2ray-binary".into(),
        "nonexistent-core".into(),
        "-socks-port".into(),
        port.to_string(),
    ])
    .unwrap();
    let mut s = Session::start(c);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        s.report.snapshot()["logs"]
            .as_str()
            .unwrap()
            .contains("SOCKS port is already occupied")
    );
    s.stop().await;
    assert!(!s.active());
}
