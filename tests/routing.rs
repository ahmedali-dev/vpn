use serde_json::json;
use tunnelnest::{
    config::Config,
    core::tun_config,
    routing::{self, Action, Match},
    sharing,
    store::Profile,
};
fn config(rules: &str) -> Config {
    Config::parse(
        &[
            "-H",
            "example.com",
            "-P",
            "443",
            "-u",
            "test",
            "-p",
            "test-password",
            "-tun",
            "-routing-rules",
            rules,
        ]
        .map(str::to_owned),
    )
    .unwrap()
}
#[test]
fn policy_validates_domains_ipv4_ipv6_processes_and_rejects_unsafe_input() {
    let rules=routing::parse(r#"[{"kind":"domain","value":" Example.COM. ","action":"direct"},{"kind":"ip","value":"2001:db8::1","action":"block"},{"kind":"process","value":"firefox.exe","action":"proxy"}]"#).unwrap();
    assert_eq!(rules[0].value, "example.com");
    assert_eq!(rules[1].value, "2001:db8::1/128");
    assert_eq!(rules[2].kind, Match::Process);
    for value in [
        r#"[{"kind":"domain","value":"https://example.com","action":"direct"}]"#,
        r#"[{"kind":"ip","value":"192.0.2.1/33","action":"direct"}]"#,
        r#"[{"kind":"process","value":"/bin/sh","action":"proxy"}]"#,
        r#"[{"kind":"domain","value":"","action":"block"}]"#,
        r#"[{"kind":"domain","value":"example.com","action":"unknown"}]"#,
        r#"[{"kind":"ip","value":"192.0.2.1","action":"direct","outbound":"injected"}]"#,
    ] {
        assert!(routing::parse(value).is_err(), "accepted {value}");
    }
    assert!(routing::parse(&"[]".repeat(5000)).is_err());
}
#[test]
fn generated_rules_preserve_order_and_dns_and_ssh_udp_guards() {
    let mut c = config(
        r#"[{"kind":"domain","value":"example.com","action":"block"},{"kind":"ip","value":"192.168.1.0/24","action":"proxy"},{"kind":"process","value":"curl","action":"direct"}]"#,
    );
    c.flags.insert("bypass-lan".into(), "true".into());
    for platform in ["linux", "windows", "macos"] {
        let v = tun_config(&c, &["192.0.2.1/32".into()], platform);
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "hijack-dns");
        assert_eq!(rules[1]["action"], "sniff");
        assert_eq!(rules[2]["domain_suffix"][0], "example.com");
        assert_eq!(rules[2]["action"], "reject");
        assert_eq!(rules[3]["mode"], "and");
        assert_eq!(rules[3]["action"], "reject");
        assert_eq!(rules[4]["outbound"], "proxy");
        assert_eq!(rules[5]["process_name"][0], "curl");
        assert_eq!(rules[5]["outbound"], "direct");
        assert_eq!(rules[6]["ip_is_private"], true);
        assert_eq!(rules[7]["network"], "udp");
        assert_eq!(v["route"]["final"], "proxy");
        assert_eq!(v["dns"]["reverse_mapping"], true);
        assert_eq!(v["inbounds"][0]["route_exclude_address"][0], "192.0.2.1/32");
    }
    assert_eq!(routing::parse("[]").unwrap().len(), 0);
}
#[test]
fn routing_policy_roundtrips_in_shared_profiles_and_explicit_disable_survives() {
    let c = config(r#"[{"kind":"process","value":"curl","action":"direct"}]"#);
    let mut args = c.canonical_args();
    args.push("-bypass-lan=false".into());
    let p = Profile {
        name: "Routes".into(),
        mode: "ssh".into(),
        args,
        ..Default::default()
    };
    let decoded = sharing::decode(&sharing::encode(p.clone(), "").unwrap(), "").unwrap();
    assert_eq!(decoded.args, p.args);
    let restored = Config::parse(&decoded.args).unwrap();
    assert_eq!(restored.routing_rules().unwrap()[0].action, Action::Direct);
    assert!(!restored.boolean("bypass-lan"));
}
fn core_binary() -> Option<std::path::PathBuf> {
    let key = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("linux", "x86_64") => "linux-x64",
        ("windows", "x86_64") => "win32-x64",
        _ => return None,
    };
    let path = std::env::var_os("TUNNELNEST_CORE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("dist/runtime")
                .join(key)
                .join("cores")
        })
        .join(format!("sing-box{}", std::env::consts::EXE_SUFFIX));
    if path.is_file() {
        Some(path)
    } else {
        assert!(
            std::env::var_os("TUNNELNEST_REQUIRE_CORES").is_none(),
            "matching sing-box is required"
        );
        None
    }
}
#[tokio::test]
async fn routing_configuration_passes_the_matching_bundled_core_schema() {
    use std::io::Write;
    let Some(binary) = core_binary() else { return };
    let mut c = config(
        r#"[{"kind":"domain","value":"example.com","action":"direct"},{"kind":"ip","value":"192.0.2.0/24","action":"block"},{"kind":"process","value":"curl","action":"proxy"}]"#,
    );
    c.flags.insert("bypass-lan".into(), "true".into());
    for ssh in [true, false] {
        c.flags
            .insert("mode".into(), if ssh { "ssh" } else { "xray" }.into());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(
            &serde_json::to_vec(&tun_config(
                &c,
                &["192.0.2.1/32".into()],
                std::env::consts::OS,
            ))
            .unwrap(),
        )
        .unwrap();
        file.flush().unwrap();
        let output = tokio::process::Command::new(&binary)
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
}
#[tokio::test]
async fn actual_core_enforces_direct_proxy_and_block_rules_without_changing_system_routes() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let Some(binary) = core_binary() else { return };
    let target = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = target.accept().await {
            tokio::spawn(async move {
                let mut b = [0; 4096];
                let _ = stream.read(&mut b).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect",
                    )
                    .await;
            });
        }
    });
    let proxy = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let proxy_task = tokio::spawn(async move {
        while let Ok((stream, _)) = proxy.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    for action in ["direct", "block", "proxy"] {
        let c = config(&json!([{"kind":"ip","value":"127.0.0.1/32","action":action}]).to_string());
        let reserve = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = reserve.local_addr().unwrap().port();
        let mut v = tun_config(&c, &[], std::env::consts::OS);
        v["inbounds"] = json!([{"type":"mixed","listen":"127.0.0.1","listen_port":port}]);
        v["outbounds"][0]["server_port"] = json!(proxy_port);
        drop(reserve);
        let mut core = tunnelnest::core::CoreProcess::start(binary.clone(), Some(v), "", true)
            .await
            .unwrap();
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let before = hits.load(Ordering::SeqCst);
        let result = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).unwrap())
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("http://127.0.0.1:{target_port}/"))
            .send()
            .await;
        if action == "direct" {
            assert_eq!(result.unwrap().text().await.unwrap(), "direct");
        } else {
            assert!(result.is_err());
        }
        assert_eq!(hits.load(Ordering::SeqCst) > before, action == "proxy");
        core.stop().await;
    }
    target_task.abort();
    proxy_task.abort();
}
