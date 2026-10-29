use tunnelnest::{config::Config, core::tun_config, sharing, store::Profile};
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
#[test]
fn tuning_is_validated_and_preserved_by_profile_sharing() {
    let values = args(&[
        "-mode",
        "ssh",
        "-H",
        "example.com",
        "-P",
        "443",
        "-u",
        "alice",
        "-p",
        "fixture-password",
        "-ssh-keepalive-interval",
        "20",
        "-ssh-keepalive-max",
        "4",
        "-ssh-inactivity-timeout",
        "120",
        "-ssh-connect-timeout",
        "60",
        "-ssh-handshake-timeout",
        "40",
        "-ssh-channel-timeout",
        "15",
        "-startup-timeout",
        "45",
        "-health-timeout",
        "30",
        "-tun-mtu",
        "1400",
    ]);
    let c = Config::parse(&values).unwrap();
    assert_eq!(c.health_timeout(), std::time::Duration::from_secs(30));
    let p = Profile {
        name: "stability".into(),
        mode: "ssh".into(),
        args: c.canonical_args(),
        ..Default::default()
    };
    sharing::validate(p.clone()).unwrap();
    let code = sharing::encode(p.clone(), "").unwrap();
    assert_eq!(sharing::decode(&code, "").unwrap().args, p.args);
    let generated = tun_config(
        &c,
        &["192.0.2.1/32".into(), "2001:db8::1/128".into()],
        "linux",
    );
    assert_eq!(generated["inbounds"][0]["mtu"], 1400);
    assert_eq!(
        generated["inbounds"][0]["route_exclude_address"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(generated["outbounds"][0]["network"], "tcp");
    for (key, value) in [
        ("tun-mtu", "1279"),
        ("tun-mtu", "9001"),
        ("ssh-keepalive-max", "0"),
        ("ssh-channel-timeout", "0"),
        ("startup-timeout", "181"),
        ("health-timeout", "0"),
        ("health-timeout", "121"),
        ("ssh-connect-timeout", "abc"),
    ] {
        assert!(
            Config::parse(&args(&["-ui", &format!("-{key}"), value])).is_err(),
            "{key}={value}"
        );
    }
    assert!(
        Config::parse(&args(&[
            "-ui",
            "-ssh-keepalive-interval",
            "30",
            "-ssh-inactivity-timeout",
            "60"
        ]))
        .is_err()
    );
    Config::parse(&args(&["-ui", "-ssh-inactivity-timeout", "0"])).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn invalid_core_configs_are_terminal_but_running_core_crashes_are_retryable() {
    use std::{os::unix::fs::PermissionsExt, time::Duration};
    use tunnelnest::{core::CoreProcess, recovery::permanent};
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("core");
    std::fs::write(&binary,"#!/bin/sh\nif [ \"$2\" = '-test' ]; then echo 'invalid UUID configuration' >&2; exit 23; fi\nexit 9\n").unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = CoreProcess::start(binary.clone(), Some(serde_json::json!({})), "", false)
        .await
        .err()
        .unwrap();
    assert!(permanent(&error));
    assert!(format!("{error:#}").contains("invalid UUID"));
    std::fs::write(
        &binary,
        "#!/bin/sh\nif [ \"$2\" = '-test' ]; then exit 0; fi\nexit 9\n",
    )
    .unwrap();
    let mut process = CoreProcess::start(binary, Some(serde_json::json!({})), "", false)
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Err(error) = process.check_running("Xray") {
                break error;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!permanent(&error));
    assert!(format!("{error:#}").contains("uptime="));
    assert!(format!("{error:#}").contains("PID="));
    process.stop().await;
}

#[test]
fn quic_fallback_is_opt_in_and_only_blocks_udp_443() {
    use tunnelnest::core::xray_config;
    let mut c = Config::parse(&args(&[
        "-mode",
        "xray",
        "-v2ray-link",
        "vless://uuid@example.com:443?security=tls&type=ws",
    ]))
    .unwrap();
    let normal = xray_config(&c, &c.protocol().unwrap(), None);
    assert!(
        !normal["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["tag"] == "block-quic")
    );
    c.flags.insert("block-quic".into(), "true".into());
    let configured = xray_config(&c, &c.protocol().unwrap(), None);
    let rule = &configured["routing"]["rules"][0];
    assert_eq!(rule["network"], "udp");
    assert_eq!(rule["port"], "443");
    assert_eq!(rule["outboundTag"], "block-quic");
    let tun = tun_config(&c, &[], "linux");
    assert_eq!(tun["route"]["rules"][0]["action"], "hijack-dns");
    assert_eq!(
        tun["route"]["rules"][1],
        serde_json::json!({"network":"udp","port":443,"action":"reject"})
    );
    let p = Profile {
        name: "TCP fallback".into(),
        mode: "xray".into(),
        args: c.canonical_args(),
        ..Default::default()
    };
    let code = sharing::encode(p.clone(), "").unwrap();
    assert_eq!(sharing::decode(&code, "").unwrap().args, p.args);
}
