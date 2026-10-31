use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use tunnelnest::{
    config::{Config, Protocol},
    core::{tun_config, xray_config},
    network::{InterfaceAddress, tun_conflict},
    tun::Settings,
};
fn vmess(extra: serde_json::Value) -> String {
    let mut v = json!({"add":"example.com","port":"443","id":"00000000-0000-0000-0000-000000000001","net":"grpc","tls":"tls","path":"/service"});
    v.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    format!("vmess://{}", STANDARD.encode(v.to_string()))
}
#[test]
fn tls_values_and_grpc_service_are_preserved_or_rejected_explicitly() {
    for value in [json!(true), json!("tls"), json!("true"), json!(1)] {
        let p = Protocol::parse(&vmess(json!({"tls":value}))).unwrap();
        assert_eq!(p.security, "tls");
        assert_eq!(p.service_name, "service");
    }
    for value in [json!(false), json!(""), json!("none"), json!(0)] {
        assert_eq!(
            Protocol::parse(&vmess(json!({"tls":value})))
                .unwrap()
                .security,
            "none"
        );
    }
    assert!(Protocol::parse(&vmess(json!({"tls":"unknown"}))).is_err());
    assert_eq!(
        Protocol::parse(&vmess(json!({"serviceName":"explicit"})))
            .unwrap()
            .service_name,
        "explicit"
    );
}
#[test]
fn xhttp_and_reality_fields_reach_the_generated_config() {
    let p=Protocol::parse("vless://dummy@example.com:443?security=reality&type=xhttp&sni=cdn.example&pbk=public&sid=ab&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A12345%7D&spx=%2Fspider").unwrap();
    let v = xray_config(&Config::default(), &p, None);
    let stream = &v["outbounds"][0]["streamSettings"];
    assert_eq!(stream["xhttpSettings"]["mode"], "packet-up");
    assert_eq!(
        stream["xhttpSettings"]["extra"]["scMaxEachPostBytes"],
        12345
    );
    assert_eq!(stream["realitySettings"]["spiderX"], "/spider");
    assert!(Protocol::parse("vless://dummy@example.com:443?type=xhttp&extra=%5B%5D").is_err());
}
#[test]
fn shadowsocks_sip002_and_legacy_links_generate_the_requested_cipher() {
    for link in [
        format!(
            "ss://{}@example.com:443#Test",
            STANDARD.encode("aes-256-gcm:p:a:ss")
        ),
        format!(
            "ss://{}",
            STANDARD.encode("aes-256-gcm:p:a:ss@example.com:443")
        ),
        "ss://aes-256-gcm:p%3Aa%3Ass@example.com:443".into(),
    ] {
        let p = Protocol::parse(&link).unwrap();
        assert_eq!(p.uuid, "p:a:ss");
        assert_eq!(p.cipher, "aes-256-gcm");
        assert_eq!(p.address, "example.com");
        let v = xray_config(&Config::default(), &p, None);
        assert_eq!(
            v["outbounds"][0]["settings"]["servers"][0]["method"],
            "aes-256-gcm"
        );
    }
    assert!(
        Protocol::parse(&format!(
            "ss://{}@example.com:443?plugin=unsupported",
            STANDARD.encode("aes-256-gcm:password")
        ))
        .is_err()
    );
}
#[test]
fn custom_tun_settings_own_their_addresses_and_detect_overlapping_lans() {
    let mut c = Config::default();
    c.flags.insert("tun-address4".into(), "10.83.0.1/30".into());
    c.flags
        .insert("tun-address6".into(), "fd23:4567::1/126".into());
    c.flags.insert("tun-stack".into(), "gvisor".into());
    let settings = Settings::from_config(&c).unwrap();
    let v = tun_config(&c, &[], "macos");
    assert_eq!(v["inbounds"][0]["address"][0], "10.83.0.1/30");
    assert_eq!(v["inbounds"][0]["stack"], "gvisor");
    assert_eq!(
        tun_conflict(
            &settings,
            &[InterfaceAddress {
                name: "LAN".into(),
                ip: "10.83.0.42".parse().unwrap(),
                prefix: 24
            }]
        ),
        Some("LAN".into())
    );
    assert!(
        tun_conflict(
            &settings,
            &[InterfaceAddress {
                name: "LAN".into(),
                ip: "192.168.1.2".parse().unwrap(),
                prefix: 24
            }]
        )
        .is_none()
    );
    for bad in [
        "8.8.8.8/30",
        "10.0.0.0/30",
        "10.0.0.3/30",
        "10.0.0.1/32",
        "192.168.1.1/8",
        "172.16.1.1/8",
    ] {
        c.flags.insert("tun-address4".into(), bad.into());
        assert!(Settings::from_config(&c).is_err());
    }
}
#[test]
fn split_health_policy_does_not_require_direct_traffic_to_match_the_proxy_exit() {
    let mut c = Config::default();
    assert!(!tunnelnest::runtime::has_split_policy(&c).unwrap());
    c.flags.insert(
        "routing-rules".into(),
        r#"[{"kind":"process","value":"tunnel","action":"direct"}]"#.into(),
    );
    assert!(tunnelnest::runtime::has_split_policy(&c).unwrap());
    c.flags.remove("routing-rules");
    c.flags.insert("bypass-lan".into(), "true".into());
    assert!(tunnelnest::runtime::has_split_policy(&c).unwrap());
}

#[test]
fn portable_shares_preserve_custom_tun_settings() {
    let args = [
        "-mode",
        "ssh",
        "-H",
        "example.com",
        "-P",
        "443",
        "-u",
        "alice",
        "-p",
        "fixture-secret",
        "-tun-address4",
        "10.83.0.1/30",
        "-tun-address6",
        "fd23:4567::1/126",
        "-tun-stack",
        "system",
    ]
    .map(str::to_owned)
    .to_vec();
    let profile = tunnelnest::store::Profile {
        id: 0,
        name: "Custom device".into(),
        mode: "ssh".into(),
        args: args.clone(),
        ..Default::default()
    };
    let code = tunnelnest::sharing::encode(profile, "").unwrap();
    assert_eq!(tunnelnest::sharing::decode(&code, "").unwrap().args, args);
}
