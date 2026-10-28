use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use tunnelnest::{
    config::{Config, Protocol},
    core::{tun_config, xray_config},
    runtime::pac_script,
    sharing,
    store::{Profile, Store},
};
fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}
fn ssh() -> Profile {
    Profile {
        name: "Test SSH".into(),
        mode: "ssh".into(),
        args: args(&[
            "-mode",
            "ssh",
            "-H",
            "example.com",
            "-P",
            "443",
            "-u",
            "alice",
            "-p",
            "a-secret-password",
            "-ssh-host-key",
            "SHA256:test",
        ]),
        ..Default::default()
    }
}
#[test]
fn imports_transports_sni_and_ipv6() {
    let vmess=format!("vmess://{}",STANDARD.encode(serde_json::to_vec(&json!({"add":"server.example","port":443,"id":"uuid","net":"ws","tls":"tls","host":"cdn.example:443","path":"/ws","aid":"0","alpn":"h2,http/1.1"})).unwrap()));
    let p = Protocol::parse(&vmess).unwrap();
    assert_eq!(p.sni, "cdn.example");
    assert_eq!(p.sni_source, "host");
    assert_eq!(p.alpn, vec!["h2", "http/1.1"]);
    let p=Protocol::parse("vless://uuid@[2001:db8::1]:443?security=reality&sni=cdn.example&pbk=pub&sid=ab&type=grpc&serviceName=a%2Fb&fp=chrome").unwrap();
    assert_eq!(p.address, "2001:db8::1");
    assert_eq!(p.service_name, "a/b");
    assert_eq!(p.reality_public_key, "pub");
    let p = Protocol::parse("trojan://p%40ss@host.example:443?type=ws&host=cdn.example").unwrap();
    assert_eq!(p.uuid, "p@ss");
    assert_eq!(p.security, "tls");
    assert_eq!(p.sni, "host.example");
    let p =
        Protocol::parse("vless://uuid@host.example:443?security=tls&sni=explicit.example").unwrap();
    assert_eq!(p.sni, "explicit.example");
}
#[test]
fn rejects_invalid_configuration() {
    for a in [
        vec!["-mode", "invalid"],
        vec!["-ui", "-socks-port", "0"],
        vec!["-ui", "-pac-port", "65536"],
        vec!["-ui", "-socks-port", "1080", "-pac-port", "1080"],
        vec!["-ui", "-tls-version", "tls1.0"],
        vec!["-ui", "-v2ray-cert-sha256", "bad"],
        vec!["-ui", "-proxy", "file:///etc/passwd"],
        vec!["-ui", "-unknown", "x"],
        vec!["-ui", "trailing"],
    ] {
        assert!(Config::parse(&args(&a)).is_err(), "{a:?}");
    }
    for s in [
        "vmess://%%%",
        "vless://u@host:0",
        "vless://u@host:443?security=reality",
        "trojan://u@host:443?type=bad",
    ] {
        assert!(Protocol::parse(s).is_err());
    }
    let mut p = ssh();
    p.args.extend(args(&["-socks-port", "65536"]));
    assert!(Config::parse(&p.args).is_err());
}
#[test]
fn config_generation_preserves_security_and_routes() {
    let c=Config::parse(&args(&["-mode","xray","-v2ray-link","vless://uuid@host.example:443?security=tls&sni=cdn.example&type=ws&host=cdn.example&path=%2Fabc","-tls-version","tls1.3"])).unwrap();
    let p = c.protocol().unwrap();
    let v = xray_config(&c, &p, Some(&"ab".repeat(32)));
    assert_eq!(v["inbounds"][0]["listen"], "127.0.0.1");
    assert_eq!(
        v["outbounds"][0]["streamSettings"]["tlsSettings"]["minVersion"],
        "1.3"
    );
    assert!(
        v["outbounds"][0]["streamSettings"]["tlsSettings"]
            .get("allowInsecure")
            .is_none()
    );
    assert_eq!(
        v["outbounds"][0]["streamSettings"]["wsSettings"]["path"],
        "/abc"
    );
    let c = Config::parse(&ssh().args).unwrap();
    let v = tun_config(&c, &["192.0.2.1/32".into()], "linux");
    assert_eq!(v["inbounds"][0]["auto_redirect"], true);
    assert_eq!(v["inbounds"][0]["route_exclude_address"][0], "192.0.2.1/32");
    assert_eq!(v["outbounds"][0]["network"], "tcp");
    assert_eq!(v["route"]["rules"][1]["action"], "reject");
    assert_eq!(v["dns"]["servers"][0]["detour"], "proxy");
    assert!(
        tun_config(&c, &[], "macos")["inbounds"][0]
            .get("auto_redirect")
            .is_none()
    );
    assert!(!pac_script(1080).contains("; DIRECT"));
}
#[test]
fn ipv4_dns_filters_aaaa_and_service_hints_only_for_ssh_compatibility() {
    for platform in ["linux", "macos", "windows"] {
        let mut c = Config::parse(&ssh().args).unwrap();
        assert_eq!(tun_config(&c, &[], platform)["dns"]["rules"], json!([]));
        c.flags.insert("ssh-ipv4-only".into(), "true".into());
        let v = tun_config(&c, &[], platform);
        assert_eq!(v["dns"]["strategy"], "ipv4_only");
        assert_eq!(
            v["dns"]["rules"][0],
            json!({"query_type":["AAAA","HTTPS","SVCB"],"action":"predefined","rcode":"NOERROR"})
        );
        // IPv6 remains captured: unsupported traffic must not escape directly.
        assert_eq!(v["inbounds"][0]["address"].as_array().unwrap().len(), 2);
        c.flags.insert("mode".into(), "xray".into());
        assert_eq!(tun_config(&c, &[], platform)["dns"]["rules"], json!([]));
    }
}
#[test]
fn compact_sharing_roundtrip_and_tamper_rejection() {
    for password in ["", "password123"] {
        let p = ssh();
        let code = sharing::encode(p.clone(), password).unwrap();
        assert!(code.starts_with(if password.is_empty() { "TN2." } else { "TN2P." }));
        let decoded = sharing::decode(&code, password).unwrap();
        assert_eq!(decoded.args, p.args);
        assert_eq!(decoded.name, p.name);
        let mut damaged = code.into_bytes();
        let n = damaged.len() - 5;
        damaged[n] = if damaged[n] == b'A' { b'B' } else { b'A' };
        assert!(sharing::decode(std::str::from_utf8(&damaged).unwrap(), password).is_err());
    }
    let code = sharing::encode(ssh(), "password123").unwrap();
    assert!(sharing::decode(&code, "wrong-password").is_err());
    assert!(sharing::encode(ssh(), "short").is_err());
    let mut p = ssh();
    p.args.extend(args(&["-payload-file", "/etc/passwd"]));
    assert!(sharing::encode(p, "").is_err());
    let mut p = ssh();
    p.args.extend(args(&["-ui"]));
    assert!(sharing::validate(p).is_err());
    let mut p = ssh();
    p.args.extend(args(&["-H", "other"]));
    assert!(sharing::validate(p).is_err());
    assert!(sharing::decode(&format!("TN2.{}", "A".repeat(25000)), "").is_err());
}
#[test]
fn vault_encryption_password_restart_and_session_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profiles.db");
    let mut s = Store::open_password(&path).unwrap();
    assert_eq!(s.status()["locked"], true);
    assert!(s.save(ssh()).is_err());
    s.unlock("a-long-master-password").unwrap();
    let p = s.save(ssh()).unwrap();
    assert!(p.id > 0);
    assert_eq!(s.get(p.id).unwrap().args, p.args);
    let mut ephemeral = ssh();
    ephemeral.name = "Session".into();
    ephemeral.session_only = true;
    // Alternate flag spelling must not bypass session-only credential removal.
    ephemeral.args = args(&[
        "--mode=ssh",
        "--H=example.com",
        "--P=443",
        "--u=alice",
        "--p=session-secret-value",
    ]);
    let ephemeral = s.save(ephemeral).unwrap();
    assert!(
        s.get(ephemeral.id)
            .unwrap()
            .args
            .contains(&"session-secret-value".into())
    );
    let imported = s.import(ssh()).unwrap();
    assert_eq!(imported.name, "Test SSH (2)");
    drop(s);
    let disk = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&disk);
    assert!(!text.contains("a-secret-password"));
    assert!(!text.contains("session-secret-value"));
    let mut s = Store::open_password(&path).unwrap();
    assert!(s.list().unwrap().iter().all(|p| p.locked));
    assert!(s.unlock("incorrect-password").is_err());
    s.unlock("a-long-master-password").unwrap();
    let session = s
        .list()
        .unwrap()
        .into_iter()
        .find(|p| p.id == ephemeral.id)
        .unwrap();
    assert!(session.needs_credentials);
    assert!(!session.args.contains(&"session-secret-value".into()));
    assert!(s.get(ephemeral.id).is_err());
    s.delete(p.id).unwrap();
    assert!(s.get(p.id).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn explicit_session_trust_opt_out_is_portable_and_does_not_expose_session_credentials() {
    let mut profile = ssh();
    profile
        .args
        .insert(0, "-ssh-trust-on-first-use=false".into());
    let encoded = sharing::encode(profile.clone(), "").unwrap();
    let decoded = sharing::decode(&encoded, "").unwrap();
    assert_eq!(decoded.args, profile.args);
    assert!(
        !Config::parse(&decoded.args)
            .unwrap()
            .boolean("ssh-trust-on-first-use")
    );
    let removed = tunnelnest::store::credentials_removed(&decoded.args);
    assert!(
        !removed
            .iter()
            .any(|value| value == "a-secret-password" || value == "alice")
    );
    let mut duplicate = profile;
    duplicate.args.push("-ssh-trust-on-first-use".into());
    assert!(sharing::validate(duplicate).is_err());
}
