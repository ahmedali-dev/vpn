use tunnelnest::{
    infrastructure::cloud::{base_url, from_profile, to_profile},
    store::{Profile, Store},
};
fn profile() -> Profile {
    Profile {
        name: "SSH cloud".into(),
        mode: "ssh".into(),
        args: [
            "-mode",
            "ssh",
            "-H",
            "example.com",
            "-P",
            "443",
            "-u",
            "user",
            "-p",
            "password",
            "-S",
            "web.whatsapp.com",
            "-ssh-trust-on-first-use",
        ]
        .map(str::to_owned)
        .to_vec(),
        ..Profile::default()
    }
}
#[test]
fn cloud_accepts_only_https_or_loopback_origins() {
    for url in [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://[::1]:3000",
        "https://management.example.com",
    ] {
        assert!(base_url(url).is_ok(), "{url}");
    }
    for url in [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/path",
        "https://example.com/?token=secret",
        "file:///tmp/cloud",
    ] {
        assert!(base_url(url).is_err(), "{url}");
    }
}
#[test]
fn cloud_roundtrip_keeps_portable_flags_but_applies_web_edits() {
    let mut server = from_profile(profile()).unwrap();
    assert_eq!(server.credentials.password, "password");
    assert!(
        server
            .credentials
            .profile_code
            .as_ref()
            .unwrap()
            .starts_with("TN2.")
    );
    server.id = "0123456789abcdef01234567".into();
    server.credentials.password = "web-edited-password".into();
    server.sni = "changed.example.com".into();
    let p = to_profile(server).unwrap();
    let c = tunnelnest::config::Config::parse(&p.args).unwrap();
    assert_eq!(c.get("p", ""), "web-edited-password");
    assert_eq!(c.get("S", ""), "changed.example.com");
    assert!(c.boolean("ssh-trust-on-first-use"));
}
#[test]
fn cloud_refresh_updates_bound_profiles_without_duplicates_or_lost_local_edits() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open_password(&dir.path().join("profiles.sqlite3")).unwrap();
    store.unlock("a strong vault password").unwrap();
    let p = store.save(profile()).unwrap();
    let id = store.cloud_remote("scope", p.id).unwrap();
    assert_eq!(id, store.cloud_remote("scope", p.id).unwrap());
    store.cloud_bind("scope", &id, &p).unwrap();
    let mut remote = profile();
    remote.name = "Renamed in cloud".into();
    assert!(store.cloud_receive("scope", &id, remote.clone()).unwrap());
    assert_eq!(store.list().unwrap().len(), 1);
    assert_eq!(store.get(p.id).unwrap().name, "Renamed in cloud");
    let mut local = store.get(p.id).unwrap();
    local.name = "Local unsynced edit".into();
    store.save(local).unwrap();
    assert!(!store.cloud_receive("scope", &id, remote).unwrap());
    assert_eq!(store.get(p.id).unwrap().name, "Local unsynced edit");
}

#[test]
fn web_vmess_without_sni_override_preserves_the_link_sni() {
    use tunnelnest::infrastructure::cloud::{Credentials, Server};
    let s=Server{id:"0123456789abcdef01234567".into(),name:"Web VLESS".into(),protocol:"v2ray".into(),address:String::new(),port:443,sni:String::new(),notes:String::new(),credentials:Credentials{link:"vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&sni=web.whatsapp.com&type=ws".into(),..Credentials::default()}};
    let p = to_profile(s).unwrap();
    let c = tunnelnest::config::Config::parse(&p.args).unwrap();
    assert!(!c.flags.contains_key("v2ray-sni"));
    assert_eq!(c.protocol().unwrap().sni, "web.whatsapp.com");
}
