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

/// Exercise the actual HTTP client against a public API, with no auth or database.
#[tokio::test]
async fn public_api_add_update_refresh_delete_without_authentication() {
    use axum::{
        Router,
        body::to_bytes,
        extract::{Request, State},
        response::Json,
        routing::any,
    };
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tunnelnest::infrastructure::cloud::{Cloud, Connect};

    #[derive(Default)]
    struct PublicApi {
        record: Option<Value>,
        methods: Vec<String>,
    }
    async fn handle(State(state): State<Arc<Mutex<PublicApi>>>, req: Request) -> Json<Value> {
        assert!(!req.headers().contains_key("authorization"));
        assert!(!req.headers().contains_key("cookie"));
        let method = req.method().to_string();
        let path = req.uri().path().to_owned();
        if path == "/api/public/status" {
            assert_eq!(method, "GET");
            return Json(json!({"public":true,"version":1}));
        }
        assert!(
            req.headers()
                .get("origin")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("http://127.0.0.1:")
        );
        let bytes = to_bytes(req.into_body(), 65536).await.unwrap();
        let mut api = state.lock().unwrap();
        api.methods.push(method.clone());
        match method.as_str() {
            "PUT" => {
                let mut value: Value = serde_json::from_slice(&bytes).unwrap();
                value["id"] = json!(path.rsplit('/').next().unwrap());
                api.record = Some(value);
                Json(json!({"server":{"id":path.rsplit('/').next().unwrap()}}))
            }
            "GET" => Json(json!({"servers":api.record.iter().collect::<Vec<_>>(),"next":null})),
            "DELETE" => {
                api.record = None;
                Json(json!({"ok":true}))
            }
            _ => panic!("Unexpected public API request"),
        }
    }
    let state = Arc::new(Mutex::new(PublicApi::default()));
    let app = Router::new()
        .route("/api/public/{*path}", any(handle))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let cloud = Cloud::connect(Connect { url }).await.unwrap();
    let id = "0123456789abcdef01234567";
    cloud.upload(id, &profile()).await.unwrap();
    let mut edited = profile();
    edited.name = "Updated through public API".into();
    cloud.upload(id, &edited).await.unwrap();
    let records = cloud.download().await.unwrap();
    assert_eq!(
        records.len(),
        1,
        "Updating must retain the original remote ID"
    );
    assert_eq!(records[0].id, id);
    assert_eq!(records[0].name, edited.name);
    assert_eq!(records[0].credentials.password, "password");
    cloud.delete(id).await.unwrap();
    assert!(cloud.download().await.unwrap().is_empty());
    assert_eq!(
        state.lock().unwrap().methods,
        ["PUT", "PUT", "GET", "DELETE", "GET"]
    );
    task.abort();
}
