use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tunnelnest::control::{Control, router};

#[tokio::test]
async fn profile_diagnostics_requires_authentication_and_a_saved_profile() {
    let host = "127.0.0.1:12345";
    let token = "a".repeat(64);
    let control = Control::new(
        host.into(),
        token.clone(),
        false,
        None,
        CancellationToken::new(),
    );
    for (auth, expected) in [
        ("", StatusCode::UNAUTHORIZED),
        (token.as_str(), StatusCode::BAD_REQUEST),
    ] {
        let response = router(control.clone())
            .oneshot(
                Request::post("/api/profiles/diagnose")
                    .header("Host", host)
                    .header("X-Tunnel-Token", auth)
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"id":7}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn saved_profile_report_has_scoped_results_without_secrets() {
    use axum::body::to_bytes;
    use tunnelnest::store::{Profile, Store};
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open_password(&temp.path().join("profiles.db")).unwrap();
    store.unlock("test-vault-password").unwrap();
    let profile = store
        .save(Profile {
            name: "Private profile".into(),
            mode: "ssh".into(),
            args: [
                "-H",
                "server.invalid",
                "-P",
                "443",
                "-u",
                "private-user",
                "-p",
                "private-password",
                "-proxy",
                "http://proxy-user:proxy-password@127.0.0.1:8080",
            ]
            .map(String::from)
            .to_vec(),
            ..Default::default()
        })
        .unwrap();
    let host = "127.0.0.1:12345";
    let token = "a".repeat(64);
    let control = Control::new(
        host.into(),
        token.clone(),
        false,
        Some(store),
        CancellationToken::new(),
    );
    let response = router(control)
        .oneshot(
            Request::post("/api/profiles/diagnose")
                .header("Host", host)
                .header("X-Tunnel-Token", token)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::json!({"id":profile.id}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(report["checks"][0]["state"], "skipped");
    assert_eq!(report["currentSession"]["state"], "disconnected");
    assert!(
        report["currentSession"]["scope"]
            .as_str()
            .unwrap()
            .contains("different profile")
    );
    let text = String::from_utf8(body.to_vec()).unwrap();
    for secret in [
        "Private profile",
        "private-user",
        "private-password",
        "proxy-user",
        "proxy-password",
        "server.invalid",
        "127.0.0.1",
    ] {
        assert!(!text.contains(secret), "{text}");
    }
}
