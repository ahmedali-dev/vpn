use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tunnelnest::control::{Control, router, valid_helper};

#[tokio::test]
async fn authenticated_control_and_static_assets() {
    let token = "a".repeat(64);
    let cancel = CancellationToken::new();
    let control = Control::new(
        "127.0.0.1:12345".into(),
        token.clone(),
        false,
        None,
        cancel.clone(),
    );
    let app = router(control);
    for (path, host, auth, origin, status) in [
        (
            "/api/status",
            "127.0.0.1:12345",
            "",
            "",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/api/status",
            "evil.test",
            token.as_str(),
            "",
            StatusCode::FORBIDDEN,
        ),
        (
            "/api/status",
            "127.0.0.1:12345",
            token.as_str(),
            "http://evil.test",
            StatusCode::FORBIDDEN,
        ),
        (
            "/api/status",
            "127.0.0.1:12345",
            token.as_str(),
            "",
            StatusCode::OK,
        ),
        ("/", "127.0.0.1:12345", "", "", StatusCode::OK),
        ("/app.js", "127.0.0.1:12345", "", "", StatusCode::OK),
        ("/dropdowns.js", "127.0.0.1:12345", "", "", StatusCode::OK),
        (
            "/profile-input.js",
            "127.0.0.1:12345",
            "",
            "",
            StatusCode::OK,
        ),
        ("/qr-reader.js", "127.0.0.1:12345", "", "", StatusCode::OK),
        (
            "/../../Cargo.toml",
            "127.0.0.1:12345",
            "",
            "",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let mut req = Request::builder()
            .uri(path)
            .header("host", host)
            .header("x-tunnel-token", auth);
        if !origin.is_empty() {
            req = req.header("origin", origin)
        }
        let r = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), status, "{path} {host}");
        assert_eq!(r.headers()["cache-control"], "no-store");
    }
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/import")
                .header("host", "127.0.0.1:12345")
                .header("x-tunnel-token", &token)
                .body(Body::from(
                    json!({"link":"trojan://secret@example.com:443"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let data = axum::body::to_bytes(r.into_body(), 65536).await.unwrap();
    let data: serde_json::Value = serde_json::from_slice(&data).unwrap();
    assert_eq!(data["Protocol"], "trojan");
    assert_eq!(data["UUID"], "secret");
    for body in [
        r#"{"args":["-ui"]}"#.to_string(),
        r#"{"args":[],"unknown":1}"#.to_string(),
        "x".repeat(140000),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/start")
                    .header("host", "127.0.0.1:12345")
                    .header("x-tunnel-token", &token)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/quit")
                .header("host", "127.0.0.1:12345")
                .header("x-tunnel-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(cancel.is_cancelled());
}
#[tokio::test]
async fn helper_restricts_profiles_and_requires_tun() {
    let token = "b".repeat(64);
    let app = router(Control::new(
        "127.0.0.1:12345".into(),
        token.clone(),
        true,
        None,
        CancellationToken::new(),
    ));
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/profiles")
                .header("host", "127.0.0.1:12345")
                .header("x-tunnel-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/start")
                .header("host", "127.0.0.1:12345")
                .header("x-tunnel-token", &token)
                .body(Body::from(
                    json!({"args":["-mode","ssh","-H","host","-P","443","-u","u","-p","p"]})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}
#[test]
fn helper_urls_reject_remote_or_missing_tokens() {
    assert!(valid_helper(&format!("http://127.0.0.1:1234/#{}", "a".repeat(64))).is_ok());
    for url in [
        "http://example.com:1234/#x",
        "https://127.0.0.1:1234/",
        "http://127.0.0.1:1234/",
        "http://user@127.0.0.1:1234/",
    ] {
        assert!(valid_helper(url).is_err());
    }
}

#[tokio::test]
async fn saved_logs_require_authentication_and_reject_path_traversal() {
    use tunnelnest::{config::Config, runtime::Reporter};
    let dir = tempfile::tempdir().unwrap();
    let report = Reporter::persistent_in(dir.path(), &Config::default());
    report.log("saved test event");
    let name = report.snapshot()["logFile"].as_str().unwrap().to_owned();
    let token = "c".repeat(64);
    let control = Control::new(
        "127.0.0.1:12345".into(),
        token.clone(),
        false,
        None,
        CancellationToken::new(),
    );
    control.set_log_dir(dir.path().into());
    let app = router(control);
    for (auth, status) in [
        ("", StatusCode::UNAUTHORIZED),
        (token.as_str(), StatusCode::OK),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/logs")
                    .header("host", "127.0.0.1:12345")
                    .header("x-tunnel-token", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
    for (file, status) in [
        (name.as_str(), StatusCode::OK),
        ("../Cargo.toml", StatusCode::BAD_REQUEST),
        ("/etc/passwd", StatusCode::BAD_REQUEST),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/logs/read")
                    .header("host", "127.0.0.1:12345")
                    .header("x-tunnel-token", &token)
                    .body(Body::from(json!({"name":file}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if status == StatusCode::OK {
            let body = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            assert!(String::from_utf8_lossy(&body).contains("saved test event"));
        }
    }
}
