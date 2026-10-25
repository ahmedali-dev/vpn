#![cfg(feature = "desktop")]
use serde_json::json;
use tunnelnest::desktop::share_file_bytes;
use tunnelnest::desktop::{app_navigation_allowed, request_control};
#[test]
fn native_exports_validate_content_and_sanitize_names() {
    let (name, extension, data) =
        share_file_bytes(&json!({"name":"a/b","format":"profile","code":"TN2.ABC_xyz"})).unwrap();
    assert_eq!(name, "TunnelNest-a-b.tnprofile");
    assert_eq!(extension, "tnprofile");
    assert_eq!(data, b"TN2.ABC_xyz\n");
    for value in [
        json!({"format":"profile","code":"file:///tmp/secret"}),
        json!({"format":"qr","image":"data:text/plain;base64,AAAA"}),
        json!({"format":"qr","image":"data:image/png;base64,AAAA"}),
        json!({"format":"bad"}),
    ] {
        assert!(share_file_bytes(&value).is_err());
    }
}

#[test]
fn desktop_navigation_is_confined_to_bundled_assets() {
    for url in [
        "tauri://localhost/index.html",
        "http://tauri.localhost/",
        "https://tauri.localhost/",
    ] {
        assert!(app_navigation_allowed(&url.parse().unwrap()), "{url}");
    }
    for url in [
        "https://example.com/",
        "http://127.0.0.1:12345/",
        "file:///etc/passwd",
        "tauri://evil.test/",
        "http://tauri.localhost.evil.test/",
        "http://tauri.localhost:1234/",
        "tauri://user@localhost/",
    ] {
        assert!(!app_navigation_allowed(&url.parse().unwrap()), "{url}");
    }
}

#[tokio::test]
async fn tauri_control_bridge_authenticates_and_restricts_api_requests() {
    use tokio_util::sync::CancellationToken;
    use tunnelnest::control::{Control, router};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let token = "a".repeat(64);
    let control = Control::new(
        address.to_string(),
        token.clone(),
        false,
        None,
        CancellationToken::new(),
    );
    let task = tokio::spawn(async move {
        axum::serve(listener, router(control)).await.unwrap();
    });
    let url = format!("http://{address}/#{token}").parse().unwrap();
    assert_eq!(
        request_control(&url, "status", None).await.unwrap()["state"],
        "disconnected"
    );
    let profile = request_control(
        &url,
        "import",
        Some(json!({"link":"trojan://secret@example.com:443"})),
    )
    .await
    .unwrap();
    assert_eq!(profile["Protocol"], "trojan");
    let wrong_token = format!("http://{address}/#{}", "b".repeat(64))
        .parse()
        .unwrap();
    assert!(
        request_control(&wrong_token, "status", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("unauthorized")
    );
    for (path, body) in [
        ("../status", None),
        ("quit", Some(json!({}))),
        ("helper/attach", Some(json!({"url":"http://evil.test"}))),
        ("status", Some(json!({}))),
        ("start", None),
        ("import", Some(json!({"link":"A".repeat(65536)}))),
    ] {
        assert!(request_control(&url, path, body).await.is_err(), "{path}");
    }
    task.abort();
}
