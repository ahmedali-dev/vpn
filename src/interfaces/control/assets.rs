//! Embedded desktop assets
//!
//! Serves only explicitly registered bundled files; never reads arbitrary filesystem paths.

use axum::body::Body;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;

pub(super) fn asset(path: &str) -> Response {
    let (bytes, mime): (&'static [u8], &str) = match path {
        "/" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/index.html"
            )),
            "text/html; charset=utf-8",
        ),
        "/shared/state.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/shared/state.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/profile-editor.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/profile-editor.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/profile-library.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/profile-library.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/profile-arguments.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/profile-arguments.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/connection.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/connection.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/diagnostics.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/diagnostics.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/notifications.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/notifications.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/activity.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/activity.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/saved-logs.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/saved-logs.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/sharing.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/sharing.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/vault.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/vault.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/trust.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/trust.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/dashboard.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/dashboard.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/navigation.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/navigation.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/updates.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/updates.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/features/cloud.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/features/cloud.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/app.js" => (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/desktop/ui/app.js")),
            "text/javascript; charset=utf-8",
        ),
        "/dropdowns.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/dropdowns.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/profile-input.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/profile-input.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/profile-options.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/profile-options.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/share-qr.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/share-qr.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/qr-reader.js" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/qr-reader.js"
            )),
            "text/javascript; charset=utf-8",
        ),
        "/qrcode.js" => (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/desktop/ui/qrcode.js")),
            "text/javascript; charset=utf-8",
        ),
        "/style.css" => (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/desktop/ui/style.css")),
            "text/css; charset=utf-8",
        ),
        "/tunnelnest-mark.png" => (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/desktop/ui/tunnelnest-mark.png"
            )),
            "image/png",
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .body(Body::from(bytes))
        .unwrap()
}
