//! Authenticated HTTP interface
//!
//! Defines request DTOs, host/origin/token guards, response handling and routing to use cases.

use super::Control;
use super::api::api;
use super::assets::asset;
use anyhow::Result;
use axum::Json;
use axum::Router;
use axum::body::to_bytes;
use axum::extract::Request;
use axum::extract::State;
use axum::http::Method;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;

pub(super) fn json_response(status: StatusCode, v: Value) -> Response {
    (status, Json(v)).into_response()
}
pub(super) async fn read<T: DeserializeOwned>(req: Request) -> Result<T> {
    let raw = to_bytes(req.into_body(), 128 * 1024).await?;
    Ok(serde_json::from_slice(&raw)?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Args {
    pub(super) args: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Link {
    pub(super) link: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Password {
    pub(super) password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Id {
    pub(super) id: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Share {
    pub(super) id: i64,
    #[serde(default)]
    pub(super) password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Import {
    pub(super) code: String,
    #[serde(default)]
    pub(super) password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LogFile {
    pub(super) name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attach {
    pub(super) url: String,
}

pub fn router(control: Arc<Control>) -> Router {
    Router::new().fallback(handle).with_state(control)
}
pub(super) async fn handle(State(c): State<Arc<Control>>, req: Request) -> Response {
    let mut response = dispatch(c, req).await;
    let h = response.headers_mut();
    for (key, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    ] {
        h.insert(
            header::HeaderName::from_static(key),
            header::HeaderValue::from_static(value),
        );
    }
    response
}
pub(super) async fn dispatch(c: Arc<Control>, req: Request) -> Response {
    let error = |s, status| json_response(status, json!({"error":s}));
    if req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        != Some(c.host.as_str())
    {
        return error("invalid host", StatusCode::FORBIDDEN);
    }
    if let Some(origin) = req.headers().get(header::ORIGIN)
        && origin.as_bytes() != format!("http://{}", c.host).as_bytes()
    {
        return error("invalid origin", StatusCode::FORBIDDEN);
    }
    let path = req.uri().path().to_owned();
    if !path.starts_with("/api/") {
        if c.helper_only {
            return StatusCode::NOT_FOUND.into_response();
        }
        if req.method() != Method::GET {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        return asset(&path);
    }
    let token = req
        .headers()
        .get("x-tunnel-token")
        .map(|v| v.as_bytes())
        .unwrap_or(&[]);
    if !bool::from(token.ct_eq(c.token.as_bytes())) {
        return error("unauthorized", StatusCode::UNAUTHORIZED);
    }
    if c.helper_only
        && ![
            "/api/start",
            "/api/stop",
            "/api/status",
            "/api/quit",
            "/api/lease",
            "/api/diagnostics",
        ]
        .contains(&path.as_str())
    {
        return error("helper endpoint is restricted", StatusCode::FORBIDDEN);
    }
    let get = [
        "/api/status",
        "/api/profiles",
        "/api/vault/status",
        "/api/diagnostics",
        "/api/logs",
    ]
    .contains(&path.as_str());
    if req.method() != if get { Method::GET } else { Method::POST } {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    match api(c, &path, req).await {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({"error":e.to_string()})),
    }
}
