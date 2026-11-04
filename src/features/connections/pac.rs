//! PAC feature adapter
//!
//! Serves the local proxy auto-configuration file without changing system proxy settings.

use tokio::net::TcpListener;

pub fn pac_script(port: u16) -> String {
    format!(
        "function FindProxyForURL(url, host) {{ if (isPlainHostName(host) || host === 'localhost' || isInNet(host, '127.0.0.0', '255.0.0.0') || isInNet(host, '10.0.0.0', '255.0.0.0') || isInNet(host, '172.16.0.0', '255.240.0.0') || isInNet(host, '192.168.0.0', '255.255.0.0')) return 'DIRECT'; return 'SOCKS5 127.0.0.1:{port}'; }}"
    )
}
pub(super) async fn pac_server(listener: TcpListener, port: u16) {
    use axum::{Router, routing::get};
    let app = Router::new().route(
        "/proxy.pac",
        get(move || async move {
            (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/x-ns-proxy-autoconfig",
                )],
                pac_script(port),
            )
        }),
    );
    let _ = axum::serve(listener, app).await;
}
