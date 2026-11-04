//! Verified SSH/TLS transport service.
//!
//! Builds upstream proxy/payload transports, enforces TLS policy and SSH host-key trust, then authenticates SSH.

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;
pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

mod tls;
pub use tls::certificate_pin;
pub use tls::resolve_pin;
pub use tls::tls;
mod http_proxy;
pub use http_proxy::expand_payload;
pub use http_proxy::http_connect;
mod ssh;
pub use ssh::HostVerifier;
pub use ssh::connect_ssh;
pub use ssh::connect_ssh_logged;
pub use ssh::ssh_transport;
