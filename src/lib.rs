pub mod config;
pub mod control;
pub mod core;
pub mod diagnostics;
mod hostname;
pub mod logging;
pub mod network;
pub mod notifications;
pub mod recovery;
pub mod routing;
pub mod runtime;
pub mod sharing;
pub mod store;
pub mod traffic;
pub mod transport;
pub mod tun;

#[cfg(feature = "desktop")]
pub mod desktop;

#[cfg(all(feature = "desktop", target_os = "macos"))]
mod macos_notifications;
