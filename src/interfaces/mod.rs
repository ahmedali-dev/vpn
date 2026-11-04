//! Application entry interfaces.
//!
//! The authenticated local HTTP API and native desktop adapter call business features; they do not define profile formats.

pub mod control;
#[cfg(feature = "desktop")]
pub mod desktop;
#[cfg(all(feature = "desktop", target_os = "macos"))]
pub(crate) mod macos_notifications;
