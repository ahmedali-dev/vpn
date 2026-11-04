//! TunnelNest application library.
//!
//! Feature implementations live in features/, technical adapters in infrastructure/, entry interfaces in interfaces/. Stable root exports preserve existing callers.

pub mod features;
pub mod infrastructure;
pub mod interfaces;
pub use features::profiles::sharing;
pub use features::{
    configuration as config, connections as runtime, diagnostics, notifications, recovery, routing,
    traffic, tun,
};
pub(crate) use infrastructure::hostname;
pub use infrastructure::{cores as core, logging, network, persistence as store, transport};
pub use interfaces::control;
#[cfg(feature = "desktop")]
pub use interfaces::desktop;
#[cfg(all(feature = "desktop", target_os = "macos"))]
pub(crate) use interfaces::macos_notifications;
