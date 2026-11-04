//! Connection business orchestration.
//!
//! Module index only: follow session -> preparation -> orchestrator -> attempt. Each service declares its dependencies explicitly; public compatibility exports are listed below.

mod attempt;
mod core_logs;
mod forwarding;
mod health;
mod orchestrator;
mod pac;
mod preparation;
mod session;
mod status;
pub use crate::infrastructure::privileges::is_admin;
pub use health::has_split_policy;
pub use health::verify;
pub use pac::pac_script;
pub use session::Session;
pub use status::Reporter;
pub use status::Status;
#[cfg(test)]
mod tests;
