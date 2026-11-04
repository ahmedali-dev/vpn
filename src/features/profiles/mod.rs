//! Profile feature.
//!
//! Owns profile data, validation and portable sharing. Encrypted SQLite storage is an infrastructure adapter.

mod model;
pub mod service;
pub mod sharing;
pub use model::Profile;
pub use service::{credentials_removed, prepare_for_save};
