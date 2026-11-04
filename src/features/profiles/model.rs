//! Saved profile model.
//!
//! The serialized fields are a compatibility contract: keep field names and defaults stable.

use serde::{Deserialize, Serialize};
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Profile {
    pub id: i64,
    pub name: String,
    pub mode: String,
    pub args: Vec<String>,
    pub schema_version: u32,
    pub updated_at: String,
    pub session_only: bool,
    pub needs_credentials: bool,
    pub locked: bool,
}
