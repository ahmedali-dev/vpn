//! Local control interface.
//!
//! Owns shared control state. Business commands, authenticated HTTP, helper communication and asset delivery have separate files.

use crate::runtime::Reporter;
use crate::runtime::Session;
use crate::store::Store;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
struct Helper {
    url: url::Url,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    mirror: Reporter,
    last: Arc<Mutex<LogCursor>>,
}
impl Drop for Helper {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
pub struct Control {
    host: String,
    token: String,
    helper_only: bool,
    cancel: CancellationToken,
    session: AsyncMutex<Option<Session>>,
    diagnosing: AsyncMutex<()>,
    cloud: AsyncMutex<Option<crate::infrastructure::cloud::Cloud>>,
    store: Mutex<Option<Store>>,
    helper: AsyncMutex<Option<Helper>>,
    helper_failure: Mutex<Option<Value>>,
    last_lease: AtomicU64,
    epoch: Instant,
    log_dir: Mutex<Option<PathBuf>>,
}
#[derive(Default)]
struct LogCursor {
    session: String,
    end: u64,
    legacy: String,
    retired: std::collections::VecDeque<String>,
}

mod api;
mod assets;
mod cloud;
mod diagnostics;
mod helper;
mod http;
mod server;
mod service;
pub use diagnostics::diagnostics;
#[cfg(feature = "desktop")]
pub(crate) use helper::helper_request;
pub use helper::valid_helper;
pub use http::router;
pub use server::serve;
pub use server::serve_with_ready;
#[cfg(test)]
mod tests;
