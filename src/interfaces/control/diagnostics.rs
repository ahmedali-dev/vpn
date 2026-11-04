//! Control diagnostics projection
//!
//! Builds a safe diagnostic view of the current session without exporting raw credentials.

use crate::logging;
use crate::runtime::is_admin;
use serde_json::Value;
use serde_json::json;

pub fn diagnostics(status: &Value) -> Value {
    fn clean(value: Value) -> Value {
        match value {
            Value::String(s) => Value::String(logging::Redactor::default().clean(&s)),
            Value::Array(a) => Value::Array(a.into_iter().map(clean).collect()),
            Value::Object(m) => Value::Object(m.into_iter().map(|(k, v)| (k, clean(v))).collect()),
            v => v,
        }
    }
    let logs = status["logs"].as_str().unwrap_or("");
    let tail = logs
        .char_indices()
        .rev()
        .nth(16000)
        .map(|(i, _)| &logs[i..])
        .unwrap_or(logs);
    clean(
        json!({"engine":"rust","version":env!("CARGO_PKG_VERSION"),"platform":std::env::consts::OS,"arch":std::env::consts::ARCH,"state":status["state"],"error":status["error"],"health":status["health"],"checks":status["checks"],"cores":status["cores"],"recovery":status["recovery"],"transportErrors":status["transportErrors"],"recentLogs":tail,"administrator":is_admin()}),
    )
}
