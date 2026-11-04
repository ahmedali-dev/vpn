//! Elevated helper client
//!
//! Validates authenticated loopback helper URLs and mirrors logs without exposing control tokens.

use super::Helper;
use super::LogCursor;
use crate::runtime::Reporter;
use anyhow::Result;
use anyhow::ensure;
use serde_json::Value;
use serde_json::json;
use std::sync::Mutex;
use std::time::Duration;

pub(super) async fn close_helper(helper: Helper) {
    let _ = helper_request(&helper.url, "stop", Some(json!({}))).await;
    if let Ok(status) = helper_request(&helper.url, "status", None).await {
        mirror_logs(&helper.mirror, &helper.last, &status);
    }
    let _ = helper_request(&helper.url, "quit", Some(json!({}))).await;
}
pub(super) fn mirror_logs(report: &Reporter, last: &Mutex<LogCursor>, status: &Value) {
    let current = status["logs"].as_str().unwrap_or("");
    let mut previous = last.lock().unwrap();
    if let (Some(session), Some(start), Some(end)) = (
        status["logSession"].as_str(),
        status["logStart"].as_u64(),
        status["logEnd"].as_u64(),
    ) && !session.is_empty()
        && end.checked_sub(start) == Some(current.len() as u64)
    {
        if previous.retired.iter().any(|old| old == session) {
            return;
        }
        let same = previous.session == session;
        if same && end <= previous.end {
            return;
        }
        let offset = if same {
            previous.end.saturating_sub(start).min(current.len() as u64) as usize
        } else {
            0
        };
        if current.is_char_boundary(offset) {
            if same && previous.end < start {
                report.event(
                    "WARN",
                    "HELPER",
                    format!(
                        "Helper log buffer advanced before polling; {} bytes were missed",
                        start - previous.end
                    ),
                );
            }
            mirror_events(report, &current[offset..]);
            if !same && !previous.session.is_empty() {
                if previous.retired.len() == 32 {
                    previous.retired.pop_front();
                }
                let old = std::mem::take(&mut previous.session);
                previous.retired.push_back(old);
            }
            previous.session = session.into();
            previous.end = end;
            previous.legacy.clear();
            return;
        }
    }
    // Older helpers do not expose cursors. Find the exact rolling-buffer overlap
    // in linear time, including snapshots truncated in the middle of a log line.
    if current.is_empty() || previous.legacy.contains(current) {
        return;
    }
    let overlap = log_overlap(previous.legacy.as_bytes(), current.as_bytes());
    if current.is_char_boundary(overlap) {
        mirror_events(report, &current[overlap..]);
    }
    previous.legacy = current.into();
}
pub(super) fn mirror_events(report: &Reporter, fragment: &str) {
    for line in fragment.lines() {
        let header = line.find('[').map(|i| &line[i..]).unwrap_or("");
        let level = if header.starts_with("[ERROR]") {
            "ERROR"
        } else if header.starts_with("[WARN]") {
            "WARN"
        } else {
            "INFO"
        };
        report.event(level, "HELPER", line);
    }
}
pub(super) fn log_overlap(previous: &[u8], current: &[u8]) -> usize {
    if current.is_empty() {
        return 0;
    }
    let mut prefix = vec![0usize; current.len()];
    for i in 1..current.len() {
        let mut n = prefix[i - 1];
        while n > 0 && current[i] != current[n] {
            n = prefix[n - 1];
        }
        if current[i] == current[n] {
            n += 1;
        }
        prefix[i] = n;
    }
    let mut matched = 0;
    for byte in previous {
        while matched > 0 && (matched == current.len() || *byte != current[matched]) {
            matched = prefix[matched - 1];
        }
        if *byte == current[matched] {
            matched += 1;
        }
    }
    matched
}
pub fn valid_helper(raw: &str) -> Result<url::Url> {
    let u = url::Url::parse(raw.trim())?;
    ensure!(
        u.scheme() == "http"
            && u.host_str() == Some("127.0.0.1")
            && u.port().is_some()
            && u.path() == "/"
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment()
                .is_some_and(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())),
        "invalid helper URL"
    );
    Ok(u)
}
pub(crate) async fn helper_request(
    url: &url::Url,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let target = url.join(&format!("api/{path}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(if path == "profiles/diagnose" {
            60
        } else {
            25
        }))
        .build()?;
    let req = if let Some(body) = body {
        client.post(target).json(&body)
    } else {
        client.get(target)
    };
    let response = req
        .header("X-Tunnel-Token", url.fragment().unwrap_or(""))
        .send()
        .await?;
    let success = response.status().is_success();
    let data: Value = response.json().await?;
    ensure!(
        success,
        "helper: {}",
        data["error"].as_str().unwrap_or("request failed")
    );
    Ok(data)
}
