//! External-core log adapter
//!
//! Drains bounded core output and translates failures into sanitized session events.

use super::status::Reporter;
use crate::core::CoreProcess;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncRead;
use tokio::io::BufReader;
use tokio::task::JoinSet;

pub(super) async fn pipe_log<S: AsyncRead + Unpin + Send + 'static>(
    stream: S,
    r: Reporter,
    source: &'static str,
) {
    let mut reader = BufReader::new(stream);
    let mut pending = vec![];
    let mut oversized = false;
    loop {
        let chunk = match reader.fill_buf().await {
            Ok(chunk) => chunk,
            Err(e) => {
                r.event("WARN", source, format!("Cannot read core output: {e}"));
                break;
            }
        };
        if chunk.is_empty() {
            if !pending.is_empty() || oversized {
                core_line(&r, source, &pending, oversized);
            }
            break;
        }
        let consumed = chunk
            .iter()
            .position(|b| *b == b'\n')
            .map_or(chunk.len(), |i| i + 1);
        let complete = chunk[consumed - 1] == b'\n';
        if pending.len() + consumed <= 16000 && !oversized {
            pending.extend_from_slice(&chunk[..consumed]);
        } else {
            oversized = true;
            pending.clear();
        }
        reader.consume(consumed);
        if complete {
            core_line(&r, source, &pending, oversized);
            pending.clear();
            oversized = false;
        }
    }
}
pub(super) fn core_line(r: &Reporter, source: &str, data: &[u8], oversized: bool) {
    if oversized {
        r.event(
            "WARN",
            source,
            "Oversized core log line omitted (limit 16000 bytes)",
        );
        return;
    }
    let line = String::from_utf8_lossy(data);
    let lower = line.to_ascii_lowercase();
    let failure = if source.starts_with("CORE") {
        crate::traffic::Failure::classify(&line)
    } else {
        None
    };
    if let Some(kind) = failure {
        r.traffic_failure(kind, &line);
    }
    let severity = if lower.contains("[error]") || lower.contains("[fatal]") {
        "ERROR"
    } else if lower.contains("[warning]") || lower.contains("[warn]") {
        "WARN"
    } else if lower.contains("[info]") || lower.contains("[debug]") {
        "INFO"
    } else if lower.contains("panic:") || lower.contains("fatal:") {
        "ERROR"
    } else {
        "INFO"
    };
    let level = if severity == "INFO"
        && failure.is_some_and(|kind| kind != crate::traffic::Failure::ClientClosed)
    {
        "WARN"
    } else {
        severity
    };
    r.event(level, source, line.trim_end());
}

pub(super) fn capture(
    core: &mut CoreProcess,
    r: &Reporter,
    jobs: &mut JoinSet<()>,
    source: &'static str,
) {
    if let Some(out) = core.child().stdout.take() {
        jobs.spawn(pipe_log(
            out,
            r.clone(),
            if source == "TUN" {
                "TUN/STDOUT"
            } else {
                "CORE/STDOUT"
            },
        ));
    }
    if let Some(err) = core.child().stderr.take() {
        jobs.spawn(pipe_log(
            err,
            r.clone(),
            if source == "TUN" {
                "TUN/STDERR"
            } else {
                "CORE/STDERR"
            },
        ));
    }
}
