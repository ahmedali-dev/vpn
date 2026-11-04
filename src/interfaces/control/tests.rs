//! Authentication, helper lifecycle and log cursor regression tests.
use super::Control;
use super::LogCursor;
use super::helper::log_overlap;
use super::helper::mirror_logs;
use crate::config::Config;
use crate::logging;
use crate::runtime::Reporter;
use axum::Json;
use axum::Router;
use serde_json::json;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
mod log_mirror_tests {
    use super::*;
    #[test]
    fn rolling_snapshots_and_stale_polls_do_not_duplicate_saved_logs() {
        let report = Reporter::default();
        let cursor = Mutex::new(LogCursor::default());
        let first = json!({"logs":"first\nsecond\n","logSession":"one","logStart":0,"logEnd":13});
        mirror_logs(&report, &cursor, &first);
        mirror_logs(
            &report,
            &cursor,
            &json!({"logs":"second\nthird\n","logSession":"one","logStart":6,"logEnd":19}),
        );
        mirror_logs(&report, &cursor, &first);
        let text = report.snapshot()["logs"].as_str().unwrap().to_owned();
        assert_eq!(text.matches("first").count(), 1);
        assert_eq!(text.matches("second").count(), 1);
        assert_eq!(text.matches("third").count(), 1);
        mirror_logs(
            &report,
            &cursor,
            &json!({"logs":"first\n","logSession":"two","logStart":0,"logEnd":6}),
        );
        assert_eq!(
            report.snapshot()["logs"]
                .as_str()
                .unwrap()
                .matches("first")
                .count(),
            2,
            "a new session is a new stream"
        );
        mirror_logs(&report, &cursor, &first);
        assert_eq!(
            report.snapshot()["logs"]
                .as_str()
                .unwrap()
                .matches("first")
                .count(),
            2,
            "a late response from a retired session must be ignored"
        );
    }
    #[test]
    fn legacy_rolling_overlap_handles_unicode_and_source_resets() {
        let report = Reporter::default();
        let cursor = Mutex::new(LogCursor::default());
        for text in [
            "first\nمرحبا\nsecond\n",
            "حبا\nsecond\nthird\n",
            "second\nthird\n",
        ] {
            mirror_logs(&report, &cursor, &json!({"logs":text}));
        }
        let text = report.snapshot()["logs"].as_str().unwrap().to_owned();
        assert_eq!(text.matches("second").count(), 1);
        assert_eq!(text.matches("third").count(), 1);
        assert_eq!(log_overlap(b"ababab", b"ababx"), 4);
    }
    #[test]
    fn cursor_gaps_are_reported_and_malformed_offsets_do_not_panic() {
        let report = Reporter::default();
        let cursor = Mutex::new(LogCursor::default());
        mirror_logs(
            &report,
            &cursor,
            &json!({"logs":"a\n","logSession":"s","logStart":0,"logEnd":2}),
        );
        mirror_logs(
            &report,
            &cursor,
            &json!({"logs":"b\n","logSession":"s","logStart":10,"logEnd":12}),
        );
        assert!(
            report.snapshot()["logs"]
                .as_str()
                .unwrap()
                .contains("8 bytes were missed")
        );
        mirror_logs(
            &report,
            &cursor,
            &json!({"logs":"é\n","logSession":"s","logStart":11,"logEnd":14}),
        );
    }
    #[test]
    fn helper_snapshots_append_only_new_events_to_user_files() {
        let dir = tempfile::tempdir().unwrap();
        let report = Reporter::persistent_in(dir.path(), &Config::default());
        let previous = Mutex::new(LogCursor::default());
        let first = json!({"logs":"[INFO] SSH established\n"});
        mirror_logs(&report, &previous, &first);
        let initial = report.snapshot()["logs"].as_str().unwrap().to_owned();
        mirror_logs(&report, &previous, &first);
        assert_eq!(report.snapshot()["logs"], initial);
        mirror_logs(
            &report,
            &previous,
            &json!({"logs":"[INFO] SSH established\n[ERROR] Remote closed\n"}),
        );
        let status = report.snapshot();
        let text = status["logs"].as_str().unwrap();
        assert_eq!(text.matches("SSH established").count(), 1);
        assert!(text.contains("Remote closed"));
        let saved = logging::read(dir.path(), status["logFile"].as_str().unwrap()).unwrap();
        assert!(saved.contains("Remote closed"));
        assert!(
            saved.contains("[ERROR] [HELPER]"),
            "mirroring must preserve source severity"
        );
    }
}

#[cfg(test)]
mod helper_recovery_tests {
    use super::*;
    #[tokio::test]
    async fn unreachable_helper_detaches_without_breaking_local_status_or_losing_logs() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app=Router::new().fallback(||async{Json(json!({"administrator":true,"state":"connected","logs":"previous helper message\n","logSession":"fixture","logStart":0,"logEnd":24}))});
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let c = Control::new(
            "127.0.0.1:12345".into(),
            "a".repeat(64),
            false,
            None,
            CancellationToken::new(),
        );
        c.set_log_dir(dir.path().into());
        let url = format!("http://{address}/#{}", "b".repeat(64));
        c.attach(&url).await.unwrap();
        assert_eq!(c.status().await.unwrap()["helperAvailable"], true);
        c.detach_failed_helper(
            &format!("http://127.0.0.1:1/#{}", "c".repeat(64))
                .parse()
                .unwrap(),
        )
        .await;
        assert!(
            c.helper_url().await.is_some(),
            "a stale poll must not detach a replacement helper"
        );
        server.abort();
        let _ = server.await;
        let status = tokio::time::timeout(Duration::from_secs(3), c.status())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status["state"], "error");
        assert_eq!(status["helperAvailable"], false);
        assert_eq!(status["recovery"]["tunCleanupVerified"], false);
        assert!(
            status["logs"]
                .as_str()
                .unwrap()
                .contains("previous helper message")
        );
        assert!(c.helper_url().await.is_none());
        assert!(!status.to_string().contains(&"b".repeat(64)));
        c.stop().await.unwrap();
        assert_eq!(c.status().await.unwrap()["state"], "error");
    }
}
