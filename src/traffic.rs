//! Bounded per-stream error diagnostics; errors trigger verification, not a blind restart.
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Failure {
    WebSocket,
    Reset,
    Timeout,
    UdpClosed,
    ClientClosed,
}
impl Failure {
    pub fn classify(line: &str) -> Option<Self> {
        let lower = line.to_ascii_lowercase();
        if lower.contains("connection reset by peer") {
            Some(Self::Reset)
        } else if lower.contains("websocket: close 1006") {
            Some(Self::WebSocket)
        } else if lower.contains("operation timed out") {
            Some(Self::Timeout)
        } else if lower.contains("read/write on closed pipe") {
            Some(Self::UdpClosed)
        } else if lower.contains("broken pipe") {
            Some(Self::ClientClosed)
        } else {
            None
        }
    }
    pub fn upstream(self) -> bool {
        matches!(self, Self::WebSocket | Self::Reset | Self::Timeout)
    }
}
#[derive(Default)]
pub struct TrafficErrors {
    counts: [u64; 5],
    recent: VecDeque<Instant>,
    last_probe: Option<Instant>,
    last_reason: String,
}
impl TrafficErrors {
    pub fn record(&mut self, kind: Failure, now: Instant, reason: String) -> bool {
        let i = match kind {
            Failure::WebSocket => 0,
            Failure::Reset => 1,
            Failure::Timeout => 2,
            Failure::UdpClosed => 3,
            Failure::ClientClosed => 4,
        };
        self.counts[i] = self.counts[i].saturating_add(1);
        self.last_reason = reason.chars().take(512).collect();
        while self
            .recent
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) > Duration::from_secs(15))
        {
            self.recent.pop_front();
        }
        if kind.upstream() {
            if self.recent.len() == 32 {
                self.recent.pop_front();
            }
            self.recent.push_back(now);
        }
        let due = kind.upstream()
            && self.recent.len() >= 3
            && self
                .last_probe
                .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(30));
        if due {
            self.last_probe = Some(now);
        }
        due
    }
    pub fn snapshot(&self, now: Instant) -> Value {
        json!({"websocketClosures":self.counts[0],"connectionResets":self.counts[1],"timeouts":self.counts[2],"udpClosedPipes":self.counts[3],"clientClosedPipes":self.counts[4],"recentUpstreamFailures":self.recent.iter().filter(|at|now.saturating_duration_since(**at)<=Duration::from_secs(15)).count(),"lastReason":self.last_reason})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn burst_requests_a_probe_with_a_cooldown_and_bounded_history() {
        let mut s = TrafficErrors::default();
        let now = Instant::now();
        assert!(!s.record(Failure::Reset, now, "test".into()));
        assert!(!s.record(Failure::WebSocket, now, "test".into()));
        assert!(s.record(Failure::Timeout, now, "test".into()));
        for _ in 0..100 {
            assert!(!s.record(Failure::Reset, now, "x".repeat(1000)));
        }
        assert_eq!(s.recent.len(), 32);
        assert_eq!(s.snapshot(now)["lastReason"].as_str().unwrap().len(), 512);
        assert_eq!(
            s.snapshot(now + Duration::from_secs(16))["recentUpstreamFailures"],
            0
        );
        for _ in 0..2 {
            assert!(!s.record(Failure::Reset, now + Duration::from_secs(31), "test".into()));
        }
        assert!(s.record(Failure::Reset, now + Duration::from_secs(31), "test".into()));
    }
    #[test]
    fn secondary_errors_are_not_counted_as_new_upstream_failures() {
        let mut s = TrafficErrors::default();
        let now = Instant::now();
        for _ in 0..20 {
            assert!(!s.record(Failure::UdpClosed, now, "test".into()));
            assert!(!s.record(Failure::ClientClosed, now, "test".into()));
        }
        assert_eq!(s.snapshot(now)["recentUpstreamFailures"], 0);
        assert_eq!(
            Failure::classify(
                "connection ends > websocket: close 1006 (abnormal closure): unexpected EOF"
            ),
            Some(Failure::WebSocket)
        );
        assert_eq!(Failure::classify("websocket: creating connection"), None);
    }
}
