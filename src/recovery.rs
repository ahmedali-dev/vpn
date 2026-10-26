//! Connection recovery policy shared by SSH and external-core sessions.
use std::{fmt, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermanentFailure {
    Authentication,
    Identity,
    Configuration,
}
impl fmt::Display for PermanentFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} failure requires user action", self)
    }
}
impl std::error::Error for PermanentFailure {}
pub fn permanent(error: &anyhow::Error) -> bool {
    error.is::<PermanentFailure>()
        || error.chain().any(|e| {
            e.is::<PermanentFailure>()
                || e.downcast_ref::<std::io::Error>().is_some_and(|e| {
                    matches!(
                        e.kind(),
                        std::io::ErrorKind::PermissionDenied
                            | std::io::ErrorKind::AddrInUse
                            | std::io::ErrorKind::InvalidInput
                            | std::io::ErrorKind::NotFound
                    )
                })
        })
}

#[derive(Default)]
pub struct RetryPolicy {
    failures: u32,
}
impl RetryPolicy {
    /// Six consecutive failures; a minute of connected service restores the budget.
    /// Jitter is supplied by the caller to make policy tests deterministic.
    pub fn failed(&mut self, connected: Duration, jitter: f64) -> Option<Duration> {
        if connected >= Duration::from_secs(60) {
            self.failures = 0;
        }
        self.failures += 1;
        if self.failures >= 6 {
            return None;
        }
        let base = (2u64 << (self.failures - 1)).min(30) as f64;
        Some(Duration::from_secs_f64(
            (base * (0.8 + jitter.clamp(0.0, 1.0) * 0.4)).min(30.0),
        ))
    }
    pub fn failures(&self) -> u32 {
        self.failures
    }
}

#[derive(Default)]
pub struct HealthGate {
    failures: u32,
}
impl HealthGate {
    pub fn failed(&mut self) -> bool {
        self.failures += 1;
        self.failures >= 3
    }
    pub fn recovered(&mut self) {
        self.failures = 0;
    }
    pub fn failures(&self) -> u32 {
        self.failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_budget_backoff_and_cap() {
        let mut p = RetryPolicy::default();
        let delays: Vec<_> = (0..6)
            .map(|_| p.failed(Duration::ZERO, 0.5).map(|d| d.as_secs()))
            .collect();
        assert_eq!(
            delays,
            vec![Some(2), Some(4), Some(8), Some(16), Some(30), None]
        );
    }
    #[test]
    fn stable_service_restores_budget() {
        let mut p = RetryPolicy::default();
        for _ in 0..5 {
            assert!(p.failed(Duration::ZERO, 0.5).is_some());
        }
        assert_eq!(
            p.failed(Duration::from_secs(60), 0.5),
            Some(Duration::from_secs(2))
        );
        assert_eq!(p.failures(), 1);
    }
    #[test]
    fn short_connection_does_not_reset_budget_and_jitter_is_bounded() {
        let mut p = RetryPolicy::default();
        assert_eq!(
            p.failed(Duration::from_secs(59), 0.0),
            Some(Duration::from_millis(1600))
        );
        assert_eq!(
            p.failed(Duration::from_secs(59), 1.0),
            Some(Duration::from_millis(4800))
        );
        assert_eq!(p.failures(), 2);
    }
    #[test]
    fn health_requires_three_consecutive_failures() {
        let mut h = HealthGate::default();
        assert!(!h.failed());
        assert!(!h.failed());
        h.recovered();
        assert!(!h.failed());
        assert!(!h.failed());
        assert!(h.failed());
    }
    #[test]
    fn permanent_markers_survive_context() {
        let e = anyhow::anyhow!("credentials rejected")
            .context(PermanentFailure::Authentication)
            .context("SSH startup");
        assert!(permanent(&e));
        assert!(!permanent(&anyhow::anyhow!("temporary network loss")));
        assert!(permanent(
            &std::io::Error::from(std::io::ErrorKind::AddrInUse).into()
        ));
    }
}
