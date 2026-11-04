//! Notification feature.
//!
//! Owns user preferences, deduplicated state transitions and private desktop notifications.

//! Private notification preferences and a deduplicated connection-state policy.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Preferences {
    pub enabled: bool,
    pub connection_updates: bool,
    pub problems: bool,
    pub background_only: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            enabled: false,
            connection_updates: true,
            problems: true,
            background_only: false,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Event {
    Connected,
    Restored,
    Reconnecting,
    Unstable,
    Failed,
    Disconnected,
    Disconnecting,
    Stopped,
    ServiceUnavailable,
}
impl Event {
    pub fn content(self) -> (&'static str, &'static str) {
        match self {
            Self::Connected => (
                "TunnelNest connected",
                "The tunnel passed its connectivity checks.",
            ),
            Self::Restored => (
                "TunnelNest reconnected",
                "The connection recovered and passed its connectivity checks.",
            ),
            Self::Reconnecting => (
                "TunnelNest is reconnecting",
                "Connection interrupted. Automatic recovery is in progress.",
            ),
            Self::Unstable => (
                "TunnelNest connection needs attention",
                "Connectivity checks are failing. Open the app for details.",
            ),
            Self::Failed => (
                "TunnelNest connection failed",
                "The connection stopped. Open the app to review diagnostics.",
            ),
            Self::Disconnecting => (
                "TunnelNest is disconnecting",
                "Closing the tunnel connection.",
            ),
            Self::Stopped => (
                "TunnelNest disconnected",
                "The tunnel has been disconnected.",
            ),
            Self::Disconnected => (
                "TunnelNest disconnected",
                "The connection ended unexpectedly. Open the app for details.",
            ),
            Self::ServiceUnavailable => (
                "TunnelNest service unavailable",
                "Could not contact the local connection service. Open the app for details.",
            ),
        }
    }
    pub fn allowed(self, prefs: Preferences, focused: bool) -> bool {
        prefs.enabled
            && !(prefs.background_only && focused)
            && match self {
                Self::Connected | Self::Restored | Self::Disconnecting | Self::Stopped => {
                    prefs.connection_updates
                }
                _ => prefs.problems,
            }
    }
}
#[derive(Default)]
pub struct Tracker {
    previous: Option<String>,
    session: String,
    connected: bool,
    attempt: u64,
    outage: bool,
    terminal: bool,
    stopping: bool,
    failures: u8,
    unavailable: bool,
    last_sent: HashMap<Event, Instant>,
}
impl Tracker {
    fn limited(&mut self, event: Option<Event>, now: Instant) -> Option<Event> {
        let event = event?;
        let cooldown = if matches!(
            event,
            Event::Connected | Event::Restored | Event::Disconnecting | Event::Stopped
        ) {
            5
        } else {
            30
        };
        if self
            .last_sent
            .get(&event)
            .is_some_and(|at| now.saturating_duration_since(*at) < Duration::from_secs(cooldown))
        {
            return None;
        }
        self.last_sent.insert(event, now);
        Some(event)
    }
    pub fn unavailable(&mut self, now: Instant) -> Option<Event> {
        self.failures = self.failures.saturating_add(1);
        if self.failures < 3 || self.unavailable {
            return None;
        }
        self.unavailable = true;
        self.limited(Some(Event::ServiceUnavailable), now)
    }
    pub fn observe(
        &mut self,
        status: &Value,
        intentional_stop: bool,
        now: Instant,
    ) -> Option<Event> {
        self.failures = 0;
        self.unavailable = false;
        let state = status["state"].as_str()?;
        let state = if state == "connected" && status["health"]["state"] == "degraded" {
            "degraded"
        } else {
            state
        };
        let session = status["logSession"].as_str().unwrap_or("");
        let attempt = status["recovery"]["attempt"]
            .as_u64()
            .unwrap_or(self.attempt);
        if self.previous.is_none() {
            self.previous = Some(state.into());
            self.session = session.into();
            self.connected = state == "connected";
            self.attempt = attempt;
            self.outage = matches!(state, "degraded" | "reconnecting");
            self.terminal = state == "error";
            return None; // Do not replay old status on app startup.
        }
        let new_session = !session.is_empty() && session != self.session;
        let recovered_between_polls = !new_session && self.connected && attempt > self.attempt;
        if new_session {
            self.session = session.into();
            self.connected = false;
            self.outage = false;
            self.terminal = false;
            self.stopping = false;
        }
        if state == "connected" && !intentional_stop {
            self.stopping = false;
        }
        if intentional_stop || state == "stopping" {
            self.stopping = true;
        }
        let event = match state {
            "connected"
                if self.previous.as_deref() != Some("connected")
                    || new_session
                    || recovered_between_polls =>
            {
                let event = if self.connected {
                    Event::Restored
                } else {
                    Event::Connected
                };
                self.connected = true;
                self.outage = false;
                self.terminal = false;
                self.stopping = false;
                Some(event)
            }
            "reconnecting" if !self.outage && !self.stopping => {
                self.outage = true;
                Some(Event::Reconnecting)
            }
            "degraded" if self.connected && !self.outage && !self.stopping => {
                self.outage = true;
                Some(Event::Unstable)
            }
            "error" if !self.terminal => {
                self.terminal = true;
                Some(Event::Failed)
            }
            "disconnected" => {
                let requested = self.stopping || intentional_stop;
                let had_activity = requested
                    || self.connected
                    || matches!(
                        self.previous.as_deref(),
                        Some("connecting" | "verifying" | "reconnecting" | "degraded" | "stopping")
                    );
                self.connected = false;
                self.outage = false;
                self.stopping = false;
                if had_activity {
                    Some(if requested {
                        Event::Stopped
                    } else {
                        Event::Disconnected
                    })
                } else {
                    None
                }
            }
            _ => None,
        };
        self.previous = Some(state.into());
        self.attempt = attempt;
        self.limited(event, now)
    }
}

pub struct Center {
    path: PathBuf,
    prefs: Mutex<Preferences>,
    issue: Mutex<Option<String>>,
    pub intentional_stop: AtomicBool,
}
impl Center {
    pub fn open(path: PathBuf) -> Self {
        let read = (|| -> Result<Preferences> {
            let file = fs::File::open(&path)?;
            let mut bytes = Vec::new();
            file.take(8193).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 8192, "notification preferences too large");
            Ok(serde_json::from_slice(&bytes)?)
        })();
        let (prefs, issue)=match read {
            Ok(prefs)=>(prefs,None),
            Err(_) if !path.exists()=>(Preferences::default(),None),
            Err(_)=>(Preferences::default(),Some("Notification settings could not be read. Save them again to enable notifications.".into())),
        };
        Self {
            path,
            prefs: Mutex::new(prefs),
            issue: Mutex::new(issue),
            intentional_stop: AtomicBool::new(false),
        }
    }
    pub fn preferences(&self) -> Preferences {
        *self.prefs.lock().unwrap()
    }
    pub fn snapshot(&self) -> Value {
        json!({"preferences":self.preferences(),"issue":self.issue.lock().unwrap().clone()})
    }
    pub fn save(&self, preferences: Preferences) -> Result<()> {
        let mut current = self.prefs.lock().unwrap();
        let parent = self
            .path
            .parent()
            .context("notification settings directory unavailable")?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&serde_json::to_vec_pretty(&preferences)?)?;
        file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|e| e.error)?;
        *current = preferences;
        *self.issue.lock().unwrap() = None;
        Ok(())
    }
    pub fn delivery_failed(&self) {
        *self.issue.lock().unwrap()=Some("The desktop notification service could not accept the notification. Check system notification settings and the Linux notification daemon.".into());
    }
    pub fn stopping(&self) -> bool {
        !self.intentional_stop.swap(true, Ordering::SeqCst)
    }
}

#[cfg(feature = "desktop")]
pub async fn send(app: &tauri::AppHandle, title: &str, body: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = app;
        crate::macos_notifications::send(title, body).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        use tauri_plugin_notification::NotificationExt;
        let notification = app.notification().builder().title(title).body(body);
        #[cfg(target_os = "linux")]
        let notification = notification.icon("tunnelnest");
        notification.show()?;
        Ok(())
    }
}

#[cfg(feature = "desktop")]
pub async fn notify_event(app: &tauri::AppHandle, center: &Center, event: Event) {
    use tauri::Manager;
    let focused = app
        .get_webview_window("main")
        .and_then(|w| w.is_focused().ok())
        .unwrap_or(false);
    if event.allowed(center.preferences(), focused) {
        let (title, body) = event.content();
        if let Err(error) = send(app, title, body).await {
            center.delivery_failed();
            eprintln!("Native notification failed: {error}");
        }
    }
}

#[cfg(feature = "desktop")]
pub async fn watch(
    app: tauri::AppHandle,
    url: url::Url,
    center: std::sync::Arc<Center>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut tracker = Tracker::default();
    let mut tick = tokio::time::interval(Duration::from_millis(1500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { _=cancel.cancelled()=>break, _=tick.tick()=>() }
        let status = tokio::select! { _=cancel.cancelled()=>break, status=crate::control::helper_request(&url,"status",None)=>status };
        if cancel.is_cancelled() {
            break;
        }
        let event = match status {
            Ok(status) => {
                let stopping = center.intentional_stop.load(Ordering::SeqCst);
                let event = tracker.observe(&status, stopping, Instant::now());
                if matches!(status["state"].as_str(), Some("disconnected" | "error")) {
                    center.intentional_stop.store(false, Ordering::SeqCst);
                }
                event
            }
            Err(_) => tracker.unavailable(Instant::now()),
        };
        if let Some(event) = event {
            tokio::select! {_=cancel.cancelled()=>break, _=notify_event(&app,&center,event)=>()}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn status(session: &str, state: &str) -> Value {
        json!({"logSession":session,"state":state})
    }
    #[test]
    fn retries_are_deduplicated_and_recovery_is_announced() {
        let mut t = Tracker::default();
        let now = Instant::now();
        assert_eq!(t.observe(&status("", "disconnected"), false, now), None);
        assert_eq!(t.observe(&status("one", "connecting"), false, now), None);
        assert_eq!(
            t.observe(&status("one", "connected"), false, now),
            Some(Event::Connected)
        );
        assert_eq!(
            t.observe(&status("one", "reconnecting"), false, now),
            Some(Event::Reconnecting)
        );
        for _ in 0..6 {
            t.observe(&status("one", "connecting"), false, now);
            assert_eq!(t.observe(&status("one", "reconnecting"), false, now), None);
        }
        assert_eq!(
            t.observe(&status("one", "connected"), false, now),
            Some(Event::Restored)
        );
        assert_eq!(t.observe(&status("one", "connected"), false, now), None);
    }
    #[test]
    fn startup_is_silent_and_requested_disconnect_is_announced() {
        let mut t = Tracker::default();
        let now = Instant::now();
        assert_eq!(t.observe(&status("one", "connected"), false, now), None);
        assert_eq!(
            t.observe(&status("one", "disconnected"), true, now),
            Some(Event::Stopped)
        );
        t.observe(&status("two", "connected"), false, now);
        t.observe(&status("two", "stopping"), false, now);
        assert_eq!(
            t.observe(
                &status("two", "disconnected"),
                false,
                now + Duration::from_secs(6)
            ),
            Some(Event::Stopped)
        );
    }
    #[test]
    fn unexpected_disconnect_terminal_failure_and_service_outage_are_bounded() {
        let mut t = Tracker::default();
        let now = Instant::now();
        t.observe(&status("one", "connected"), false, now);
        assert_eq!(
            t.observe(&status("one", "disconnected"), false, now),
            Some(Event::Disconnected)
        );
        assert_eq!(
            t.observe(&status("two", "error"), false, now),
            Some(Event::Failed)
        );
        assert_eq!(t.observe(&status("two", "error"), false, now), None);
        assert_eq!(t.observe(&status("three", "error"), false, now), None);
        assert_eq!(t.unavailable(now), None);
        assert_eq!(t.unavailable(now), None);
        assert_eq!(t.unavailable(now), Some(Event::ServiceUnavailable));
        assert_eq!(t.unavailable(now), None);
    }
    #[test]
    fn disabled_categories_and_focus_are_respected() {
        assert!(!Event::Connected.allowed(Preferences::default(), false));
        let p = Preferences {
            enabled: true,
            background_only: true,
            ..Default::default()
        };
        assert!(!Event::Connected.allowed(p, true));
        assert!(Event::Connected.allowed(p, false));
        assert!(!Event::Failed.allowed(
            Preferences {
                problems: false,
                ..p
            },
            false
        ));
        assert!(!Event::Restored.allowed(
            Preferences {
                connection_updates: false,
                ..p
            },
            false
        ));
    }
    #[test]
    fn preferences_persist_and_corrupt_settings_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notification-settings.json");
        let center = Center::open(path.clone());
        assert!(!center.preferences().enabled);
        let p = Preferences {
            enabled: true,
            ..Default::default()
        };
        center.save(p).unwrap();
        assert_eq!(Center::open(path.clone()).preferences(), p);
        fs::write(&path, b"not JSON").unwrap();
        let center = Center::open(path);
        assert!(!center.preferences().enabled);
        assert!(center.snapshot()["issue"].is_string());
    }
    #[test]
    fn raw_connection_errors_never_enter_notification_content() {
        let mut tracker = Tracker::default();
        let now = Instant::now();
        tracker.observe(&status("one", "connected"), false, now);
        let event=tracker.observe(&json!({"logSession":"one","state":"error","error":"private-user private-password https://private-server.invalid/?token=secret","connection":{"server":"private-server.invalid"}}),false,now).unwrap();
        let (title, body) = event.content();
        assert_eq!(event, Event::Failed);
        for private in [
            "private-user",
            "private-password",
            "private-server",
            "secret",
        ] {
            assert!(!format!("{title} {body}").contains(private));
        }
    }
    #[test]
    fn degraded_health_recovers_without_repeated_alerts() {
        let mut tracker = Tracker::default();
        let now = Instant::now();
        tracker.observe(&status("one", "connected"), false, now);
        let degraded =
            json!({"logSession":"one","state":"connected","health":{"state":"degraded"}});
        assert_eq!(
            tracker.observe(&degraded, false, now),
            Some(Event::Unstable)
        );
        assert_eq!(
            tracker.observe(&degraded, false, now + Duration::from_secs(31)),
            None
        );
        assert_eq!(
            tracker.observe(
                &status("one", "connected"),
                false,
                now + Duration::from_secs(32)
            ),
            Some(Event::Restored)
        );
    }
    #[test]
    fn failed_settings_save_does_not_enable_notifications() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("file");
        fs::write(&parent, b"file").unwrap();
        let center = Center::open(parent.join("settings.json"));
        assert!(
            center
                .save(Preferences {
                    enabled: true,
                    ..Default::default()
                })
                .is_err()
        );
        assert!(!center.preferences().enabled);
    }
    #[test]
    fn brief_reconnection_is_detected_even_when_retry_states_are_not_polled() {
        let mut t = Tracker::default();
        let now = Instant::now();
        t.observe(
            &json!({"logSession":"one","state":"connected","recovery":{"attempt":1}}),
            false,
            now,
        );
        assert_eq!(
            t.observe(
                &json!({"logSession":"one","state":"connected","recovery":{"attempt":2}}),
                false,
                now
            ),
            Some(Event::Restored)
        );
        assert_eq!(
            t.observe(
                &json!({"logSession":"one","state":"connected","recovery":{"attempt":2}}),
                false,
                now
            ),
            None
        );
    }
    #[test]
    fn stopping_a_pending_connection_is_reported_once_in_connection_updates() {
        let mut t = Tracker::default();
        let now = Instant::now();
        t.observe(&status("one", "connecting"), false, now);
        t.observe(&status("one", "stopping"), true, now);
        assert_eq!(
            t.observe(&status("one", "disconnected"), true, now),
            Some(Event::Stopped)
        );
        assert_eq!(t.observe(&status("one", "disconnected"), false, now), None);
        let preferences = Preferences {
            enabled: true,
            connection_updates: false,
            problems: true,
            background_only: false,
        };
        assert!(!Event::Stopped.allowed(preferences, false));
        assert!(!Event::Disconnecting.allowed(preferences, false));
        assert!(Event::Disconnected.allowed(preferences, false));
    }
    #[test]
    fn fast_manual_disconnect_is_reported_even_if_connecting_was_not_polled() {
        let mut tracker = Tracker::default();
        let now = Instant::now();
        tracker.observe(&status("", "disconnected"), false, now);
        assert_eq!(
            tracker.observe(&status("one", "disconnected"), true, now),
            Some(Event::Stopped)
        );
        assert_eq!(
            tracker.observe(&status("one", "disconnected"), false, now),
            None
        );
    }
}
