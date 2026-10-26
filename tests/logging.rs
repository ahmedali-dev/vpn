#[cfg(unix)]
use std::io::Write;
use tunnelnest::{
    config::Config,
    logging::{self, MAX_FILE_BYTES, MAX_FILES, SessionFile},
    runtime::Reporter,
};
fn config() -> Config {
    Config::parse(
        &[
            "-H",
            "example.com",
            "-P",
            "443",
            "-u",
            "alice",
            "-p",
            "synthetic-password",
            "-proxy",
            "http://bob:proxy-secret@proxy.example:8080",
        ]
        .map(str::to_owned),
    )
    .unwrap()
}
#[test]
fn saved_logs_survive_reporter_and_redact_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let report = Reporter::persistent_in(dir.path(), &config());
    report.event(
        "ERROR",
        "SSH",
        "Authentication failed for synthetic-password; proxy-secret; vmess://secret-share",
    );
    report.event("INFO","CORE","Authorization: Basic aGFyZGNvZGVk\n{\"password\":\"short\"}\nhttp://user:unknown-secret@host.example/?token=foo\nhttp://127.0.0.1:1234/#0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let snapshot = report.snapshot();
    let live = snapshot["logs"].as_str().unwrap();
    assert!(live.contains("[ERROR] [SSH]"));
    for secret in [
        "synthetic-password",
        "proxy-secret",
        "vmess://secret-share",
        "aGFyZGNvZGVk",
        "unknown-secret",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        assert!(!live.contains(secret), "leaked {secret}");
    }
    let name = snapshot["logFile"].as_str().unwrap().to_owned();
    drop(report);
    let saved = logging::read(dir.path(), &name).unwrap();
    assert_eq!(saved, live);
    assert!(saved.lines().all(|line| line.starts_with("20")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
#[test]
fn rotation_retention_and_read_limits_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let mut log = SessionFile::create(dir.path()).unwrap();
    let line = "a".repeat(20000);
    for _ in 0..110 {
        log.append(&line).unwrap();
    }
    drop(log);
    let files = logging::list(dir.path()).unwrap();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|f| f.size <= MAX_FILE_BYTES));
    for _ in 0..MAX_FILES + 2 {
        let mut f = SessionFile::create(dir.path()).unwrap();
        f.append("event\n").unwrap();
    }
    assert_eq!(logging::list(dir.path()).unwrap().len(), MAX_FILES);
    for name in [
        "../Cargo.toml",
        "/etc/passwd",
        "tunnelnest-../secret.log",
        "other.log",
    ] {
        assert!(logging::read(dir.path(), name).is_err());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = dir.path().join("secret");
        std::fs::File::create(&target)
            .unwrap()
            .write_all(b"private")
            .unwrap();
        symlink(&target, dir.path().join("tunnelnest-symlink.log")).unwrap();
        assert!(logging::read(dir.path(), "tunnelnest-symlink.log").is_err());
        assert!(
            !logging::list(dir.path())
                .unwrap()
                .iter()
                .any(|f| f.name == "tunnelnest-symlink.log")
        );
    }
}
#[test]
fn file_errors_keep_live_logs_working_and_visible() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-directory");
    std::fs::write(&file, "test").unwrap();
    let report = Reporter::persistent_in(&file, &config());
    report.log("still available");
    assert!(
        report.snapshot()["logError"]
            .as_str()
            .unwrap()
            .contains("Could not save logs")
    );
    assert!(
        report.snapshot()["logs"]
            .as_str()
            .unwrap()
            .contains("still available")
    );
}
