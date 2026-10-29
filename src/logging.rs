//! Bounded, private connection logs shared by the CLI and local control interface.
use crate::config::{Config, unescape};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_FILES: usize = 20;
#[derive(Default)]
pub struct Redactor {
    secrets: Vec<String>,
}
impl Redactor {
    pub fn for_config(c: &Config) -> Self {
        let mut secrets = vec![];
        for key in ["u", "p", "v2ray-uuid", "v2ray-link"] {
            if let Some(v) = c.flags.get(key) {
                secrets.push(v.clone());
            }
        }
        if let Ok(p) = c.protocol() {
            secrets.push(p.uuid);
        }
        if let Ok(proxy) = url::Url::parse(c.get("proxy", "")) {
            let user = unescape(proxy.username()).unwrap_or_default();
            let pass = unescape(proxy.password().unwrap_or("")).unwrap_or_default();
            secrets.extend([
                proxy.username().to_owned(),
                proxy.password().unwrap_or("").to_owned(),
                pass.clone(),
            ]);
            if !user.is_empty() {
                secrets.push(STANDARD.encode(format!("{user}:{pass}")));
            }
        }
        secrets.retain(|s| !s.is_empty());
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        Self { secrets }
    }
    pub fn clean(&self, text: &str) -> String {
        let text = text
            .lines()
            .map(|line| {
                let lower = line.to_ascii_lowercase();
                if [
                    "authorization:",
                    "\"password\"",
                    "password=",
                    "password:",
                    "\"uuid\"",
                    "token=",
                    "token:",
                    "\"token\"",
                    "\"secret\"",
                    "\"private_key\"",
                    "control_url",
                    "sharepassword",
                ]
                .iter()
                .any(|key| lower.contains(key))
                {
                    "[credential field redacted]"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut text = text;
        for secret in &self.secrets {
            if secret.len() >= 4 {
                text = text.replace(secret, "[redacted]");
            }
        }
        let mut result = String::new();
        for token in text.split_inclusive(char::is_whitespace) {
            let word = token.trim_end_matches(char::is_whitespace);
            let spacing = &token[word.len()..];
            let lower = word.to_ascii_lowercase();
            let unquoted = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            if self
                .secrets
                .iter()
                .any(|s| s == word.trim_matches(|c: char| !c.is_alphanumeric()))
                || [
                    "vmess://",
                    "vless://",
                    "trojan://",
                    "ss://",
                    "tn1.",
                    "tn2.",
                    "tn2p.",
                ]
                .iter()
                .any(|p| lower.contains(p))
                || unquoted.len() == 64 && unquoted.bytes().all(|b| b.is_ascii_hexdigit())
            {
                result.push_str("[redacted]");
            } else if let Ok(mut url) = url::Url::parse(word) {
                if !url.username().is_empty() || url.password().is_some() {
                    let _ = url.set_username("");
                    let _ = url.set_password(None);
                }
                if matches!(
                    url.host_str(),
                    Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
                ) {
                    url.set_fragment(None);
                }
                url.set_query(None);
                result.push_str(url.as_str());
            } else {
                result.push_str(word);
            }
            result.push_str(spacing);
        }
        // Strip terminal escapes/control characters so core output cannot forge a timestamp.
        result
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .collect()
    }
}

pub fn default_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("no user configuration directory")?
        .join("TunnelNestRust/logs"))
}
fn valid_name(name: &str) -> bool {
    name.starts_with("tunnelnest-")
        && name.ends_with(".log")
        && name.len() < 120
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub name: String,
    pub size: u64,
    pub modified_at: String,
}
pub fn list(dir: &Path) -> Result<Vec<LogEntry>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    ensure!(
        !fs::symlink_metadata(dir)?.file_type().is_symlink(),
        "log directory must not be a symlink"
    );
    let mut files = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let metadata = fs::symlink_metadata(entry.path())?;
        if valid_name(&name) && metadata.is_file() && !metadata.file_type().is_symlink() {
            let modified: chrono::DateTime<chrono::Utc> = metadata.modified()?.into();
            files.push(LogEntry {
                name,
                size: metadata.len(),
                modified_at: modified.to_rfc3339(),
            });
        }
    }
    files.sort_by(|a, b| {
        b.modified_at
            .cmp(&a.modified_at)
            .then_with(|| b.name.cmp(&a.name))
    });
    Ok(files)
}
pub fn read(dir: &Path, name: &str) -> Result<String> {
    ensure!(valid_name(name), "invalid log filename");
    ensure!(
        !fs::symlink_metadata(dir)?.file_type().is_symlink(),
        "log directory must not be a symlink"
    );
    let path = dir.join(name);
    ensure!(
        fs::symlink_metadata(&path)?.is_file(),
        "log file is unavailable"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    ensure!(
        !fs::symlink_metadata(&path)?.file_type().is_symlink(),
        "log file must not be a symlink"
    );
    let file = options.open(path)?;
    let mut data = vec![];
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= MAX_FILE_BYTES, "log file is too large");
    Ok(String::from_utf8_lossy(&data).into_owned())
}
pub struct SessionFile {
    dir: PathBuf,
    stem: String,
    part: u32,
    pub path: PathBuf,
    file: File,
    bytes: u64,
}
impl SessionFile {
    pub fn create(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        ensure!(
            !fs::symlink_metadata(dir)?.file_type().is_symlink(),
            "log directory must not be a symlink"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let stem = format!(
            "tunnelnest-{}-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ"),
            hex::encode(crate::store::random::<4>())
        );
        let path = dir.join(format!("{stem}-000.log"));
        let file = Self::open(&path)?;
        let s = Self {
            dir: dir.into(),
            stem,
            part: 0,
            path,
            file,
            bytes: 0,
        };
        s.prune()?;
        Ok(s)
    }
    fn open(path: &Path) -> Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        Ok(options.open(path)?)
    }
    fn prune(&self) -> Result<()> {
        for entry in list(&self.dir)?.into_iter().skip(MAX_FILES) {
            let path = self.dir.join(entry.name);
            if path != self.path {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
    pub fn append(&mut self, record: &str) -> Result<()> {
        ensure!(record.len() <= 32768, "log record too large");
        if self.bytes + record.len() as u64 > MAX_FILE_BYTES {
            self.file.flush()?;
            self.part += 1;
            self.path = self.dir.join(format!("{}-{:03}.log", self.stem, self.part));
            self.file = Self::open(&self.path)?;
            self.bytes = 0;
            self.prune()?;
        }
        self.file.write_all(record.as_bytes())?;
        self.file.flush()?;
        self.bytes += record.len() as u64;
        Ok(())
    }
}
