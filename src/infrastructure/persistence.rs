//! Encrypted SQLite profile repository.
//!
//! Owns database IO, OS-keychain/password vault access and session-only credentials. Profile validation is delegated to the feature service.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub struct Store {
    db: Connection,
    key: Option<Zeroizing<Vec<u8>>>,
    mode: String,
    session: HashMap<i64, Vec<String>>,
    account: String,
}
impl Store {
    pub fn default_path() -> Result<PathBuf> {
        Ok(dirs::config_dir()
            .context("no user config directory")?
            .join("TunnelNestRust/profiles.sqlite3"))
    }
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_internal(path, true)
    }
    pub fn open_password(path: &Path) -> Result<Self> {
        Self::open_internal(path, false)
    }
    fn open_internal(path: &Path, use_keyring: bool) -> Result<Self> {
        let parent = path.parent().context("no profile parent directory")?;
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let db = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        db.execute_batch("PRAGMA secure_delete=ON; CREATE TABLE IF NOT EXISTS cloud_links(scope TEXT NOT NULL,remote_id TEXT NOT NULL,profile_id INTEGER NOT NULL,fingerprint TEXT NOT NULL,PRIMARY KEY(scope,remote_id)); CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,mode TEXT NOT NULL,args TEXT NOT NULL,updated_at TEXT NOT NULL,session_only INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS vault_metadata(id INTEGER PRIMARY KEY CHECK(id=1),mode TEXT NOT NULL,salt TEXT NOT NULL,check_value TEXT NOT NULL);")?;
        let mode = db
            .query_row("SELECT mode FROM vault_metadata WHERE id=1", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .unwrap_or_default();
        use sha2::{Digest, Sha256};
        let account = hex::encode(Sha256::digest(path.to_string_lossy().as_bytes()));
        let mut s = Self {
            db,
            key: None,
            mode,
            session: HashMap::new(),
            account,
        };
        if use_keyring
            && s.mode != "password"
            && let Ok(entry) = keyring::Entry::new("TunnelNestRust", &s.account)
        {
            match entry.get_password() {
                Ok(encoded) => {
                    if let Ok(key) = STANDARD_NO_PAD.decode(encoded)
                        && key.len() == 32
                        && (s.mode.is_empty() || s.check_key(&key).is_ok())
                    {
                        if s.mode.is_empty() {
                            s.metadata("keychain", "", &key)?;
                        }
                        s.key = Some(Zeroizing::new(key));
                    }
                }
                Err(keyring::Error::NoEntry) if s.mode.is_empty() => {
                    let key = random::<32>();
                    if entry.set_password(&STANDARD_NO_PAD.encode(key)).is_ok() {
                        s.metadata("keychain", "", &key)?;
                        s.key = Some(Zeroizing::new(key.to_vec()));
                    }
                }
                _ => (),
            }
        }
        Ok(s)
    }
    fn metadata(&mut self, mode: &str, salt: &str, key: &[u8]) -> Result<()> {
        self.db.execute(
            "INSERT INTO vault_metadata(id,mode,salt,check_value) VALUES(1,?,?,?)",
            params![mode, salt, seal(key, b"TunnelNest vault v1")?],
        )?;
        self.mode = mode.into();
        Ok(())
    }
    fn check_key(&self, key: &[u8]) -> Result<()> {
        let check: String = self.db.query_row(
            "SELECT check_value FROM vault_metadata WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            open(key, &check)? == b"TunnelNest vault v1",
            "incorrect vault password"
        );
        Ok(())
    }
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if self.key.is_some() {
            return Ok(());
        }
        if self.mode == "keychain" {
            let encoded = keyring::Entry::new("TunnelNestRust", &self.account)?.get_password()?;
            let key = STANDARD_NO_PAD.decode(encoded)?;
            self.check_key(&key)?;
            self.key = Some(Zeroizing::new(key));
            return Ok(());
        }
        ensure!(
            (12..=1024).contains(&password.len()),
            "vault password must contain 12–1024 bytes"
        );
        let salt = if self.mode.is_empty() {
            random::<16>().to_vec()
        } else {
            let s: String =
                self.db
                    .query_row("SELECT salt FROM vault_metadata WHERE id=1", [], |r| {
                        r.get(0)
                    })?;
            STANDARD_NO_PAD.decode(s)?
        };
        let key = derive(password, &salt)?;
        if self.mode.is_empty() {
            self.metadata("password", &STANDARD_NO_PAD.encode(&salt), key.as_slice())?;
        } else {
            self.check_key(key.as_slice())?;
        }
        self.key = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }
    pub fn status(&self) -> Value {
        json!({"locked":self.key.is_none(),"mode":if self.mode.is_empty(){"locked"}else{&self.mode},"initialized":!self.mode.is_empty()})
    }
    fn key(&self) -> Result<&[u8]> {
        self.key
            .as_deref()
            .map(|x| x.as_slice())
            .context("profile vault is locked; unlock before saving or using credentials")
    }
    pub fn list(&self) -> Result<Vec<Profile>> {
        let mut stmt=self.db.prepare("SELECT id,name,mode,args,updated_at,session_only FROM profiles ORDER BY name COLLATE NOCASE")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                Profile {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    mode: r.get(2)?,
                    updated_at: r.get(4)?,
                    session_only: r.get(5)?,
                    schema_version: 1,
                    ..Default::default()
                },
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = vec![];
        for row in rows {
            let (mut p, raw) = row?;
            if let Some(key) = &self.key {
                p.args = serde_json::from_slice(&open(key, &raw)?)?;
                if p.session_only {
                    if let Some(args) = self.session.get(&p.id) {
                        p.args = args.clone();
                    } else {
                        p.needs_credentials = true;
                    }
                }
            } else {
                p.locked = true;
            }
            out.push(p);
        }
        Ok(out)
    }
    pub fn get(&self, id: i64) -> Result<Profile> {
        let p = self
            .list()?
            .into_iter()
            .find(|p| p.id == id)
            .context("profile not found")?;
        ensure!(
            !p.locked && !p.needs_credentials,
            "profile credentials unavailable"
        );
        Ok(p)
    }
    pub fn save(&mut self, p: Profile) -> Result<Profile> {
        let mut p = crate::features::profiles::prepare_for_save(p)?;
        let args = if p.session_only {
            credentials_removed(&p.args)
        } else {
            p.args.clone()
        };
        let raw = seal(self.key()?, &serde_json::to_vec(&args)?)?;
        p.updated_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        p.schema_version = 1;
        p.locked = false;
        p.needs_credentials = false;
        if p.id > 0 {
            ensure!(self.db.execute("UPDATE profiles SET name=?,mode=?,args=?,updated_at=?,session_only=? WHERE id=?",params![p.name,p.mode,raw,p.updated_at,p.session_only,p.id])?==1,"profile not found");
        } else {
            self.db.execute(
                "INSERT INTO profiles(name,mode,args,updated_at,session_only) VALUES(?,?,?,?,?)",
                params![p.name, p.mode, raw, p.updated_at, p.session_only],
            )?;
            p.id = self.db.last_insert_rowid();
        }
        if p.session_only {
            self.session.insert(p.id, p.args.clone());
        } else {
            self.session.remove(&p.id);
        }
        Ok(p)
    }
    pub fn import(&mut self, mut p: Profile) -> Result<Profile> {
        let base = p.name.clone();
        let existing = self.list()?;
        p.id = 0;
        for n in 1..=1000 {
            p.name = if n == 1 {
                base.clone()
            } else {
                format!("{} ({n})", base.chars().take(85).collect::<String>())
            };
            if !existing.iter().any(|v| v.name == p.name) {
                return self.save(p);
            }
        }
        anyhow::bail!("too many duplicate profile names")
    }
    /// Stable cloud identities and content fingerprints prevent duplicate uploads and lost local edits.
    fn fingerprint(&self, p: &Profile) -> Result<String> {
        use sha2::{Digest, Sha256};
        // Include the vault key so the sync marker cannot become a password-guessing oracle.
        let mut hash = Sha256::new();
        hash.update(b"TunnelNest cloud sync v1");
        hash.update(self.key()?);
        hash.update(serde_json::to_vec(&(&p.name, &p.mode, &p.args))?);
        Ok(hex::encode(hash.finalize()))
    }
    pub fn cloud_lookup(&self, scope: &str, id: i64) -> Result<Option<String>> {
        Ok(self
            .db
            .query_row(
                "SELECT remote_id FROM cloud_links WHERE scope=? AND profile_id=?",
                params![scope, id],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn cloud_remote(&self, scope: &str, id: i64) -> Result<String> {
        if let Some(remote) = self
            .db
            .query_row(
                "SELECT remote_id FROM cloud_links WHERE scope=? AND profile_id=?",
                params![scope, id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok(remote);
        }
        let remote = hex::encode(random::<12>());
        self.db.execute(
            "INSERT INTO cloud_links VALUES(?,?,?,?)",
            params![scope, remote, id, ""],
        )?;
        Ok(remote)
    }
    pub fn cloud_bind(&self, scope: &str, remote: &str, p: &Profile) -> Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO cloud_links VALUES(?,?,?,?)",
            params![scope, remote, p.id, self.fingerprint(p)?],
        )?;
        Ok(())
    }
    pub fn cloud_receive(&mut self, scope: &str, remote: &str, mut p: Profile) -> Result<bool> {
        let link = self
            .db
            .query_row(
                "SELECT profile_id,fingerprint FROM cloud_links WHERE scope=? AND remote_id=?",
                params![scope, remote],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        let saved = if let Some((id, fingerprint)) = link
            && let Ok(existing) = self.get(id)
        {
            if self.fingerprint(&existing)? != fingerprint {
                return Ok(false);
            }
            p.id = id;
            self.save(p)?
        } else {
            self.import(p)?
        };
        self.cloud_bind(scope, remote, &saved)?;
        Ok(true)
    }
    pub fn delete(&mut self, id: i64) -> Result<()> {
        ensure!(
            id > 0 && self.db.execute("DELETE FROM profiles WHERE id=?", [id])? == 1,
            "profile not found"
        );
        self.db
            .execute("DELETE FROM cloud_links WHERE profile_id=?", [id])?;
        self.session.remove(&id);
        Ok(())
    }
}

pub use super::cryptography::{decrypt, derive, encrypt, random};
use super::cryptography::{open, seal};
pub use crate::features::profiles::{Profile, credentials_removed};
