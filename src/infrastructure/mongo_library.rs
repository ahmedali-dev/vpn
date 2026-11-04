//! MongoDB adapter for an explicitly selected, encrypted cross-device library.
//! Names and connection secrets are encrypted; only scope, random record IDs and timestamps are public.
use crate::features::profiles::{Profile, prepare_for_save};
use crate::infrastructure::cryptography::{decrypt, derive, encrypt, random};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use mongodb::{
    Client, Collection,
    bson::{Document, doc},
    options::{ClientOptions, ServerAddress, Tls},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub uri: String,
    pub database: String,
    pub collection: String,
    pub library: String,
    pub passphrase: String,
    #[serde(default)]
    pub remember: bool,
}
impl Drop for Settings {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.uri.zeroize();
        self.passphrase.zeroize();
    }
}
pub struct MongoLibrary {
    collection: Collection<Document>,
    pub scope: String,
    key: Zeroizing<[u8; 32]>,
}
fn valid_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn scope(s: &Settings) -> Result<String> {
    ensure!(
        valid_name(&s.database) && valid_name(&s.collection) && valid_name(&s.library),
        "Database, collection and library must be 1–64 letters, digits, hyphens or underscores"
    );
    ensure!(
        (12..=1024).contains(&s.passphrase.len()),
        "Library passphrase must be 12–1024 bytes"
    );
    ensure!(
        s.uri.len() <= 4096
            && (s.uri.starts_with("mongodb://") || s.uri.starts_with("mongodb+srv://")),
        "Enter a MongoDB connection URI"
    );
    Ok(hex::encode(Sha256::digest(format!(
        "TunnelNest library v1\0{}\0{}\0{}",
        s.database, s.collection, s.library
    ))))
}
fn tls_policy(o: &ClientOptions) -> Result<()> {
    let local = !o.hosts.is_empty()
        && o.hosts.iter().all(|h| match h {
            ServerAddress::Tcp { host, .. } => {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }
            _ => false,
        });
    if let Some(Tls::Enabled(t)) = &o.tls {
        ensure!(
            t.allow_invalid_certificates != Some(true),
            "MongoDB TLS verification must stay enabled"
        );
    } else {
        ensure!(
            local,
            "Remote MongoDB requires TLS: add tls=true to the URI"
        );
    }
    Ok(())
}
fn remote_error(_: mongodb::error::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "MongoDB operation failed. Check connectivity, database permissions and connection settings."
    )
}
impl MongoLibrary {
    pub async fn connect(s: &Settings) -> Result<Arc<Self>> {
        let scope = scope(s)?;
        let mut options = ClientOptions::parse(&s.uri).await.map_err(remote_error)?;
        tls_policy(&options)?;
        options.connect_timeout = Some(Duration::from_secs(5));
        options.server_selection_timeout = Some(Duration::from_secs(5));
        options.max_pool_size = Some(4);
        options.app_name = Some("TunnelNest".into());
        let client = Client::with_options(options).map_err(remote_error)?;
        let password = Zeroizing::new(s.passphrase.clone());
        let salt = hex::decode(&scope)?;
        let key = tokio::task::spawn_blocking(move || derive(&password, &salt[..16])).await??;
        let library = Arc::new(Self {
            collection: client.database(&s.database).collection(&s.collection),
            scope,
            key,
        });
        let id = format!("k:{}", library.scope);
        let payload = library.seal(&id, b"TunnelNest shared library v1")?;
        library.collection.update_one(doc!{"_id":&id},doc!{"$setOnInsert":{"scope":&library.scope,"kind":"key","version":1,"payload":payload}}).upsert(true).await.map_err(remote_error)?;
        let verifier = library
            .collection
            .find_one(doc! {"_id":&id})
            .await
            .map_err(remote_error)?
            .context("Library verifier missing")?;
        ensure!(
            library
                .open(&id, &verifier)
                .is_ok_and(|raw| raw.as_slice() == b"TunnelNest shared library v1"),
            "Wrong library passphrase, or damaged library verifier"
        );
        Ok(library)
    }
    fn seal(&self, id: &str, raw: &[u8]) -> Result<String> {
        ensure!(raw.len() <= 65536, "Shared profile too large");
        Ok(STANDARD_NO_PAD.encode(encrypt(
            self.key.as_ref(),
            raw,
            format!("{}:{id}", self.scope).as_bytes(),
        )?))
    }
    fn open(&self, id: &str, d: &Document) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            d.get_i32("version") == Ok(1) && d.get_str("scope") == Ok(self.scope.as_str()),
            "Unsupported library record"
        );
        let payload = d.get_str("payload").context("Missing encrypted profile")?;
        ensure!(payload.len() <= 90000, "Shared profile too large");
        let raw = STANDARD_NO_PAD
            .decode(payload)
            .context("Invalid encrypted profile")?;
        decrypt(
            self.key.as_ref(),
            &raw,
            format!("{}:{id}", self.scope).as_bytes(),
        )
        .map(Zeroizing::new)
        .map_err(|_| {
            anyhow::anyhow!("Cannot decrypt library record. Check the library passphrase.")
        })
    }
    pub fn new_id() -> String {
        hex::encode(random::<16>())
    }
    fn record_id(id: &str) -> Result<String> {
        ensure!(
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid shared profile ID"
        );
        Ok(format!("p:{id}"))
    }
    pub async fn save(&self, id: &str, mut profile: Profile) -> Result<()> {
        ensure!(
            !profile.session_only,
            "Enable Remember credentials before saving to the shared library"
        );
        profile = prepare_for_save(profile)?;
        profile.id = 0;
        profile.locked = false;
        profile.needs_credentials = false;
        let id = Self::record_id(id)?;
        let raw = Zeroizing::new(serde_json::to_vec(&profile)?);
        let payload = self.seal(&id, &raw)?;
        self.collection.update_one(doc!{"_id":&id,"scope":&self.scope},doc!{"$set":{"scope":&self.scope,"kind":"profile","version":1,"payload":payload,"updatedAt":chrono::Utc::now().to_rfc3339()}}).upsert(true).await.map_err(remote_error)?;
        Ok(())
    }
    pub async fn list(&self, after: &str) -> Result<Vec<serde_json::Value>> {
        ensure!(
            after.is_empty() || Self::record_id(after).is_ok(),
            "Invalid library cursor"
        );
        let mut filter = doc! {"scope":&self.scope,"kind":"profile"};
        if !after.is_empty() {
            filter.insert("_id", doc! {"$gt":format!("p:{after}")});
        }
        let mut cursor = self
            .collection
            .find(filter)
            .sort(doc! {"_id":1})
            .limit(25)
            .await
            .map_err(remote_error)?;
        let mut out = Vec::new();
        while cursor.advance().await.map_err(remote_error)? {
            let d = cursor.deserialize_current().map_err(remote_error)?;
            let id = d.get_str("_id").context("Invalid library record")?;
            let raw = self.open(id, &d)?;
            let p: Profile = serde_json::from_slice(&raw).context("Invalid shared profile")?;
            out.push(serde_json::json!({"id":id.trim_start_matches("p:"),"name":p.name,"mode":p.mode,"updatedAt":d.get_str("updatedAt").unwrap_or("")}));
        }
        Ok(out)
    }
    pub async fn get(&self, id: &str) -> Result<Profile> {
        let id = Self::record_id(id)?;
        let d = self
            .collection
            .find_one(doc! {"_id":&id,"scope":&self.scope,"kind":"profile"})
            .await
            .map_err(remote_error)?
            .context("Shared profile not found")?;
        let raw = self.open(&id, &d)?;
        let mut p =
            prepare_for_save(serde_json::from_slice(&raw).context("Invalid shared profile")?)?;
        p.id = 0;
        p.session_only = false;
        p.locked = false;
        p.needs_credentials = false;
        Ok(p)
    }
    pub async fn delete(&self, id: &str) -> Result<()> {
        let id = Self::record_id(id)?;
        self.collection
            .delete_one(doc! {"_id":id,"scope":&self.scope,"kind":"profile"})
            .await
            .map_err(remote_error)?;
        Ok(())
    }
}
/// Remember only on explicit request; no plaintext settings file fallback.
pub fn remember(s: &Settings) -> Result<()> {
    let value=Zeroizing::new(serde_json::json!({"uri":s.uri,"database":s.database,"collection":s.collection,"library":s.library,"passphrase":s.passphrase,"remember":false}).to_string());
    keyring::Entry::new("TunnelNestMongo", "shared-library")?
        .set_password(&value)
        .map_err(|_| {
            anyhow::anyhow!("Connected for this session; OS keychain could not save settings")
        })
}
pub fn remembered() -> Result<Settings> {
    let value = Zeroizing::new(
        keyring::Entry::new("TunnelNestMongo", "shared-library")?
            .get_password()
            .map_err(|_| {
                anyhow::anyhow!("No saved library settings available in the OS keychain")
            })?,
    );
    Ok(serde_json::from_str(&value)?)
}
pub fn forget() -> Result<()> {
    let e = keyring::Entry::new("TunnelNestMongo", "shared-library")?;
    match e.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => anyhow::bail!("Cannot remove saved settings from OS keychain"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings {
        Settings {
            uri: "mongodb://localhost".into(),
            database: "test".into(),
            collection: "profiles".into(),
            library: "personal".into(),
            passphrase: "a sufficiently long passphrase".into(),
            remember: false,
        }
    }
    #[test]
    fn validates_scope() {
        let mut s = settings();
        let a = scope(&s).unwrap();
        s.library = "other".into();
        assert_ne!(a, scope(&s).unwrap());
        s.library = "$where".into();
        assert!(scope(&s).is_err());
    }
    #[tokio::test]
    async fn encryption_bound_to_scope_and_record() {
        let m = MongoLibrary {
            collection: Client::with_options(ClientOptions::default())
                .unwrap()
                .database("test")
                .collection("test"),
            scope: "scope".into(),
            key: Zeroizing::new([7; 32]),
        };
        let payload = m.seal("p:one", b"secret credentials").unwrap();
        assert!(!payload.contains("secret"));
        let d = doc! {"version":1,"scope":"scope","payload":payload};
        assert_eq!(
            m.open("p:one", &d).unwrap().as_slice(),
            b"secret credentials"
        );
        assert!(m.open("p:two", &d).is_err());
    }
    #[tokio::test]
    async fn tls_required_remotely() {
        let o = ClientOptions::parse("mongodb://example.com").await.unwrap();
        assert!(tls_policy(&o).is_err());
        let o = ClientOptions::parse("mongodb://127.0.0.1").await.unwrap();
        assert!(tls_policy(&o).is_ok());
        let o = ClientOptions::parse(
            "mongodb://example.com/?tls=true&tlsAllowInvalidCertificates=true",
        )
        .await
        .unwrap();
        assert!(tls_policy(&o).is_err());
    }
}
