//! Manual release checks. Never downloads or executes an update.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const RELEASE_API: &str = "https://api.github.com/repos/ahmedali-dev/vpn/releases/latest";
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    draft: bool,
    prerelease: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Update {
    pub current_version: String,
    pub latest_version: String,
    pub tag: String,
    pub update_available: bool,
    pub state: String,
    pub notes: String,
}
fn version(tag: &str) -> Result<[u64; 3]> {
    ensure!(tag.len() < 64, "Invalid release version");
    let raw = tag
        .strip_prefix("rust-v")
        .or_else(|| tag.strip_prefix('v'))
        .unwrap_or(tag);
    let parts: Vec<_> = raw.split('.').collect();
    ensure!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit())),
        "Invalid release version"
    );
    Ok([parts[0].parse()?, parts[1].parse()?, parts[2].parse()?])
}
pub fn release_url(tag: &str) -> Result<String> {
    version(tag)?;
    ensure!(
        tag.starts_with("rust-v") || tag.starts_with('v'),
        "Invalid release tag"
    );
    Ok(format!(
        "https://github.com/ahmedali-dev/vpn/releases/tag/{tag}"
    ))
}
fn compare(current: &str, r: Release) -> Result<Update> {
    ensure!(!r.draft && !r.prerelease, "No stable release available");
    let a = version(current)?;
    let b = version(&r.tag_name)?;
    release_url(&r.tag_name)?;
    Ok(Update {
        current_version: current.into(),
        latest_version: format!("{}.{}.{}", b[0], b[1], b[2]),
        tag: r.tag_name,
        update_available: b > a,
        state: if b > a {
            "available"
        } else if b < a {
            "ahead"
        } else {
            "current"
        }
        .into(),
        notes: r.body.unwrap_or_default().chars().take(16000).collect(),
    })
}
pub async fn check() -> Result<Update> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("TunnelNest/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut response = client
        .get(RELEASE_API)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| {
            anyhow::anyhow!("Cannot reach GitHub. Check your connection and try again.")
        })?;
    ensure!(
        response.status().is_success(),
        "GitHub release check failed (HTTP {}). Try again later.",
        response.status().as_u16()
    );
    let mut raw = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("Cannot read GitHub release")?
    {
        ensure!(
            raw.len() + chunk.len() <= 256 * 1024,
            "Release response too large"
        );
        raw.extend_from_slice(&chunk);
    }
    compare(
        env!("CARGO_PKG_VERSION"),
        serde_json::from_slice(&raw).context("Invalid GitHub release response")?,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn r(tag: &str) -> Release {
        Release {
            tag_name: tag.into(),
            body: None,
            draft: false,
            prerelease: false,
        }
    }
    #[test]
    fn numeric_versions() {
        assert!(
            compare("1.3.8", r("rust-v1.10.0"))
                .unwrap()
                .update_available
        );
        assert_eq!(compare("1.3.8", r("v1.3.7")).unwrap().state, "ahead");
        assert_eq!(compare("1.3.8", r("v1.3.8")).unwrap().state, "current");
    }
    #[test]
    fn refuses_nonrelease_urls() {
        for t in [
            "../../evil",
            "v1.2.3?x=1",
            "https://evil.test",
            "v1.2.3-beta",
        ] {
            assert!(release_url(t).is_err());
        }
    }
}
