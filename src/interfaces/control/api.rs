//! Application API use cases
//!
//! Handles profiles, vault operations, sharing, diagnostics, logs and connection commands.

use super::Control;
use super::diagnostics::diagnostics;
use super::http::Args;
use super::http::Attach;
use super::http::Id;
use super::http::Import;
use super::http::Link;
use super::http::LogFile;
use super::http::Password;
use super::http::Share;
use super::http::read;
use crate::config::Config;
use crate::config::Protocol;
use crate::logging;
use crate::sharing;
use crate::store::Profile;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use axum::extract::Request;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub(super) async fn api(c: Arc<Control>, path: &str, req: Request) -> Result<Value> {
    if path.starts_with("/api/cloud/") {
        return super::cloud::handle(c, path, req).await;
    }
    match path {
        "/api/updates/check" => {
            return Ok(serde_json::to_value(
                crate::features::updates::check().await?,
            )?);
        }
        "/api/updates/open" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Tag {
                tag: String,
            }
            let url = crate::features::updates::release_url(&read::<Tag>(req).await?.tag)?;
            tokio::task::spawn_blocking(move || webbrowser::open(&url)).await??;
        }
        "/api/status" => return c.status().await,
        "/api/logs" => {
            return Ok(
                json!({"directory":c.log_dir()?.to_string_lossy(),"files":logging::list(&c.log_dir()?)?,"maxFiles":logging::MAX_FILES,"maxFileBytes":logging::MAX_FILE_BYTES}),
            );
        }
        "/api/logs/read" => {
            let p = read::<LogFile>(req).await?;
            return Ok(json!({"name":p.name,"text":logging::read(&c.log_dir()?,&p.name)?}));
        }
        "/api/start" => c.start(read::<Args>(req).await?.args).await?,
        "/api/stop" => c.stop().await?,
        "/api/quit" => {
            c.stop().await?;
            c.cancel.cancel();
        }
        "/api/lease" => {
            ensure!(c.helper_only, "lease only applies to helper");
            c.last_lease
                .store(c.epoch.elapsed().as_secs(), Ordering::Relaxed);
        }
        "/api/helper/attach" => c.attach(&read::<Attach>(req).await?.url).await?,
        "/api/import" => {
            return Ok(serde_json::to_value(Protocol::parse(
                &read::<Link>(req).await?.link,
            )?)?);
        }
        "/api/profiles/diagnose" => {
            let request = read::<Id>(req).await?;
            let _guard = c
                .diagnosing
                .try_lock()
                .context("A profile diagnostic is already running")?;
            let profile = c
                .store
                .lock()
                .unwrap()
                .as_ref()
                .context("profiles unavailable")?
                .list()?
                .into_iter()
                .find(|p| p.id == request.id)
                .context("profile not found")?;
            ensure!(
                !profile.locked,
                "Unlock the profile vault before running diagnostics"
            );
            let config = Config::parse(&profile.args).map_err(|_| {
                anyhow::anyhow!(
                    "Invalid profile options; edit and save the profile before diagnosing"
                )
            })?;
            let session = c.status().await?;
            let mut report = crate::diagnostics::run(&config).await;
            report["currentSession"] = json!({
                "scope":"Existing connection snapshot taken before preflight; may belong to a different profile. No new authentication or routing test was performed.",
                "state":session["state"],"checks":session["checks"],
                "sshAuthenticated":session["connection"]["sshAuthenticated"],
                "tlsTrust":session["connection"]["tlsTrust"],
                "sshTrust":session["connection"]["sshTrust"]
            });
            return Ok(report);
        }
        "/api/diagnostics" => {
            let s = c.status().await?;
            return Ok(diagnostics(&s));
        }
        "/api/vault/status" => {
            return Ok(c
                .store
                .lock()
                .unwrap()
                .as_ref()
                .context("profiles unavailable")?
                .status());
        }
        "/api/vault/unlock" => {
            let p = read::<Password>(req).await?;
            c.store
                .lock()
                .unwrap()
                .as_mut()
                .context("profiles unavailable")?
                .unlock(&p.password)?;
        }
        "/api/profiles" => {
            return Ok(serde_json::to_value(
                c.store
                    .lock()
                    .unwrap()
                    .as_ref()
                    .context("profiles unavailable")?
                    .list()?,
            )?);
        }
        "/api/profiles/save" => {
            let p = read::<Profile>(req).await?;
            return Ok(serde_json::to_value(
                c.store
                    .lock()
                    .unwrap()
                    .as_mut()
                    .context("profiles unavailable")?
                    .save(p)?,
            )?);
        }
        "/api/profiles/delete" => {
            let p = read::<Id>(req).await?;
            c.store
                .lock()
                .unwrap()
                .as_mut()
                .context("profiles unavailable")?
                .delete(p.id)?;
        }
        "/api/profiles/share" => {
            let p = read::<Share>(req).await?;
            let profile = c
                .store
                .lock()
                .unwrap()
                .as_ref()
                .context("profiles unavailable")?
                .get(p.id)?;
            return Ok(json!({"code":sharing::encode(profile,&p.password)?}));
        }
        "/api/profiles/import-shared" => {
            let p = read::<Import>(req).await?;
            let profile = sharing::decode(&p.code, &p.password)?;
            return Ok(serde_json::to_value(
                c.store
                    .lock()
                    .unwrap()
                    .as_mut()
                    .context("profiles unavailable")?
                    .import(profile)?,
            )?);
        }
        _ => anyhow::bail!("unknown control endpoint"),
    }
    Ok(json!({"ok":true}))
}
