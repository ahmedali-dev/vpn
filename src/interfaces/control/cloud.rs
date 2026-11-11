//! App cloud commands. No database lock spans network work; refresh preserves dirty local profiles.
use super::{
    Control,
    http::{Id, read},
};
use crate::infrastructure::cloud::{Cloud, Connect, default_url, to_profile};
use anyhow::{Context, Result};
use axum::extract::Request;
use serde_json::{Value, json};
use std::sync::Arc;
pub(super) async fn handle(c: Arc<Control>, path: &str, req: Request) -> Result<Value> {
    let mut session = c
        .cloud
        .try_lock()
        .context("A cloud operation is already running")?;
    match path {
        "/api/cloud/connect" => {
            let input = read::<Connect>(req).await?;
            let cloud = Cloud::connect(input).await?;
            let result = json!({"connected":true,"url":cloud.url()});
            *session = Some(cloud);
            Ok(result)
        }
        "/api/cloud/status" => Ok(if let Some(s) = session.as_ref() {
            json!({"connected":true,"url":s.url()})
        } else {
            json!({"connected":false,"url":default_url()})
        }),
        "/api/cloud/logout" => {
            *session = None;
            Ok(json!({"connected":false,"url":default_url()}))
        }
        "/api/cloud/upload" => {
            let id = read::<Id>(req).await?.id;
            let s = session.as_ref().context("Configure the cloud URL first")?;
            let (p, remote) = {
                let store = c.store.lock().unwrap();
                let store = store.as_ref().context("Profiles unavailable")?;
                (store.get(id)?, store.cloud_remote(&s.scope, id)?)
            };
            s.upload(&remote, &p).await?;
            c.store
                .lock()
                .unwrap()
                .as_ref()
                .context("Profiles unavailable")?
                .cloud_bind(&s.scope, &remote, &p)?;
            Ok(json!({"ok":true}))
        }
        "/api/cloud/delete" => {
            let id = read::<Id>(req).await?.id;
            let s = session.as_ref().context("Configure the cloud URL first")?;
            let remote = c
                .store
                .lock()
                .unwrap()
                .as_ref()
                .context("Profiles unavailable")?
                .cloud_lookup(&s.scope, id)?
                .context("This profile has no cloud copy; refresh the public library first")?;
            s.delete(&remote).await?;
            Ok(json!({"ok":true}))
        }
        "/api/cloud/refresh" => {
            let s = session.as_ref().context("Configure the cloud URL first")?;
            // Refuse a locked vault before downloading any credentials.
            {
                let store = c.store.lock().unwrap();
                let store = store.as_ref().context("Profiles unavailable")?;
                anyhow::ensure!(
                    !store.status()["locked"].as_bool().unwrap_or(true),
                    "Unlock the local profile vault before refreshing cloud"
                );
            }
            let servers = tokio::time::timeout(std::time::Duration::from_secs(45), s.download())
                .await
                .context("Cloud refresh timed out; local profiles are unchanged")??;
            let mut valid = vec![];
            let mut invalid = 0;
            for server in servers {
                let id = server.id.clone();
                match to_profile(server) {
                    Ok(p) => valid.push((id, p)),
                    Err(_) => invalid += 1,
                }
            }
            let mut store = c.store.lock().unwrap();
            let store = store.as_mut().context("Profiles unavailable")?;
            let mut synced = 0;
            let mut conflicts = 0;
            for (id, p) in valid {
                if store.cloud_receive(&s.scope, &id, p)? {
                    synced += 1
                } else {
                    conflicts += 1
                }
            }
            Ok(json!({"synced":synced,"conflicts":conflicts,"invalid":invalid}))
        }
        _ => anyhow::bail!("Unknown cloud endpoint"),
    }
}
