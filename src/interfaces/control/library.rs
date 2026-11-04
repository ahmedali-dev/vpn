//! Authenticated shared-library use cases. Local storage locks never span network awaits.
use super::{
    Control,
    http::{Id, read},
};
use crate::infrastructure::mongo_library::{self, MongoLibrary, Settings};
use anyhow::{Context, Result};
use axum::extract::Request;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Remote {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    #[serde(default)]
    after: String,
}
/// Await a driver task without cancelling its internal protocol state on timeout.
/// A timed-out write may finish; stable record IDs make an explicit retry idempotent.
async fn network<T: Send + 'static>(
    future: impl std::future::Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    let task = tokio::spawn(future);
    tokio::time::timeout(std::time::Duration::from_secs(20),task).await
       .context("MongoDB timed out. A pending write may still finish; refresh or retry the same profile.")??
}
pub(super) async fn handle(c: Arc<Control>, path: &str, req: Request) -> Result<Value> {
    match path {
        "/api/mongo/connect" | "/api/mongo/load" => {
            let s = if path.ends_with("load") {
                tokio::task::spawn_blocking(mongo_library::remembered).await??
            } else {
                read::<Settings>(req).await?
            };
            let (library, s) = network(async move {
                let library = MongoLibrary::connect(&s).await?;
                Ok((library, s))
            })
            .await?;
            let scope = library.scope.clone();
            *c.mongo.lock().await = Some(library);
            let warning = if s.remember {
                tokio::task::spawn_blocking(move || mongo_library::remember(&s))
                    .await?
                    .err()
                    .map(|e| e.to_string())
            } else {
                None
            };
            Ok(json!({"connected":true,"scope":scope,"warning":warning}))
        }
        "/api/mongo/disconnect" => {
            *c.mongo.lock().await = None;
            Ok(json!({"connected":false}))
        }
        "/api/mongo/forget" => {
            tokio::task::spawn_blocking(mongo_library::forget).await??;
            Ok(json!({"ok":true}))
        }
        _ => {
            let library = c
                .mongo
                .lock()
                .await
                .clone()
                .context("Connect to a MongoDB library first")?;
            match path {
                "/api/mongo/list" => {
                    let p = read::<Page>(req).await?;
                    Ok(
                        json!({"profiles":network(async move {library.list(&p.after).await}).await?}),
                    )
                }
                "/api/mongo/save" => {
                    let id = read::<Id>(req).await?.id;
                    let (p, remote) = {
                        let guard = c.store.lock().unwrap();
                        let store = guard.as_ref().context("profiles unavailable")?;
                        (store.get(id)?, store.cloud_id(id, &library.scope)?)
                    };
                    network(async move { library.save(&remote, p).await }).await?;
                    Ok(json!({"ok":true}))
                }
                "/api/mongo/import" => {
                    let id = read::<Remote>(req).await?.id;
                    let remote = id.clone();
                    let lib = library.clone();
                    let p = network(async move { lib.get(&remote).await }).await?;
                    let mut guard = c.store.lock().unwrap();
                    let store = guard.as_mut().context("profiles unavailable")?;
                    let p = store.import(p)?;
                    store.link_cloud(p.id, &library.scope, &id)?;
                    Ok(serde_json::to_value(p)?)
                }
                "/api/mongo/delete" => {
                    let id = read::<Remote>(req).await?.id;
                    network(async move { library.delete(&id).await }).await?;
                    Ok(json!({"ok":true}))
                }
                _ => anyhow::bail!("Unknown library endpoint"),
            }
        }
    }
}
