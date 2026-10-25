use crate::{
    config::{Config, Protocol},
    logging,
    runtime::{Reporter, Session, is_admin},
    sharing,
    store::{Profile, Store, random},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Mutex as AsyncMutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

struct Helper {
    url: url::Url,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    mirror: Reporter,
    last: Arc<Mutex<String>>,
}
impl Drop for Helper {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
pub struct Control {
    host: String,
    token: String,
    helper_only: bool,
    cancel: CancellationToken,
    session: AsyncMutex<Option<Session>>,
    store: Mutex<Option<Store>>,
    helper: AsyncMutex<Option<Helper>>,
    last_lease: AtomicU64,
    epoch: Instant,
    log_dir: Mutex<Option<PathBuf>>,
}
impl Control {
    pub fn new(
        host: String,
        token: String,
        helper_only: bool,
        store: Option<Store>,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            host,
            token,
            helper_only,
            cancel,
            session: AsyncMutex::new(None),
            store: Mutex::new(store),
            helper: AsyncMutex::new(None),
            last_lease: AtomicU64::new(0),
            epoch: Instant::now(),
            log_dir: Mutex::new(logging::default_dir().ok()),
        })
    }
    pub fn set_log_dir(&self, dir: PathBuf) {
        *self.log_dir.lock().unwrap() = Some(dir);
    }
    fn log_dir(&self) -> Result<PathBuf> {
        self.log_dir
            .lock()
            .unwrap()
            .clone()
            .context("log directory unavailable")
    }
    async fn helper_url(&self) -> Option<url::Url> {
        self.helper.lock().await.as_ref().map(|h| h.url.clone())
    }
    async fn stop(&self) -> Result<()> {
        if let Some(url) = self.helper_url().await {
            helper_request(&url, "stop", Some(json!({}))).await?;
            let _ = self.status().await;
        }
        let mut session = self.session.lock().await;
        if let Some(s) = session.as_mut() {
            s.stop().await;
        }
        Ok(())
    }
    async fn status(&self) -> Result<Value> {
        if let Some(url) = self.helper_url().await {
            let mut v = helper_request(&url, "status", None).await?;
            if let Some(h) = self.helper.lock().await.as_ref() {
                mirror_logs(&h.mirror, &h.last, &v);
                let local = h.mirror.snapshot();
                v["logFile"] = local["logFile"].clone();
                v["logError"] = local["logError"].clone();
            }
            v["administrator"] = json!(is_admin());
            v["helperAvailable"] = json!(true);
            return Ok(v);
        }
        let session = self.session.lock().await;
        Ok(session
            .as_ref()
            .map(|s| s.report.snapshot())
            .unwrap_or_else(|| Reporter::default().snapshot()))
    }
    async fn start(&self, args: Vec<String>) -> Result<()> {
        let c = Config::parse(&args)?;
        ensure!(!c.boolean("ui"), "nested control servers are forbidden");
        ensure!(
            !self.helper_only || c.tun(),
            "privileged helper only accepts full-device connections"
        );
        if c.tun() && !is_admin() {
            let url = self
                .helper_url()
                .await
                .context("authorize the administrator helper for full-device routing")?;
            helper_request(&url, "start", Some(json!({"args":args}))).await?;
            return Ok(());
        }
        let mut session = self.session.lock().await;
        ensure!(
            !session.as_ref().is_some_and(Session::active),
            "disconnect the active connection first"
        );
        if let Some(helper) = self.helper.lock().await.take() {
            close_helper(helper).await;
        }
        let report = Reporter::persistent_in(&self.log_dir()?, &c);
        *session = Some(Session::start_with_report(c, report));
        Ok(())
    }
    async fn attach(&self, raw: &str) -> Result<()> {
        ensure!(!self.helper_only, "helpers cannot attach another helper");
        let url = valid_helper(raw)?;
        ensure!(
            url.authority() != self.host,
            "cannot attach the control server to itself"
        );
        let status = helper_request(&url, "status", None).await?;
        ensure!(status["administrator"] == true, "helper is not elevated");
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        let u = url.clone();
        helper_request(&url, "lease", Some(json!({}))).await?;
        let mirror = Reporter::persistent_in(&self.log_dir()?, &Config::default());
        mirror.event(
            "INFO",
            "HELPER",
            "Administrator helper attached; mirroring connection logs to this user's log directory",
        );
        let last = Arc::new(Mutex::new(String::new()));
        let report = mirror.clone();
        let previous_logs = last.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {_=c.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(3))=>{
                    if helper_request(&u,"lease",Some(json!({}))).await.is_err(){report.event("ERROR","HELPER","Helper lease renewal failed");break;}
                    match helper_request(&u,"status",None).await{Ok(status)=>mirror_logs(&report,&previous_logs,&status),Err(_)=>report.event("WARN","HELPER","Could not retrieve helper status")}
                }}
            }
        });
        let previous = self.helper.lock().await.replace(Helper {
            url,
            cancel,
            task,
            mirror,
            last,
        });
        if let Some(old) = previous {
            close_helper(old).await;
        }
        Ok(())
    }
}
async fn close_helper(helper: Helper) {
    let _ = helper_request(&helper.url, "stop", Some(json!({}))).await;
    if let Ok(status) = helper_request(&helper.url, "status", None).await {
        mirror_logs(&helper.mirror, &helper.last, &status);
    }
    let _ = helper_request(&helper.url, "quit", Some(json!({}))).await;
}
fn mirror_logs(report: &Reporter, last: &Mutex<String>, status: &Value) {
    let current = status["logs"].as_str().unwrap_or("");
    let mut previous = last.lock().unwrap();
    if current == previous.as_str() {
        return;
    }
    let extra = current.strip_prefix(previous.as_str()).unwrap_or(current);
    report.event("INFO", "HELPER", extra);
    *previous = current.to_owned();
}
pub fn valid_helper(raw: &str) -> Result<url::Url> {
    let u = url::Url::parse(raw.trim())?;
    ensure!(
        u.scheme() == "http"
            && u.host_str() == Some("127.0.0.1")
            && u.port().is_some()
            && u.path() == "/"
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment()
                .is_some_and(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())),
        "invalid helper URL"
    );
    Ok(u)
}
pub(crate) async fn helper_request(
    url: &url::Url,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let target = url.join(&format!("api/{path}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(25))
        .build()?;
    let req = if let Some(body) = body {
        client.post(target).json(&body)
    } else {
        client.get(target)
    };
    let response = req
        .header("X-Tunnel-Token", url.fragment().unwrap_or(""))
        .send()
        .await?;
    let success = response.status().is_success();
    let data: Value = response.json().await?;
    ensure!(
        success,
        "helper: {}",
        data["error"].as_str().unwrap_or("request failed")
    );
    Ok(data)
}
fn json_response(status: StatusCode, v: Value) -> Response {
    (status, Json(v)).into_response()
}
async fn read<T: DeserializeOwned>(req: Request) -> Result<T> {
    let raw = to_bytes(req.into_body(), 128 * 1024).await?;
    Ok(serde_json::from_slice(&raw)?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    args: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    link: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Password {
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    id: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Share {
    id: i64,
    #[serde(default)]
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    code: String,
    #[serde(default)]
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogFile {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attach {
    url: String,
}

pub fn router(control: Arc<Control>) -> Router {
    Router::new().fallback(handle).with_state(control)
}
async fn handle(State(c): State<Arc<Control>>, req: Request) -> Response {
    let mut response = dispatch(c, req).await;
    let h = response.headers_mut();
    for (key, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    ] {
        h.insert(
            header::HeaderName::from_static(key),
            header::HeaderValue::from_static(value),
        );
    }
    response
}
async fn dispatch(c: Arc<Control>, req: Request) -> Response {
    let error = |s, status| json_response(status, json!({"error":s}));
    if req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        != Some(c.host.as_str())
    {
        return error("invalid host", StatusCode::FORBIDDEN);
    }
    if let Some(origin) = req.headers().get(header::ORIGIN)
        && origin.as_bytes() != format!("http://{}", c.host).as_bytes()
    {
        return error("invalid origin", StatusCode::FORBIDDEN);
    }
    let path = req.uri().path().to_owned();
    if !path.starts_with("/api/") {
        if c.helper_only {
            return StatusCode::NOT_FOUND.into_response();
        }
        if req.method() != Method::GET {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        return asset(&path);
    }
    let token = req
        .headers()
        .get("x-tunnel-token")
        .map(|v| v.as_bytes())
        .unwrap_or(&[]);
    if !bool::from(token.ct_eq(c.token.as_bytes())) {
        return error("unauthorized", StatusCode::UNAUTHORIZED);
    }
    if c.helper_only
        && ![
            "/api/start",
            "/api/stop",
            "/api/status",
            "/api/quit",
            "/api/lease",
            "/api/diagnostics",
        ]
        .contains(&path.as_str())
    {
        return error("helper endpoint is restricted", StatusCode::FORBIDDEN);
    }
    let get = [
        "/api/status",
        "/api/profiles",
        "/api/vault/status",
        "/api/diagnostics",
        "/api/logs",
    ]
    .contains(&path.as_str());
    if req.method() != if get { Method::GET } else { Method::POST } {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    match api(c, &path, req).await {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({"error":e.to_string()})),
    }
}
async fn api(c: Arc<Control>, path: &str, req: Request) -> Result<Value> {
    match path {
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
        "/api/diagnostics" => {
            let s = c.status().await?;
            return Ok(
                json!({"engine":"rust","version":env!("CARGO_PKG_VERSION"),"platform":std::env::consts::OS,"arch":std::env::consts::ARCH,"state":s["state"],"administrator":is_admin()}),
            );
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
fn asset(path: &str) -> Response {
    let (bytes, mime): (&'static [u8], &str) = match path {
        "/" => (
            include_bytes!("../desktop/ui/index.html"),
            "text/html; charset=utf-8",
        ),
        "/app.js" => (
            include_bytes!("../desktop/ui/app.js"),
            "text/javascript; charset=utf-8",
        ),
        "/dropdowns.js" => (
            include_bytes!("../desktop/ui/dropdowns.js"),
            "text/javascript; charset=utf-8",
        ),
        "/profile-options.js" => (
            include_bytes!("../desktop/ui/profile-options.js"),
            "text/javascript; charset=utf-8",
        ),
        "/share-qr.js" => (
            include_bytes!("../desktop/ui/share-qr.js"),
            "text/javascript; charset=utf-8",
        ),
        "/qr-reader.js" => (
            include_bytes!("../desktop/ui/qr-reader.js"),
            "text/javascript; charset=utf-8",
        ),
        "/qrcode.js" => (
            include_bytes!("../desktop/ui/qrcode.js"),
            "text/javascript; charset=utf-8",
        ),
        "/style.css" => (
            include_bytes!("../desktop/ui/style.css"),
            "text/css; charset=utf-8",
        ),
        "/tunnelnest-mark.png" => (
            include_bytes!("../desktop/ui/tunnelnest-mark.png"),
            "image/png",
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .body(Body::from(bytes))
        .unwrap()
}
struct ReadyFile(Option<PathBuf>);
impl Drop for ReadyFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}
pub async fn serve(config: Config, cancel: CancellationToken) -> Result<()> {
    serve_with_ready(config, cancel, None).await
}
pub async fn serve_with_ready(
    config: Config,
    cancel: CancellationToken,
    notify: Option<tokio::sync::oneshot::Sender<String>>,
) -> Result<()> {
    let helper = config.boolean("ui-helper");
    ensure!(
        !helper || is_admin(),
        "helper requires administrator privileges"
    );
    let listener = TcpListener::bind(("127.0.0.1", config.number("ui-port", 0)? as u16)).await?;
    let host = listener.local_addr()?.to_string();
    let token = hex::encode(random::<32>());
    let store = if helper {
        None
    } else {
        Some(Store::open(&Store::default_path()?)?)
    };
    let c = Control::new(host.clone(), token.clone(), helper, store, cancel.clone());
    if !config.get("ui-helper-address-file", "").is_empty() {
        let path = config.get("ui-helper-address-file", "");
        c.attach(&tokio::fs::read_to_string(path).await?).await?;
        tokio::fs::remove_file(path).await?;
    }
    let url = format!("http://{host}/#{token}");
    let mut ready = ReadyFile(None);
    if !config.get("ui-ready-file", "").is_empty() {
        use std::io::Write;
        let path = PathBuf::from(config.get("ui-ready-file", ""));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).truncate(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(url.as_bytes())?;
        ready.0 = Some(path);
    }
    if !helper {
        println!("CONTROL_URL={url}");
    }
    if let Some(notify) = notify {
        let _ = notify.send(url.clone());
    }
    if !helper && !config.boolean("ui-no-browser") {
        let _ = webbrowser::open(&url);
    }
    let lease_c = c.clone();
    let lease = tokio::spawn(async move {
        if helper {
            loop {
                tokio::select! {_=lease_c.cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{if lease_c.epoch.elapsed().as_secs().saturating_sub(lease_c.last_lease.load(Ordering::Relaxed))>15{lease_c.cancel.cancel();break;}}}
            }
        }
    });
    let cleanup = c.clone();
    let shutdown = cancel.clone();
    let result = axum::serve(listener, router(c.clone()))
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
            let _ = cleanup.stop().await;
        })
        .await;
    lease.abort();
    let _ = lease.await;
    if let Some(helper) = c.helper.lock().await.take() {
        close_helper(helper).await;
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod log_mirror_tests {
    use super::*;
    #[test]
    fn helper_snapshots_append_only_new_events_to_user_files() {
        let dir = tempfile::tempdir().unwrap();
        let report = Reporter::persistent_in(dir.path(), &Config::default());
        let previous = Mutex::new(String::new());
        let first = json!({"logs":"[INFO] SSH established\n"});
        mirror_logs(&report, &previous, &first);
        let initial = report.snapshot()["logs"].as_str().unwrap().to_owned();
        mirror_logs(&report, &previous, &first);
        assert_eq!(report.snapshot()["logs"], initial);
        mirror_logs(
            &report,
            &previous,
            &json!({"logs":"[INFO] SSH established\n[ERROR] Remote closed\n"}),
        );
        let status = report.snapshot();
        let text = status["logs"].as_str().unwrap();
        assert_eq!(text.matches("SSH established").count(), 1);
        assert!(text.contains("Remote closed"));
        let saved = logging::read(dir.path(), status["logFile"].as_str().unwrap()).unwrap();
        assert!(saved.contains("Remote closed"));
    }
}
