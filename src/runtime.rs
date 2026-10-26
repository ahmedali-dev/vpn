use crate::{
    config::{Config, parse_proxy},
    core::{CoreProcess, find_core, tun_config, xray_config},
    logging::{self, Redactor, SessionFile},
    recovery::{HealthGate, RetryPolicy, permanent},
    transport::{self, HostVerifier},
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, lookup_host},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Status {
    pub state: String,
    pub error: String,
    pub logs: String,
    pub connection: Value,
    pub health: Value,
    pub recovery: Value,
    pub log_error: String,
    pub log_file: Option<SessionFile>,
    pub redactor: Redactor,
}
#[derive(Clone)]
pub struct Reporter(pub Arc<Mutex<Status>>);
impl Default for Reporter {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Status {
            state: "disconnected".into(),
            ..Default::default()
        })))
    }
}
impl Reporter {
    pub fn persistent(config: &Config) -> Self {
        match logging::default_dir() {
            Ok(dir) => Self::persistent_in(&dir, config),
            Err(e) => {
                let r = Self::default();
                r.0.lock().unwrap().log_error = e.to_string();
                r
            }
        }
    }
    pub fn persistent_in(dir: &std::path::Path, config: &Config) -> Self {
        let r = Self::default();
        let result = SessionFile::create(dir);
        {
            let mut s = r.0.lock().unwrap();
            s.redactor = Redactor::for_config(config);
            match result {
                Ok(file) => s.log_file = Some(file),
                Err(e) => s.log_error = format!("Could not save logs: {e}"),
            }
        }
        r.event(
            "INFO",
            "SESSION",
            format!(
                "TunnelNest {} on {}/{}; mode={}; routing={}",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH,
                config.mode(),
                if config.tun() { "TUN" } else { "proxy" }
            ),
        );
        r
    }
    pub fn clean(&self, text: &str) -> String {
        self.0.lock().unwrap().redactor.clean(text)
    }
    pub fn log(&self, s: impl AsRef<str>) {
        self.event("INFO", "ENGINE", s);
    }
    pub fn event(&self, level: &str, component: &str, message: impl AsRef<str>) {
        let mut state = self.0.lock().unwrap();
        let clean = state.redactor.clean(message.as_ref());
        for line in clean.lines() {
            let line = if line.len() > 16000 {
                "[oversized log line omitted]"
            } else {
                line
            };
            let record = format!(
                "{} [{level}] [{component}] {line}\n",
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            );
            if let Some(file) = state.log_file.as_mut()
                && let Err(e) = file.append(&record)
            {
                state.log_error = format!("Could not save logs: {e}");
                state.log_file = None;
            }
            state.logs.push_str(&record);
        }
        while state.logs.len() > 65536 {
            let n = state
                .logs
                .char_indices()
                .nth(1024)
                .map(|x| x.0)
                .unwrap_or(state.logs.len());
            state.logs.drain(..n);
        }
    }
    pub fn state(&self, state: &str) {
        self.event("INFO", "STATE", format!("Connection state: {state}"));
        self.0.lock().unwrap().state = state.into();
    }
    pub fn health(&self, state: &str, error: &str) {
        let error = self.clean(error);
        self.0.lock().unwrap().health =
            json!({"state":state,"error":error,"lastCheck":chrono::Utc::now().to_rfc3339()});
    }
    pub(crate) async fn stage<T>(
        &self,
        name: &str,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let start = std::time::Instant::now();
        self.event("INFO", "STAGE", format!("{name} started"));
        let result = work.await;
        let elapsed = start.elapsed().as_millis() as u64;
        self.event(
            if result.is_ok() { "INFO" } else { "WARN" },
            "STAGE",
            format!(
                "{name} {} after {elapsed}ms",
                if result.is_ok() {
                    "completed"
                } else {
                    "failed"
                }
            ),
        );
        let mut status = self.0.lock().unwrap();
        if !status.recovery.is_object() {
            status.recovery = json!({});
        }
        status.recovery["lastStage"] =
            json!({"name":name,"durationMs":elapsed,"success":result.is_ok()});
        result
    }
    fn connected(&self) {
        let now = chrono::Utc::now();
        let (startup_ms, recovery_ms) = {
            let mut status = self.0.lock().unwrap();
            let elapsed = |key: &str| {
                status.recovery[key]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|at| {
                        (now - at.with_timezone(&chrono::Utc))
                            .num_milliseconds()
                            .max(0)
                    })
            };
            let startup = elapsed("attemptStartedAt");
            let recovery = elapsed("recoveryStartedAt");
            status.recovery["startupMs"] = json!(startup);
            status.recovery["recoveryMs"] = json!(recovery);
            status.recovery["recoveryStartedAt"] = Value::Null;
            status.recovery["nextRetryAt"] = Value::Null;
            (startup, recovery)
        };
        self.event(
            "INFO",
            "CONNECT",
            format!(
                "Connection verified; startup={}ms; recovery={}ms",
                startup_ms.unwrap_or(0),
                recovery_ms.unwrap_or(0)
            ),
        );
        self.state("connected");
        self.health("healthy", "");
    }
    pub fn snapshot(&self) -> Value {
        let s = self.0.lock().unwrap();
        json!({"state":s.state,"error":s.error,"logs":s.logs,"connection":s.connection,"health":s.health,"recovery":s.recovery,"administrator":is_admin(),"logFile":s.log_file.as_ref().map(|f|f.path.file_name().unwrap_or_default().to_string_lossy()),"logError":s.log_error})
    }
}
pub fn is_admin() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}
pub struct Session {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    pub report: Reporter,
}
impl Session {
    pub fn start(config: Config) -> Self {
        let report = Reporter::persistent(&config);
        Self::start_with_report(config, report)
    }
    pub fn start_with_report(config: Config, report: Reporter) -> Self {
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        report.state("connecting");
        let r = report.clone();
        let task = tokio::spawn(async move {
            let result = run(config, c.clone(), r.clone()).await;
            {
                let mut status = r.0.lock().unwrap();
                if status.recovery.is_object() {
                    status.recovery["nextRetryAt"] = Value::Null;
                }
            }
            if c.is_cancelled() {
                r.state("disconnected");
                r.health("disconnected", "");
            } else if let Err(e) = result {
                let message = r.clean(&format!("{e:#}"));
                r.event("ERROR", "SESSION", &message);
                r.health("failed", &message);
                let mut s = r.0.lock().unwrap();
                s.error = message;
                s.state = "error".into();
            } else {
                r.state("disconnected");
            }
        });
        Self {
            cancel,
            task,
            report,
        }
    }
    pub fn active(&self) -> bool {
        !self.task.is_finished()
    }
    pub async fn stop(&mut self) {
        self.report.event(
            "INFO",
            "SHUTDOWN",
            "Disconnect requested; cancelling connection tasks",
        );
        self.report.state("stopping");
        self.cancel.cancel();
        if tokio::time::timeout(Duration::from_secs(45), &mut self.task)
            .await
            .is_err()
        {
            self.report.event(
                "WARN",
                "SHUTDOWN",
                "Graceful shutdown timed out after 45s; cancelling task",
            );
            self.task.abort();
            let _ = (&mut self.task).await;
        }
        self.report.state("disconnected");
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

async fn prepare(c: &mut Config, r: &Reporter) -> Result<Vec<String>> {
    let mut excluded = vec![];
    let (host, port) = if c.mode() == "ssh" {
        (c.get("H", "").to_string(), c.number("P", 0)? as u16)
    } else if c.get("v2ray-config", "").is_empty() {
        let p = c.protocol()?;
        (p.address, p.port as u16)
    } else {
        return Ok(excluded);
    };
    for (name, h, p) in [
        ("dial-address", host, port),
        (
            "proxy-dial-address",
            if c.get("proxy", "").is_empty() {
                String::new()
            } else {
                parse_proxy(c.get("proxy", ""))?
                    .host_str()
                    .unwrap()
                    .trim_matches(['[', ']'])
                    .into()
            },
            0,
        ),
    ] {
        if h.is_empty() {
            continue;
        }
        r.event(
            "INFO",
            "DNS",
            format!("Resolving {h} before tunnel activation"),
        );
        let ips: Vec<_> = tokio::time::timeout(
            Duration::from_secs(10),
            lookup_host(transport::authority(&h, p)),
        )
        .await??
        .map(|x| x.ip())
        .collect();
        ensure!(!ips.is_empty(), "upstream DNS returned no addresses");
        let ip = ips.iter().find(|x| x.is_ipv4()).unwrap_or(&ips[0]);
        r.event(
            "INFO",
            "DNS",
            format!("Resolved {h}: {} address(es); dial address {ip}", ips.len()),
        );
        c.flags.insert(name.into(), ip.to_string());
        for ip in ips {
            let bits = if ip.is_ipv4() { 32 } else { 128 };
            excluded.push(format!("{ip}/{bits}"));
        }
    }
    excluded.sort();
    excluded.dedup();
    Ok(excluded)
}
async fn run(mut c: Config, cancel: CancellationToken, r: Reporter) -> Result<()> {
    ensure!(
        !c.tun() || is_admin(),
        "full-device TUN requires the administrator helper"
    );
    let (host, port, sni, setting, ca) = if c.mode() == "ssh" {
        (
            c.get("H", "").to_string(),
            c.number("P", 0)? as u16,
            if c.get("S", "").is_empty() {
                c.get("H", "")
            } else {
                c.get("S", "")
            }
            .to_string(),
            c.get("ssh-cert-sha256", "auto").to_string(),
            c.get("tls-ca", "").to_string(),
        )
    } else if c.get("v2ray-config", "").is_empty() {
        let p = c.protocol()?;
        (
            p.address,
            p.port as u16,
            p.sni,
            if p.security == "tls" {
                c.get("v2ray-cert-sha256", "auto")
            } else {
                "none"
            }
            .into(),
            String::new(),
        )
    } else {
        (
            String::new(),
            0,
            String::new(),
            "none".into(),
            String::new(),
        )
    };
    r.0.lock().unwrap().connection =
        json!({"server":transport::authority(&host,port),"sni":sni,"mode":c.mode()});
    // Explicit compatibility pins survive restarts for this connection session only.
    let mut compatibility_pin = None;
    let tofu_key = Arc::new(Mutex::new(None));
    let mut retries = RetryPolicy::default();
    let mut attempt = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        attempt += 1;
        let started = std::time::Instant::now();
        let mut connected_for = Duration::ZERO;
        r.state(if attempt == 1 {
            "connecting"
        } else {
            "reconnecting"
        });
        r.health("connecting", "");
        {
            let mut status = r.0.lock().unwrap();
            if !status.recovery.is_object() {
                status.recovery = json!({});
            }
            status.recovery["attempt"] = json!(attempt);
            status.recovery["attemptStartedAt"] = json!(chrono::Utc::now().to_rfc3339());
            status.recovery["consecutiveFailures"] = json!(retries.failures());
            status.recovery["nextRetryAt"] = Value::Null;
        }
        r.event(
            "INFO",
            "CONNECT",
            format!(
                "Attempt {attempt}; server={host}:{port}; SNI={sni}; certificate mode={setting}"
            ),
        );
        let result: Result<()> = async {
            let excluded = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                value = r.stage("DNS preparation", prepare(&mut c, &r)) => value.context("upstream DNS preparation failed")?,
            };
            let pin = if setting == "insecure" && compatibility_pin.is_some() {
                compatibility_pin.clone()
            } else {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    value = r.stage("TLS discovery", async { tokio::time::timeout(Duration::from_secs(45), transport::resolve_pin(&host,port,&sni,&setting,&ca,c.get("tls-version","auto"))).await.context("TLS discovery timed out after 45s")? }) => value.context("TLS certificate discovery/verification failed")?,
                }
            };
            if setting == "insecure" { compatibility_pin = pin.clone(); }
            run_once(&c, &excluded, pin.as_deref(), cancel.clone(), r.clone(), tofu_key.clone(), &mut connected_for).await
        }.await;
        if cancel.is_cancelled() {
            return Ok(());
        }
        let error = match result {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let connected = connected_for;
        r.health("degraded", &error.to_string());
        r.event(
            "ERROR",
            "CONNECT",
            format!(
                "Attempt {attempt} failed after {}ms; connected={}ms: {error:#}",
                started.elapsed().as_millis(),
                connected.as_millis()
            ),
        );
        let terminal = permanent(&error);
        let delay = if terminal {
            None
        } else {
            retries.failed(connected, rand::random::<f64>())
        };
        {
            let mut status = r.0.lock().unwrap();
            let reason: String = status
                .redactor
                .clean(&format!("{error:#}"))
                .chars()
                .take(4000)
                .collect();
            status.recovery["lastFailure"] =
                json!({"reason":reason,"terminal":terminal,"at":chrono::Utc::now().to_rfc3339()});
            status.recovery["consecutiveFailures"] = json!(retries.failures());
            if status.recovery["recoveryStartedAt"].is_null() {
                status.recovery["recoveryStartedAt"] = json!(chrono::Utc::now().to_rfc3339());
            }
            status.recovery["nextRetryAt"] = json!(delay.map(|d| {
                (chrono::Utc::now() + chrono::Duration::milliseconds(d.as_millis() as i64))
                    .to_rfc3339()
            }));
        }
        let Some(delay) = delay else {
            r.event(
                "ERROR",
                "RECONNECT",
                if terminal {
                    "Stopped: credentials, trust, permissions or configuration require attention"
                } else {
                    "Stopped: six consecutive connection failures"
                },
            );
            return Err(error);
        };
        r.event(
            "WARN",
            "RECONNECT",
            format!(
                "Retrying in {}ms; consecutive failures={}/6",
                delay.as_millis(),
                retries.failures()
            ),
        );
        tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = tokio::time::sleep(delay) => () }
    }
}

async fn pipe_log<S: AsyncRead + Unpin + Send + 'static>(
    stream: S,
    r: Reporter,
    source: &'static str,
) {
    let mut reader = BufReader::new(stream);
    let mut pending = vec![];
    let mut oversized = false;
    loop {
        let chunk = match reader.fill_buf().await {
            Ok(chunk) => chunk,
            Err(e) => {
                r.event("WARN", source, format!("Cannot read core output: {e}"));
                break;
            }
        };
        if chunk.is_empty() {
            if !pending.is_empty() || oversized {
                core_line(&r, source, &pending, oversized);
            }
            break;
        }
        let consumed = chunk
            .iter()
            .position(|b| *b == b'\n')
            .map_or(chunk.len(), |i| i + 1);
        let complete = chunk[consumed - 1] == b'\n';
        if pending.len() + consumed <= 16000 && !oversized {
            pending.extend_from_slice(&chunk[..consumed]);
        } else {
            oversized = true;
            pending.clear();
        }
        reader.consume(consumed);
        if complete {
            core_line(&r, source, &pending, oversized);
            pending.clear();
            oversized = false;
        }
    }
}
fn core_line(r: &Reporter, source: &str, data: &[u8], oversized: bool) {
    if oversized {
        r.event(
            "WARN",
            source,
            "Oversized core log line omitted (limit 16000 bytes)",
        );
        return;
    }
    let line = String::from_utf8_lossy(data);
    let lower = line.to_ascii_lowercase();
    let level = if ["error", "fatal", "panic"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "ERROR"
    } else if lower.contains("warn") {
        "WARN"
    } else {
        "INFO"
    };
    r.event(level, source, line.trim_end());
}

fn capture(core: &mut CoreProcess, r: &Reporter, jobs: &mut JoinSet<()>, source: &'static str) {
    if let Some(out) = core.child().stdout.take() {
        jobs.spawn(pipe_log(
            out,
            r.clone(),
            if source == "TUN" {
                "TUN/STDOUT"
            } else {
                "CORE/STDOUT"
            },
        ));
    }
    if let Some(err) = core.child().stderr.take() {
        jobs.spawn(pipe_log(
            err,
            r.clone(),
            if source == "TUN" {
                "TUN/STDERR"
            } else {
                "CORE/STDERR"
            },
        ));
    }
}
async fn run_once(
    c: &Config,
    excluded: &[String],
    pin: Option<&str>,
    cancel: CancellationToken,
    r: Reporter,
    tofu_key: Arc<Mutex<Option<String>>>,
    connected_for: &mut Duration,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", c.socks_port()))
        .await
        .context("SOCKS port is already occupied")?;
    r.event(
        "INFO",
        "SOCKS",
        format!(
            "Reserved SOCKS listener 127.0.0.1:{}; connection limit={}",
            c.socks_port(),
            c.number("max-conns", 2000)?
        ),
    );
    let mut jobs = JoinSet::new();
    let pac_port = c.number("pac-port", 0)? as u16;
    if pac_port > 0 {
        let pac = TcpListener::bind(("127.0.0.1", pac_port))
            .await
            .context("PAC port is already occupied")?;
        r.event(
            "INFO",
            "PAC",
            format!("Serving PAC on 127.0.0.1:{pac_port}/proxy.pac"),
        );
        jobs.spawn(pac_server(pac, c.socks_port()));
    }
    let mut core = None;
    let mut ssh = None;
    let mut tun = None;
    let mut connected_at = None;
    let outcome=async {
    if c.mode()=="ssh" {
        let handle=Arc::new(tokio::select!{_=cancel.cancelled()=>return Ok(()),s=r.stage("SSH transport and authentication", transport::connect_ssh_logged(c,pin,tofu_key,r.clone()))=>s?});ssh=Some(handle.clone());
        jobs.spawn(socks_server(listener,handle,c.number("max-conns",2000)? as usize,c.boolean("ssh-ipv4-only"),cancel.clone(),r.clone()));
    }else {
        drop(listener);
        let names=if c.mode()=="v2ray"{vec!["v2ray","xray"]}else{vec!["xray"]};
        let binary=find_core(c.get("v2ray-binary",""),&names)?;
        let generated=if c.get("v2ray-config","").is_empty(){Some(xray_config(c,&c.protocol()?,pin))}else{None};
        let mut p=tokio::select!{_=cancel.cancelled()=>return Ok(()),p=r.stage("Core startup", CoreProcess::start(binary,generated,c.get("v2ray-config",""),false))=>p?};r.event("INFO","CORE",format!("Started core; PID={:?}",p.child().id()));capture(&mut p,&r,&mut jobs,"CORE");core=Some(p);
        let mut ready=false;
        for _ in 0..100 {
            if let Some(status)=core.as_mut().unwrap().child().try_wait()?{bail!("core exited during startup ({status})")}
            if TcpStream::connect(("127.0.0.1",c.socks_port())).await.is_ok(){ready=true;break;}
            tokio::select!{_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_millis(100))=>()}
        }ensure!(ready,"SOCKS listener did not become ready");
    }
    tokio::select!{_=cancel.cancelled()=>return Ok(()),v=r.stage("Proxy verification", verify_logged(Some(c.socks_port()),Some(&r)))=>v.context("proxy connectivity verification failed")?};
    r.log("[+] HTTPS traffic verified through SOCKS");
    if c.tun(){
        if c.mode()=="ssh" && c.boolean("ssh-ipv4-only") {
            r.event("INFO","TUN","IPv4 compatibility: filtering AAAA/HTTPS/SVCB DNS responses; cached IPv6 TLS/HTTP destinations use hostname recovery; other IPv6 traffic stays blocked. SSH carries TCP; UDP applications are unsupported.");
        }
        let mut p=tokio::select!{_=cancel.cancelled()=>return Ok(()),p=r.stage("TUN startup", CoreProcess::start(find_core(c.get("tun-binary",""),&["sing-box"] )?,Some(tun_config(c,excluded,std::env::consts::OS)),"",true))=>p?};
        r.event("INFO","TUN",format!("Starting sing-box; PID={:?}; excluded upstream routes={}",p.child().id(),excluded.len()));capture(&mut p,&r,&mut jobs,"TUN");tun=Some(p);tokio::select!{_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(2))=>()}
        if let Some(status)=tun.as_mut().unwrap().child().try_wait()?{bail!("TUN exited during startup ({status})")}
        tokio::select!{_=cancel.cancelled()=>return Ok(()),v=r.stage("TUN verification", verify_logged(None,Some(&r)))=>v.context("system connectivity failed after TUN activation")?};
        r.log("[+] Full-device routing verified");
    }
    connected_at=Some(std::time::Instant::now());
    r.connected();
    let port=c.socks_port(); let full_device=c.tun();
    monitor_connection(cancel.clone(), r.clone(),
                || {
                if let Some(p)=core.as_mut()&& let Some(code)=p.child().try_wait()?{return Err(anyhow::anyhow!("core stopped ({code})"))}
                if let Some(p)=tun.as_mut()&& let Some(code)=p.child().try_wait()?{return Err(anyhow::anyhow!("TUN stopped ({code})"))}
                if let Some(s)=&ssh&& s.is_closed(){return Err(anyhow::anyhow!("SSH session closed"))}
                    Ok(())
                },
                || {
                    let report=r.clone();
                    async move {
                        let proxy=verify_logged(Some(port),Some(&report)).await;
                        let system=if full_device { verify_logged(None,Some(&report)).await } else { Ok(()) };
                        proxy.context("proxy health check failed")?;
                        system.context("system route health check failed")
                    }
                }, Duration::from_secs(1), Duration::from_secs(30)).await
    }.await;
    *connected_for = connected_at
        .map(|at: std::time::Instant| at.elapsed())
        .unwrap_or_default();
    if let Some(p) = tun.as_mut() {
        p.stop().await;
    }
    if let Some(s) = ssh {
        let _ = s
            .disconnect(russh::Disconnect::ByApplication, "disconnect", "")
            .await;
    }
    if let Some(p) = core.as_mut() {
        p.stop().await;
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    r.event(
        "INFO",
        "CLEANUP",
        "Stopped networking processes and forwarding tasks; temporary configs released",
    );
    outcome
}
// Probe work runs independently so child exits and cancellation stay responsive.
async fn monitor_connection<F, P, Fut>(
    cancel: CancellationToken,
    r: Reporter,
    mut alive: F,
    mut probe: P,
    liveness_period: Duration,
    health_period: Duration,
) -> Result<()>
where
    F: FnMut() -> Result<()>,
    P: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let mut probes = JoinSet::new();
    let mut gate = HealthGate::default();
    let mut health = tokio::time::interval(health_period);
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    health.tick().await;
    let mut liveness = tokio::time::interval(liveness_period);
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result=async {
        loop {
            tokio::select! {
                _=cancel.cancelled()=>return Ok(()),
                _=liveness.tick()=>alive()?,
                _=health.tick(), if probes.is_empty()=>{probes.spawn(probe());},
                result=probes.join_next(), if !probes.is_empty()=>{
                    let checked=result.context("health task missing")?.context("health task failed")?;
                    match checked {
                        Ok(())=>{gate.recovered();r.health("healthy","");},
                        Err(error)=>{
                            let restart=gate.failed();
                            r.health("degraded", &error.to_string());
                            r.event("WARN","HEALTH",format!("Probe cycle failed {}/3: {error:#}",gate.failures()));
                            if restart { return Err(error.context("three consecutive health probe cycles failed")); }
                        }
                    }
                }
            }
        }
    }.await;
    probes.abort_all();
    while probes.join_next().await.is_some() {}
    result
}

pub async fn verify(port: Option<u16>) -> Result<()> {
    verify_logged(port, None).await
}
async fn verify_logged(port: Option<u16>, report: Option<&Reporter>) -> Result<()> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::limited(3));
    if let Some(port) = port {
        b = b.proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))?);
    }
    let client = b.build()?;
    for url in [
        "https://api.ipify.org",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ] {
        let started = std::time::Instant::now();
        if let Some(r) = report {
            r.event(
                "INFO",
                "HEALTH",
                format!(
                    "Checking {url} via {}",
                    if port.is_some() {
                        "SOCKS (remote DNS)"
                    } else {
                        "system routes"
                    }
                ),
            );
        }
        match client.get(url).send().await {
            Ok(response) => {
                if let Some(r) = report {
                    r.event(
                        if response.status().is_success() {
                            "INFO"
                        } else {
                            "WARN"
                        },
                        "HEALTH",
                        format!(
                            "HTTPS check returned HTTP {} in {}ms",
                            response.status(),
                            started.elapsed().as_millis()
                        ),
                    );
                }
                if response.status().is_success() {
                    return Ok(());
                }
            }
            Err(e) => {
                if let Some(r) = report {
                    r.event(
                        "WARN",
                        "HEALTH",
                        format!(
                            "HTTPS check failed after {}ms: {e}",
                            started.elapsed().as_millis()
                        ),
                    );
                }
            }
        }
    }
    bail!("both HTTPS connectivity checks failed")
}
async fn socks_server(
    listener: TcpListener,
    session: Arc<russh::client::Handle<HostVerifier>>,
    max: usize,
    ipv4: bool,
    cancel: CancellationToken,
    r: Reporter,
) {
    let permits = Arc::new(Semaphore::new(max));
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            v=listener.accept()=>{match v{Ok((stream,_))=>{if let Ok(permit)=permits.clone().try_acquire_owned(){let s=session.clone();let r=r.clone();jobs.spawn(async move{let _permit=permit;if let Err(e)=socks_connection(stream,s,ipv4,&r).await{r.event("ERROR","SOCKS",format!("{e:#}"));}});}},Err(_)=>break}},
            _=jobs.join_next(),if !jobs.is_empty()=>(),
        }
    }
}
async fn socks_connection(
    mut stream: TcpStream,
    session: Arc<russh::client::Handle<HostVerifier>>,
    ipv4: bool,
    r: &Reporter,
) -> Result<()> {
    let (mut host, port) = tokio::time::timeout(Duration::from_secs(15), async {
        ensure!(stream.read_u8().await? == 5, "unsupported SOCKS version");
        let count = stream.read_u8().await? as usize;
        let mut methods = vec![0; count];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            stream.write_all(&[5, 255]).await?;
            bail!("SOCKS requires no-auth method")
        }
        stream.write_all(&[5, 0]).await?;
        let mut request = [0; 4];
        stream.read_exact(&mut request).await?;
        ensure!(request[0] == 5 && request[2] == 0, "invalid SOCKS request");
        if request[1] != 1 {
            stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            bail!("only TCP CONNECT is supported")
        }
        let host = match request[3] {
            1 => {
                let mut ip = [0; 4];
                stream.read_exact(&mut ip).await?;
                std::net::Ipv4Addr::from(ip).to_string()
            }
            4 => {
                let mut ip = [0; 16];
                stream.read_exact(&mut ip).await?;
                std::net::Ipv6Addr::from(ip).to_string()
            }
            3 => {
                let n = stream.read_u8().await? as usize;
                ensure!(n > 0, "empty SOCKS hostname");
                let mut name = vec![0; n];
                stream.read_exact(&mut name).await?;
                String::from_utf8(name)?
            }
            _ => {
                stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                bail!("unsupported SOCKS address")
            }
        };
        let port = stream.read_u16().await?;
        Ok::<_, anyhow::Error>((host, port))
    })
    .await??;
    let recover_hostname = ipv4 && host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6());
    let mut initial = Vec::new();
    if recover_hostname {
        // TUN clients may use IPv6 cached before activation, or DoH IPv6 hints.
        // Acknowledge the local connection so the client sends its initial
        // request, then use its hostname for remote SSH resolution (as Firefox
        // does with SOCKS remote DNS). Never send the TLS data to a local TLS
        // endpoint or retry the rejected literal IPv6 address directly.
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let (name, bytes) = crate::hostname::recover(&mut stream).await
            .with_context(|| format!("IPv4 compatibility could not recover a hostname for [{host}]:{port}; restart the app using this destination to clear cached IPv6 addresses, or disable IPv4 compatibility if the SSH server supports IPv6"))?;
        r.event(
            "INFO",
            "SSH-FORWARD",
            format!(
                "IPv4 compatibility: recovering [{host}]:{port} via hostname {name}; remote DNS"
            ),
        );
        host = name;
        initial = bytes;
    }
    let started = std::time::Instant::now();
    r.event(
        "INFO",
        "SSH-FORWARD",
        format!("Opening TCP channel to {host}:{port}"),
    );
    let channel = match tokio::time::timeout(
        Duration::from_secs(30),
        session.channel_open_direct_tcpip(host.clone(), port.into(), "127.0.0.1", 0),
    )
    .await
    {
        Ok(Ok(channel)) => channel,
        error => {
            if !recover_hostname {
                stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            }
            match error {
                Err(_) => bail!("SSH forwarding to {host}:{port} timed out after 30s"),
                Ok(Err(e)) => bail!("SSH forwarding to {host}:{port} refused: {e}"),
                _ => unreachable!(),
            }
        }
    };
    if !recover_hostname {
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    }
    let mut channel = channel.into_stream();
    channel.write_all(&initial).await?;
    r.event(
        "INFO",
        "SSH-FORWARD",
        format!("Channel established in {}ms", started.elapsed().as_millis()),
    );
    let (uploaded, downloaded) = tokio::io::copy_bidirectional(&mut stream, &mut channel)
        .await
        .context("SSH data forwarding interrupted")?;
    let uploaded = uploaded + initial.len() as u64;
    r.event("INFO","SSH-FORWARD",format!("Closed {host}:{port}; uploaded={uploaded} bytes; downloaded={downloaded} bytes; duration={}ms",started.elapsed().as_millis()));
    Ok(())
}
pub fn pac_script(port: u16) -> String {
    format!(
        "function FindProxyForURL(url, host) {{ if (isPlainHostName(host) || host === 'localhost' || isInNet(host, '127.0.0.0', '255.0.0.0') || isInNet(host, '10.0.0.0', '255.0.0.0') || isInNet(host, '172.16.0.0', '255.240.0.0') || isInNet(host, '192.168.0.0', '255.255.0.0')) return 'DIRECT'; return 'SOCKS5 127.0.0.1:{port}'; }}"
    )
}
async fn pac_server(listener: TcpListener, port: u16) {
    use axum::{Router, routing::get};
    let app = Router::new().route(
        "/proxy.pac",
        get(move || async move {
            (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/x-ns-proxy-autoconfig",
                )],
                pac_script(port),
            )
        }),
    );
    let _ = axum::serve(listener, app).await;
}

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_server;

#[cfg(test)]
mod forwarding_tests {
    use super::*;

    #[tokio::test]
    async fn cached_ipv6_requests_recover_hostname_over_verified_tls_ssh() {
        for data in [
            crate::hostname::tests::client_hello(true),
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        ] {
            recovered_request(&data).await;
        }
    }

    async fn recovered_request(data: &[u8]) {
        let server = test_server::server().await;
        let c = Config::parse(&[
            "-H".into(),
            "127.0.0.1".into(),
            "-P".into(),
            server.port.to_string(),
            "-S".into(),
            "localhost".into(),
            "-u".into(),
            "alice".into(),
            "-p".into(),
            "secret".into(),
            "-tls-ca".into(),
            server.ca.path().to_str().unwrap().into(),
            "-ssh-host-key".into(),
            server.ssh_fingerprint.clone(),
        ])
        .unwrap();
        let report = Reporter::default();
        let ssh = Arc::new(
            transport::connect_ssh_logged(
                &c,
                Some(&server.certificate_pin),
                Arc::new(Mutex::new(None)),
                report.clone(),
            )
            .await
            .unwrap(),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let log = report.clone();
        let task = tokio::spawn(async move { socks_connection(stream, ssh, true, &log).await });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 4];
        request.extend_from_slice(
            &"2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        client.write_all(data).await.unwrap();
        let mut echo = vec![0; data.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echo, data);
        drop(client);
        task.await.unwrap().unwrap();
        let snapshot = report.snapshot();
        let text = snapshot["logs"].as_str().unwrap();
        assert!(
            text.contains("Opening TCP channel to example.com:443"),
            "{text}"
        );
        assert!(!text.contains("Opening TCP channel to 2001:db8"), "{text}");
    }
}

#[cfg(test)]
mod recovery_monitor_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn pending_probe_does_not_block_liveness_or_leak_on_exit() {
        let probes = Arc::new(AtomicUsize::new(0));
        let active = probes.clone();
        let mut ticks = 0;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            monitor_connection(
                CancellationToken::new(),
                Reporter::default(),
                || {
                    ticks += 1;
                    if ticks >= 5 {
                        bail!("child stopped")
                    }
                    Ok(())
                },
                move || {
                    let active = active.clone();
                    async move {
                        struct Guard(Arc<AtomicUsize>);
                        impl Drop for Guard {
                            fn drop(&mut self) {
                                self.0.fetch_sub(1, Ordering::SeqCst);
                            }
                        }
                        active.fetch_add(1, Ordering::SeqCst);
                        let _guard = Guard(active);
                        std::future::pending::<Result<()>>().await
                    }
                },
                Duration::from_millis(10),
                Duration::from_millis(1),
            ),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("child stopped"));
        assert_eq!(probes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn intermittent_failures_recover_and_only_three_consecutive_failures_restart() {
        let report = Reporter::default();
        let mut cycle = 0;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            monitor_connection(
                CancellationToken::new(),
                report.clone(),
                || Ok(()),
                || {
                    cycle += 1;
                    let pass = cycle == 3;
                    async move {
                        if pass {
                            Ok(())
                        } else {
                            bail!("temporary probe failure")
                        }
                    }
                },
                Duration::from_millis(1),
                Duration::from_millis(2),
            ),
        )
        .await
        .unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("three consecutive")
        );
        assert_eq!(cycle, 6);
        assert_eq!(report.snapshot()["health"]["state"], "degraded");
    }
    #[tokio::test]
    async fn cancellation_stops_pending_health_work() {
        let token = CancellationToken::new();
        let stop = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            stop.cancel();
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            monitor_connection(
                token,
                Reporter::default(),
                || Ok(()),
                std::future::pending::<Result<()>>,
                Duration::from_millis(1),
                Duration::from_millis(1),
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }
}

#[cfg(test)]
mod recovery_diagnostics_tests {
    use super::*;
    #[tokio::test]
    async fn completed_stages_and_recovery_timing_are_exported() {
        let r = Reporter::default();
        {
            let mut s = r.0.lock().unwrap();
            s.recovery = json!({"attempt":2,"attemptStartedAt":(chrono::Utc::now()-chrono::Duration::seconds(2)).to_rfc3339(),
                "recoveryStartedAt":(chrono::Utc::now()-chrono::Duration::seconds(5)).to_rfc3339(),
                "lastFailure":{"reason":"temporary failure"},"nextRetryAt":"old retry"});
        }
        r.stage("test stage", async { Ok(()) }).await.unwrap();
        r.connected();
        let snapshot = r.snapshot();
        assert_eq!(snapshot["recovery"]["lastStage"]["name"], "test stage");
        assert_eq!(snapshot["recovery"]["lastStage"]["success"], true);
        assert!(snapshot["recovery"]["startupMs"].as_i64().unwrap() >= 2000);
        assert!(snapshot["recovery"]["recoveryMs"].as_i64().unwrap() >= 5000);
        assert_eq!(
            snapshot["recovery"]["lastFailure"]["reason"],
            "temporary failure"
        );
        assert!(snapshot["recovery"]["nextRetryAt"].is_null());
        assert_eq!(snapshot["state"], "connected");
    }
}
