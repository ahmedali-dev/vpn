//! Connectivity and readiness service
//!
//! Performs bounded HTTPS/DNS checks, policy-aware route checks and core/SSH liveness monitoring.

use super::status::Reporter;
use crate::config::Config;
use crate::recovery::HealthGate;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(super) async fn finish_core_logs(jobs: &mut JoinSet<()>, r: &Reporter) {
    if tokio::time::timeout(Duration::from_secs(1), async {
        while jobs.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        r.event(
            "WARN",
            "CORE",
            "Core log drain deadline exceeded; remaining output readers cancelled",
        );
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
    }
}
pub(super) async fn startup_work<T, F, Fut>(
    cancel: CancellationToken,
    mut alive: F,
    work: Fut,
) -> Result<Option<T>>
where
    F: FnMut() -> Result<()>,
    Fut: std::future::Future<Output = Result<T>>,
{
    tokio::pin!(work);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! { biased;
            _=cancel.cancelled()=>return Ok(None),
            _=tick.tick()=>alive()?,
            result=&mut work=>return result.map(Some),
        }
    }
}
pub(super) async fn verify_system_dns(timeout: Duration) -> Result<()> {
    let work = async {
        let mut jobs = JoinSet::new();
        for host in ["api.ipify.org", "www.cloudflare.com"] {
            jobs.spawn(async move {
                let mut values = lookup_host((host, 443)).await?;
                ensure!(
                    values.any(|a| !a.ip().is_unspecified() && !a.ip().is_loopback()),
                    "{host}: no usable DNS addresses"
                );
                Ok::<_, anyhow::Error>(())
            });
        }
        let mut errors = Vec::new();
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok(Ok(())) => {
                    jobs.abort_all();
                    while jobs.join_next().await.is_some() {}
                    return Ok(());
                }
                Ok(Err(e)) => errors.push(e.to_string()),
                Err(e) => errors.push(e.to_string()),
            }
        }
        bail!("System DNS resolution failed: {}", errors.join("; "))
    };
    tokio::time::timeout(timeout, work)
        .await
        .context("System DNS verification timed out")
        .context(crate::recovery::FailureCategory::Dns)?
        .map_err(|e| e.context(crate::recovery::FailureCategory::Dns))
}
pub(super) async fn wait_ready<F, P, Fut>(
    cancel: CancellationToken,
    deadline: Duration,
    mut alive: F,
    mut probe: P,
) -> Result<bool>
where
    F: FnMut() -> Result<()>,
    P: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>> + Send,
{
    async fn check<Fut: std::future::Future<Output = Result<bool>>>(
        pause: bool,
        future: Fut,
    ) -> Result<bool> {
        if pause {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        future.await
    }
    let mut work = Box::pin(check(false, probe()));
    let mut ticks = tokio::time::interval(Duration::from_millis(100));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let timeout = tokio::time::sleep(deadline);
    tokio::pin!(timeout);
    let mut last_error = None;
    loop {
        tokio::select! {
            _=cancel.cancelled()=>return Ok(false),
            _=&mut timeout=>return Err(last_error.take().unwrap_or_else(||anyhow::anyhow!("service is not ready")).context(format!("readiness deadline exceeded after {}s",deadline.as_secs()))),
            _=ticks.tick()=>alive()?,
            result=&mut work=>{
                match result {Ok(true)=>return Ok(true),Ok(false)=>(),Err(error)=>last_error=Some(error)}
                work=Box::pin(check(true,probe()));
            }
        }
    }
}

// Probe work runs independently so child exits and cancellation stay responsive.
pub(super) async fn monitor_connection<F, P, Fut>(
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
    let probe_requested = r.0.lock().unwrap().probe_requested.clone();
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
                _=probe_requested.notified(), if probes.is_empty()=>{probes.spawn(probe());},
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

pub fn has_split_policy(c: &Config) -> Result<bool> {
    Ok(c.boolean("bypass-lan") || !c.routing_rules()?.is_empty())
}
pub(super) async fn verify_policy_routes(ips: &[IpAddr], excluded: &[String]) -> Result<()> {
    let interface = crate::network::tun_interface_for(ips)
        .await?
        .context("Configured TUN interface is missing")?;
    ensure!(
        crate::network::tun_capture_routes_present(&interface, excluded).await?,
        "IPv4/IPv6 capture routes are missing from the owned TUN interface"
    );
    Ok(())
}
pub(super) fn matching_exit(proxy: IpAddr, system: IpAddr) -> Result<()> {
    ensure!(
        proxy == system,
        "system IPv4 exit {system} differs from proxy exit {proxy}; full-device routing is not verified"
    );
    Ok(())
}
pub(super) async fn exit_ip(port: Option<u16>, timeout: Duration) -> Result<IpAddr> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(port) = port {
        builder = builder.proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))?);
    }
    let client = builder.build()?;
    // Both destinations force IPv4. A single unavailable service must not
    // independently make an otherwise healthy tunnel fail verification.
    let mut failures = Vec::new();
    for (url, trace) in [
        ("https://api4.ipify.org", false),
        ("https://1.1.1.1/cdn-cgi/trace", true),
    ] {
        let result: Result<IpAddr> = async {
            let mut response = client.get(url).send().await?.error_for_status()?;
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    body.len() + chunk.len() <= 8192,
                    "exit IP response too large"
                );
                body.extend_from_slice(&chunk);
            }
            parse_exit(&body, trace)
        }
        .await;
        match result {
            Ok(ip) => return Ok(ip),
            Err(error) => failures.push(format!("{url}: {error:#}")),
        }
    }
    bail!(
        "both IPv4 exit services failed; system/proxy routing could not be compared: {}",
        failures.join("; ")
    )
}
pub(super) fn parse_exit(body: &[u8], trace: bool) -> Result<IpAddr> {
    let text = std::str::from_utf8(body)?;
    let value = if trace {
        text.lines()
            .find_map(|s| s.strip_prefix("ip="))
            .context("trace response has no IP")?
    } else {
        text.trim()
    };
    let ip: IpAddr = value.parse()?;
    ensure!(ip.is_ipv4(), "expected an IPv4 exit address");
    Ok(ip)
}

pub async fn verify(port: Option<u16>) -> Result<()> {
    verify_logged(port, None).await
}
pub(super) async fn verify_logged(port: Option<u16>, report: Option<&Reporter>) -> Result<()> {
    verify_with_timeout(port, report, Duration::from_secs(20)).await
}
pub(super) async fn verify_with_timeout(
    port: Option<u16>,
    report: Option<&Reporter>,
    timeout: Duration,
) -> Result<()> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(3));
    if let Some(port) = port {
        builder = builder.proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))?);
    }
    check_endpoints(
        builder.build()?,
        &[
            "https://api.ipify.org",
            "https://www.cloudflare.com/cdn-cgi/trace",
        ],
        report,
        if port.is_some() {
            "SOCKS (remote DNS)"
        } else {
            "system routes"
        },
        timeout,
    )
    .await
}
pub(super) async fn check_endpoints(
    client: reqwest::Client,
    urls: &[&str],
    report: Option<&Reporter>,
    route: &str,
    timeout: Duration,
) -> Result<()> {
    let mut jobs = JoinSet::new();
    for url in urls {
        let url = url.to_string();
        let client = client.clone();
        let report = report.cloned();
        let route = route.to_string();
        jobs.spawn(async move {
            let started = std::time::Instant::now();
            if let Some(r) = &report {
                r.event(
                    "INFO",
                    "HEALTH",
                    format!(
                        "Checking {url} via {route}; deadline={}s",
                        timeout.as_secs()
                    ),
                );
            }
            let result = match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => Ok(()),
                Ok(response) => Err(format!("HTTP {}", response.status())),
                Err(error) => Err(request_failure(&error)),
            };
            if let Some(r) = &report {
                r.event(
                    if result.is_ok() { "INFO" } else { "WARN" },
                    "HEALTH",
                    format!(
                        "{url}: {} after {}ms",
                        result
                            .as_ref()
                            .err()
                            .map(String::as_str)
                            .unwrap_or("HTTPS check passed"),
                        started.elapsed().as_millis()
                    ),
                );
            }
            (url, result)
        });
    }
    let mut failures = Vec::new();
    while let Some(result) = jobs.join_next().await {
        match result {
            Ok((_, Ok(()))) => {
                jobs.abort_all();
                while jobs.join_next().await.is_some() {}
                return Ok(());
            }
            Ok((url, Err(reason))) => failures.push(format!("{url}: {reason}")),
            Err(error) => failures.push(format!("probe task failed: {error}")),
        }
    }
    bail!(
        "all HTTPS connectivity checks failed via {route} (deadline {}s per endpoint): {}",
        timeout.as_secs(),
        failures.join("; ")
    )
}
pub(super) fn request_failure(error: &reqwest::Error) -> String {
    use std::error::Error;
    let category = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect/SOCKS/TLS failure"
    } else {
        "request failure"
    };
    let mut details = vec![format!("{category}: {error}")];
    let mut source = error.source();
    while let Some(error) = source {
        details.push(error.to_string());
        source = error.source();
        if details.len() == 8 {
            break;
        }
    }
    details.join(": ")
}
