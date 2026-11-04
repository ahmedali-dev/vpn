//! Single connection attempt service
//!
//! Owns ordered startup, verified readiness, monitoring and cleanup for SSH or Xray plus optional TUN.

use super::core_logs::capture;
use super::forwarding::socks_server;
use super::health::exit_ip;
use super::health::finish_core_logs;
use super::health::has_split_policy;
use super::health::matching_exit;
use super::health::monitor_connection;
use super::health::startup_work;
use super::health::verify_policy_routes;
use super::health::verify_system_dns;
use super::health::verify_with_timeout;
use super::health::wait_ready;
use super::pac::pac_server;
use super::status::Reporter;
use crate::config::Config;
use crate::core::CoreProcess;
use crate::core::find_core;
use crate::core::tun_config;
use crate::core::xray_config;
use crate::transport;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(super) async fn run_once(
    c: &Config,
    excluded: &[String],
    pin: Option<&str>,
    cancel: CancellationToken,
    r: Reporter,
    tofu_key: Arc<Mutex<Option<String>>>,
    connected_for: &mut Duration,
) -> Result<()> {
    let health_timeout = c.health_timeout();
    let device_settings = crate::tun::Settings::from_config(c)?;
    let device_ips = device_settings.ips();
    let split_policy = has_split_policy(c)?;
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
    let mut log_jobs = JoinSet::new();
    let mut core = None;
    let mut ssh = None;
    let mut tun = None;
    let mut tun_started = false;
    let observed_interface: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut connected_at = None;
    let outcome=async {
    if c.mode()=="ssh" {
        let handle=Arc::new(tokio::select!{_=cancel.cancelled()=>return Ok(()),s=r.stage("SSH transport and authentication", transport::connect_ssh_logged(c,pin,tofu_key,r.clone()))=>s?});ssh=Some(handle.clone());
        jobs.spawn(socks_server(listener,handle,c.number("max-conns",2000)? as usize,c.boolean("ssh-ipv4-only"),cancel.clone(),r.clone(),Duration::from_secs(c.number("ssh-channel-timeout",30)? as u64)));
    }else {
        drop(listener);
        let names=if c.mode()=="v2ray"{vec!["v2ray","xray"]}else{vec!["xray"]};
        let binary=find_core(c.get("v2ray-binary",""),&names)?;
        let generated=if c.get("v2ray-config","").is_empty(){Some(xray_config(c,&c.protocol()?,pin))}else{None};
        let mut p=tokio::select!{_=cancel.cancelled()=>return Ok(()),p=r.stage("Core startup", CoreProcess::start(binary,generated,c.get("v2ray-config",""),false))=>p?};r.event("INFO","CORE",format!("Started core; PID={:?}",p.child().id()));r.core_version("proxy",&p);capture(&mut p,&r,&mut log_jobs,"CORE");core=Some(p);
        let ready=wait_ready(cancel.clone(),Duration::from_secs(c.number("startup-timeout",30)? as u64),
            ||core.as_mut().unwrap().check_running("core during startup"),
            ||async {Ok(TcpStream::connect(("127.0.0.1",c.socks_port())).await.is_ok())}).await?;
        if !ready {return Ok(());}

    }
    r.state("verifying");
    let verified = startup_work(cancel.clone(), || {
        if let Some(p)=core.as_mut(){p.check_running("core during verification")?;}
        if let Some(s)=&ssh {ensure!(!s.is_closed(), "SSH session closed during verification");}
        Ok(())
    },r.stage("Proxy verification", verify_with_timeout(Some(c.socks_port()),Some(&r),health_timeout))).await?;
    if verified.is_none(){return Ok(());}
    r.0.lock().unwrap().checks["proxyHttps"]=json!("passed");
    r.log("[+] HTTPS traffic verified through SOCKS");
    let expected_exit=if c.tun()&&!split_policy{
        let value=startup_work(cancel.clone(),||{
            if let Some(p)=core.as_mut(){p.check_running("core during exit verification")?;}
            if let Some(s)=&ssh{ensure!(!s.is_closed(),"SSH session closed during exit verification");}
            Ok(())
        },exit_ip(Some(c.socks_port()),health_timeout)).await.context("could not determine proxy IPv4 exit")?;
        if value.is_none(){return Ok(());}value
    }else{None};
    if c.tun(){
        if let Some(name)=crate::network::tun_conflict(&device_settings,&crate::network::interface_addresses().await?) {
            return Err(anyhow::anyhow!("Configured TUN subnet overlaps interface {name}; choose unused private TUN addresses").context(crate::recovery::PermanentFailure::Configuration));
        }
        for route in excluded {
            if let Some(ip)=route.split('/').next().and_then(|v|v.parse::<IpAddr>().ok())
                && device_settings.addresses.iter().any(|a|a.overlaps(ip,if ip.is_ipv4(){32}else{128})) {
                return Err(anyhow::anyhow!("Configured TUN subnet overlaps an upstream server; choose unused private TUN addresses").context(crate::recovery::PermanentFailure::Configuration));
            }
        }
        r.event("INFO","TUN",format!("Virtual addresses: {}; stack={}",device_settings.addresses.iter().map(|a|a.cidr()).collect::<Vec<_>>().join(", "),device_settings.stack));
        if c.mode()=="ssh" && c.boolean("ssh-ipv4-only") {
            r.event("INFO","TUN","IPv4 compatibility: filtering AAAA/HTTPS/SVCB DNS responses; cached IPv6 TLS/HTTP destinations use hostname recovery; other IPv6 traffic stays blocked. SSH carries TCP; UDP applications are unsupported.");
        }
        let mut p=tokio::select!{_=cancel.cancelled()=>return Ok(()),p=r.stage("TUN startup", CoreProcess::start(find_core(c.get("tun-binary",""),&["sing-box"] )?,Some(tun_config(c,excluded,std::env::consts::OS)),"",true))=>p?};
        r.event("INFO","TUN",format!("Starting sing-box; PID={:?}; excluded upstream routes={}",p.child().id(),excluded.len()));r.core_version("tun",&p);capture(&mut p,&r,&mut log_jobs,"TUN");tun=Some(p);tun_started=true;
        let ready=r.stage("TUN interface and route readiness",wait_ready(cancel.clone(),
            Duration::from_secs(c.number("startup-timeout",30)? as u64),
            ||{
                tun.as_mut().unwrap().check_running("TUN during startup")?;
                if let Some(p)=core.as_mut(){p.check_running("core during TUN startup")?;}
                if let Some(s)=&ssh{ensure!(!s.is_closed(),"SSH session closed during TUN startup");}
                Ok(())
            },
            ||async {
                match crate::network::tun_interface_for(&device_ips).await? {Some(name)=>*observed_interface.lock().unwrap()=Some(name),None=>return Ok(false)}
                verify_system_dns(health_timeout).await?;
                r.0.lock().unwrap().checks["systemDns"]=json!("passed");
                if split_policy {
                    verify_policy_routes(&device_ips, excluded).await?;
                    r.0.lock().unwrap().checks["systemIpv4"]=json!("policy_not_compared");
                    r.event("INFO","TUN","Split routing policy verified: proxy HTTPS, system DNS and owned TUN routes checked; system exit may intentionally differ");
                } else {
                    let actual=exit_ip(None,health_timeout).await?;
                    matching_exit(expected_exit.unwrap(),actual)?;
                    r.0.lock().unwrap().checks["systemIpv4"]=json!("passed");
                    r.event("INFO","TUN",format!("System DNS works and IPv4 exit {actual} matches verified proxy exit; IPv6 is not independently verified"));
                }
                Ok(true)
            })).await?;
        if !ready {return Ok(());}
        r.log("[+] Full-device routing verified");
    }
    connected_at=Some(std::time::Instant::now());
    r.connected();
    let port=c.socks_port(); let full_device=c.tun();
    monitor_connection(cancel.clone(), r.clone(),
                || {
                if let Some(p)=core.as_mut(){p.check_running("core")?;}
                if let Some(p)=tun.as_mut(){p.check_running("TUN")?;}
                if let Some(s)=&ssh&& s.is_closed(){return Err(anyhow::anyhow!("SSH session closed"))}
                    Ok(())
                },
                || {
                    let report=r.clone();
                    let probe_ips=device_ips.clone();
                    let probe_excluded=excluded.to_vec();
                    async move {
                        if full_device {
                            verify_system_dns(health_timeout).await?;
                            if split_policy {
                                verify_with_timeout(Some(port),Some(&report),health_timeout).await?;
                                verify_policy_routes(&probe_ips, &probe_excluded).await?;
                                report.event("INFO","HEALTH","Split-policy health passed: profile HTTPS, DNS and owned TUN routes");
                            } else {
                                let proxy=exit_ip(Some(port),health_timeout).await.context("proxy exit check failed")?;
                                let system=exit_ip(None,health_timeout).await.context("system exit check failed")?;
                                matching_exit(proxy,system)?;
                                report.event("INFO","HEALTH",format!("Proxy and system IPv4 exits match: {system}"));
                            }
                            Ok(())
                        }else{verify_with_timeout(Some(port),Some(&report),health_timeout).await.context("proxy health check failed")}
                    }
                }, Duration::from_secs(1), Duration::from_secs(30)).await
    }.await;
    *connected_for = connected_at
        .map(|at: std::time::Instant| at.elapsed())
        .unwrap_or_default();
    let owned_interface = if tun_started {
        match crate::network::tun_interface_for(&device_ips).await {
            Ok(None) => Ok(observed_interface.lock().unwrap().clone()),
            other => other,
        }
    } else {
        Ok(None)
    };
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
    finish_core_logs(&mut log_jobs, &r).await;
    let mut cleanup_verified = true;
    if tun_started {
        // Allow asynchronous adapter removal, but never delete another app's routes.
        let check = async {
            for _ in 0..10 {
                if crate::network::tun_interface_for(&device_ips)
                    .await?
                    .is_none()
                {
                    if let Ok(Some(interface)) = &owned_interface {
                        if crate::network::tun_routes_present(interface).await? {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    } else if owned_interface.is_err() {
                        return Ok(false);
                    }
                    return Ok::<_, anyhow::Error>(true);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(false)
        };
        let removed = matches!(
            tokio::time::timeout(Duration::from_secs(4), check).await,
            Ok(Ok(true))
        );
        cleanup_verified = removed;
        r.0.lock().unwrap().recovery["tunCleanupVerified"] = json!(removed);
        r.event(if removed {"INFO"}else{"WARN"},"CLEANUP",if removed {"TUN interface and owned route removal verified"} else {"TUN cleanup could not be verified; inspect remaining adapter/routes before reconnecting"});
    }
    r.event(
        "INFO",
        "CLEANUP",
        "Stopped networking processes and forwarding tasks; temporary configs released",
    );
    if !cleanup_verified {
        return Err(anyhow::anyhow!(
            "TUN cleanup could not be verified; refusing to install a new set of routes"
        )
        .context(crate::recovery::PermanentFailure::Configuration)
        .context(crate::recovery::FailureCategory::Cleanup));
    }
    outcome
}
// Processes are stopped first; allow their stdout/stderr readers to reach EOF.
