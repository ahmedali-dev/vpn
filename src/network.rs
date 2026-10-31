//! Read-only network observations. Never changes routes or sends bypass probes.
use crate::config::{Config, parse_proxy};
use anyhow::{Context, Result};
use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};
use tokio::{process::Command, sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetworkState {
    pub generation: u64,
    pub online: Option<bool>,
}
#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    identity: String,
    online: bool,
}
#[derive(Debug)]
pub struct NetworkChanged;
impl std::fmt::Display for NetworkChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("network changed or system resumed; refreshing transport and upstream routes")
    }
}
impl std::error::Error for NetworkChanged {}

pub struct Task(pub JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn output(program: &str, args: &[&str]) -> Result<String> {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await??;
    anyhow::ensure!(result.status.success(), "network inspection command failed");
    anyhow::ensure!(
        result.stdout.len() <= 262144,
        "network inspection output too large"
    );
    Ok(String::from_utf8(result.stdout)?)
}

#[cfg(target_os = "linux")]
async fn snapshot() -> Result<Snapshot> {
    let v4 = output(
        "ip",
        &["-j", "-4", "route", "show", "table", "main", "default"],
    )
    .await?;
    let v6 = output(
        "ip",
        &["-j", "-6", "route", "show", "table", "main", "default"],
    )
    .await?;
    let addresses = output("ip", &["-j", "address", "show"]).await?;
    linux_snapshot(&v4, &v6, &addresses)
}
#[cfg(any(target_os = "linux", test))]
fn linux_snapshot(v4: &str, v6: &str, addresses: &str) -> Result<Snapshot> {
    let mut routes = serde_json::from_str::<Vec<serde_json::Value>>(v4)?;
    routes.extend(serde_json::from_str::<Vec<serde_json::Value>>(v6)?);
    let devices: Vec<_> = routes.iter().filter_map(|r| r["dev"].as_str()).collect();
    let mut values: Vec<String> = routes
        .iter()
        .map(|r| format!("{}:{}:{}", r["dev"], r["gateway"], r["prefsrc"]))
        .collect();
    for iface in serde_json::from_str::<Vec<serde_json::Value>>(addresses)? {
        if devices.contains(&iface["ifname"].as_str().unwrap_or("")) {
            let mut addresses = Vec::new();
            if let Some(info) = iface["addr_info"].as_array() {
                for address in info {
                    addresses.push(format!(
                        "{}:{}:{}",
                        address["family"], address["local"], address["prefixlen"]
                    ));
                }
            }
            addresses.sort();
            values.push(format!(
                "{}:{}:{}",
                iface["ifname"],
                iface["operstate"],
                addresses.join(",")
            ));
        }
    }
    values.sort();
    Ok(Snapshot {
        online: !routes.is_empty(),
        identity: values.join("|"),
    })
}
#[cfg(target_os = "windows")]
async fn snapshot() -> Result<Snapshot> {
    let data=output("powershell.exe", &["-NoProfile","-NonInteractive","-Command",
        "$ErrorActionPreference='Stop'; ConvertTo-Json -Compress -InputObject @(Get-NetIPConfiguration | Where-Object { ($_.IPv4DefaultGateway -or $_.IPv6DefaultGateway) -and $_.NetAdapter.Status -eq 'Up' -and $_.InterfaceAlias -ne 'TunnelNest' } | Sort-Object InterfaceIndex | Select-Object InterfaceIndex,@{n='address4';e={$_.IPv4Address.IPAddress}},@{n='gateway4';e={$_.IPv4DefaultGateway.NextHop}},@{n='gateway6';e={$_.IPv6DefaultGateway.NextHop}})"]).await?;
    let value: serde_json::Value = serde_json::from_str(&data)?;
    Ok(Snapshot {
        online: !value.is_null() && value.as_array().is_none_or(|v| !v.is_empty()),
        identity: value.to_string(),
    })
}
#[cfg(target_os = "macos")]
async fn snapshot() -> Result<Snapshot> {
    // The physical default interface is stable across sing-box split routes.
    let result = output("/sbin/route", &["-n", "get", "default"]).await;
    match result {
        Ok(data) => {
            let fields: Vec<_> = data
                .lines()
                .filter(|s| {
                    let s = s.trim_start();
                    s.starts_with("gateway:") || s.starts_with("interface:")
                })
                .map(str::trim)
                .collect();
            Ok(Snapshot {
                online: !fields.is_empty(),
                identity: fields.join("|"),
            })
        }
        Err(error) => {
            if output("/sbin/ifconfig", &["-l"]).await.is_err() {
                return Err(error);
            }
            Ok(Snapshot {
                online: false,
                identity: String::new(),
            })
        }
    }
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn snapshot() -> Result<Snapshot> {
    anyhow::bail!("network inspection unsupported")
}

pub fn targets(config: &Config) -> Result<Vec<(String, u16)>> {
    let mut targets = Vec::new();
    if config.mode() == "ssh" {
        targets.push((config.get("H", "").into(), config.number("P", 0)? as u16));
    } else if config.get("v2ray-config", "").is_empty() {
        let p = config.protocol()?;
        targets.push((p.address, p.port as u16));
    }
    if !config.get("proxy", "").is_empty() {
        let p = parse_proxy(config.get("proxy", ""))?;
        targets.push((
            p.host_str()
                .context("proxy host missing")?
                .trim_matches(['[', ']'])
                .into(),
            p.port_or_known_default().context("proxy port missing")?,
        ));
    }
    Ok(targets)
}
async fn dns(targets: &[(String, u16)]) -> Result<Vec<IpAddr>> {
    let mut result = Vec::new();
    for (host, port) in targets {
        result.extend(
            tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), *port)),
            )
            .await??
            .map(|a| a.ip()),
        );
    }
    result.sort();
    result.dedup();
    Ok(result)
}

#[derive(Default)]
struct Changes {
    current: Option<Snapshot>,
    candidate: Option<Snapshot>,
    last_dns: Option<Vec<IpAddr>>,
}
impl Changes {
    fn observe(&mut self, value: Snapshot) -> bool {
        if self.current.is_none() {
            self.current = Some(value);
            return false;
        }
        if self.current.as_ref() == Some(&value) {
            self.candidate = None;
            return false;
        }
        if self.candidate.as_ref() == Some(&value) {
            self.current = Some(value);
            self.candidate = None;
            return true;
        }
        self.candidate = Some(value);
        false
    }
    fn dns_changed(&mut self, value: Vec<IpAddr>) -> bool {
        // A pool may add/rotate records while the current connection is healthy.
        // Reconnect proactively only after every previously observed address is gone.
        let changed = self.last_dns.as_ref().is_some_and(|old| {
            !old.is_empty() && !value.is_empty() && !old.iter().any(|ip| value.contains(ip))
        });
        if self.last_dns.is_none() || changed {
            self.last_dns = Some(value);
        }
        changed
    }
}

pub fn watch_network(
    config: &Config,
    cancel: CancellationToken,
    r: crate::runtime::Reporter,
) -> Result<(Task, watch::Receiver<NetworkState>)> {
    let targets = targets(config)?;
    let (tx, rx) = watch::channel(NetworkState::default());
    let task = tokio::spawn(async move {
        let mut changes = Changes::default();
        let mut last = SystemTime::now();
        let mut ticks = 0u32;
        let mut inspection_warning = false;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=cancel.cancelled()=>return,_=interval.tick()=>()}
            let now = SystemTime::now();
            let resumed = now.duration_since(last).unwrap_or_default() > Duration::from_secs(20);
            let observed = tokio::select! {_=cancel.cancelled()=>return,s=snapshot()=>s};
            let mut changed = resumed;
            if let Ok(value) = observed {
                changed |= changes.observe(value);
            } else if !inspection_warning {
                inspection_warning = true;
                r.event("WARN","NETWORK","Physical network inspection unavailable; continuing with transport/health recovery");
            }
            if ticks.is_multiple_of(12) {
                let resolved = tokio::select! {_=cancel.cancelled()=>return,d=dns(&targets)=>d};
                if let Ok(addresses) = resolved {
                    changed |= changes.dns_changed(addresses);
                }
            }
            ticks = ticks.wrapping_add(1);
            let online = changes.current.as_ref().map(|s| s.online);
            if changed {
                r.event(
                    "INFO",
                    "NETWORK",
                    if resumed {
                        "System wake or long scheduling pause detected"
                    } else {
                        "Physical network or upstream DNS addresses changed"
                    },
                );
            }
            tx.send_modify(|state| {
                if changed {
                    state.generation = state.generation.wrapping_add(1);
                }
                state.online = online;
            });
            last = SystemTime::now();
        }
    });
    Ok((Task(task), rx))
}

/// Cancel an attempt without dropping its cleanup future.
pub fn interrupt_on_change(
    mut state: watch::Receiver<NetworkState>,
    token: CancellationToken,
) -> Task {
    let baseline = state.borrow_and_update().generation;
    Task(tokio::spawn(async move {
        loop {
            tokio::select! {_=token.cancelled()=>return,s=state.changed()=>if s.is_err(){return;}}
            if state.borrow().generation != baseline {
                token.cancel();
                return;
            }
        }
    }))
}

#[derive(Clone, Debug)]
pub struct InterfaceAddress {
    pub name: String,
    pub ip: IpAddr,
    pub prefix: u8,
}
#[cfg(unix)]
pub async fn interface_addresses() -> Result<Vec<InterfaceAddress>> {
    let mut ptr = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ptr) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _guard = Guard(ptr);
    let mut item = ptr;
    let mut result = vec![];
    while !item.is_null() {
        let addr = unsafe { &*item };
        if !addr.ifa_addr.is_null() && !addr.ifa_name.is_null() {
            let family = unsafe { (*addr.ifa_addr).sa_family } as i32;
            let pair = match family {
                libc::AF_INET => {
                    let v = unsafe { &*(addr.ifa_addr as *const libc::sockaddr_in) };
                    let prefix = if addr.ifa_netmask.is_null() {
                        32
                    } else {
                        unsafe { &*(addr.ifa_netmask as *const libc::sockaddr_in) }
                            .sin_addr
                            .s_addr
                            .count_ones() as u8
                    };
                    Some((IpAddr::from(v.sin_addr.s_addr.to_ne_bytes()), prefix))
                }
                libc::AF_INET6 => {
                    let v = unsafe { &*(addr.ifa_addr as *const libc::sockaddr_in6) };
                    let prefix = if addr.ifa_netmask.is_null() {
                        128
                    } else {
                        unsafe { &*(addr.ifa_netmask as *const libc::sockaddr_in6) }
                            .sin6_addr
                            .s6_addr
                            .iter()
                            .map(|b| b.count_ones() as u8)
                            .sum()
                    };
                    Some((IpAddr::from(v.sin6_addr.s6_addr), prefix))
                }
                _ => None,
            };
            if let Some((ip, prefix)) = pair {
                result.push(InterfaceAddress {
                    name: unsafe { std::ffi::CStr::from_ptr(addr.ifa_name) }
                        .to_string_lossy()
                        .into_owned(),
                    ip,
                    prefix,
                });
            }
        }
        item = addr.ifa_next;
    }
    Ok(result)
}
#[cfg(windows)]
pub async fn interface_addresses() -> Result<Vec<InterfaceAddress>> {
    let text=output("powershell.exe",&["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; ConvertTo-Json -Compress -InputObject @(Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength)"]).await?;
    let rows: Vec<serde_json::Value> = serde_json::from_str(&text)?;
    rows.iter()
        .map(|v| {
            Ok(InterfaceAddress {
                name: v["InterfaceAlias"]
                    .as_str()
                    .context("missing interface alias")?
                    .into(),
                ip: v["IPAddress"]
                    .as_str()
                    .context("missing address")?
                    .split('%')
                    .next()
                    .unwrap_or_default()
                    .parse()?,
                prefix: v["PrefixLength"].as_u64().context("missing prefix")? as u8,
            })
        })
        .collect()
}
#[cfg(not(any(unix, windows)))]
pub async fn interface_addresses() -> Result<Vec<InterfaceAddress>> {
    anyhow::bail!("interface inspection unsupported")
}
pub async fn tun_interface_for(ips: &[IpAddr]) -> Result<Option<String>> {
    Ok(interface_addresses()
        .await?
        .into_iter()
        .find(|a| ips.contains(&a.ip))
        .map(|a| a.name))
}
pub async fn tun_interface() -> Result<Option<String>> {
    tun_interface_for(&crate::tun::Settings::from_config(&Config::default())?.ips()).await
}
pub async fn tun_present() -> Result<bool> {
    Ok(tun_interface().await?.is_some())
}
pub fn tun_conflict(
    settings: &crate::tun::Settings,
    addresses: &[InterfaceAddress],
) -> Option<String> {
    addresses
        .iter()
        .find(|a| {
            settings
                .addresses
                .iter()
                .any(|target| target.overlaps(a.ip, a.prefix))
        })
        .map(|a| a.name.clone())
}
/// Require capture routes, not just the connected virtual-address subnet.
pub async fn tun_capture_routes_present(interface: &str, excluded: &[String]) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let mut prefixes = vec![];
        for (family, default) in [("-4", "0.0.0.0/0"), ("-6", "::/0")] {
            let data = output("ip", &["-j", family, "route", "show", "table", "all"]).await?;
            let rows: Vec<serde_json::Value> = serde_json::from_str(&data)?;
            for row in rows {
                if row["dev"].as_str() == Some(interface)
                    && let Some(dst) = row["dst"].as_str()
                {
                    prefixes.push(if dst == "default" {
                        default.to_owned()
                    } else {
                        dst.to_owned()
                    });
                }
            }
        }
        Ok(capture_prefixes(&prefixes, excluded))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(macos_capture_routes(
            &output("/usr/sbin/netstat", &["-rn"]).await?,
            interface,
            excluded,
        ))
    }
    #[cfg(windows)]
    {
        let data = output("powershell.exe", &["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; ConvertTo-Json -Compress -InputObject @(Get-NetRoute | Select-Object InterfaceAlias,DestinationPrefix)"]).await?;
        let rows: Vec<serde_json::Value> = serde_json::from_str(&data)?;
        let prefixes = rows
            .iter()
            .filter(|r| r["InterfaceAlias"].as_str() == Some(interface))
            .filter_map(|r| r["DestinationPrefix"].as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        Ok(capture_prefixes(&prefixes, excluded))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        anyhow::bail!("capture route inspection unsupported")
    }
}
// sing-tun may split default ranges around upstream exclusions. Compare their
// union rather than requiring literal /0 routes. macOS omits 0/8 and ::/8.
fn capture_prefixes(prefixes: &[String], excluded: &[String]) -> bool {
    let ranges = prefixes
        .iter()
        .chain(excluded)
        .filter_map(|v| route_interval(v))
        .collect::<Vec<_>>();
    for (v4, first, last) in [
        (true, 1u128 << 24, u32::MAX as u128),
        (false, 1u128 << 120, u128::MAX),
    ] {
        let mut family = ranges
            .iter()
            .filter(|r| r.0 == v4)
            .map(|r| (r.1, r.2))
            .collect::<Vec<_>>();
        family.sort_unstable();
        let mut next = first;
        let mut complete = false;
        for (start, end) in family {
            if end < next {
                continue;
            }
            if start > next {
                break;
            }
            if end >= last {
                complete = true;
                break;
            }
            next = end + 1;
        }
        if !complete {
            return false;
        }
    }
    true
}
fn route_interval(text: &str) -> Option<(bool, u128, u128)> {
    let (host, prefix) = text
        .split_once('/')
        .map(|(h, p)| (h, Some(p)))
        .unwrap_or((text, None));
    let mut host = host.split('%').next()?.to_owned();
    let v4 = !host.contains(':');
    let implicit = if v4 {
        host.split('.').count() as u8 * 8
    } else {
        128
    };
    if v4 {
        while host.split('.').count() < 4 {
            host.push_str(".0");
        }
    }
    let ip: IpAddr = host.parse().ok()?;
    let bits = if v4 { 32 } else { 128 };
    let prefix: u8 = prefix.map(str::parse).transpose().ok()?.unwrap_or(implicit);
    if prefix > bits {
        return None;
    }
    let host_bits = bits - prefix;
    let mask = if host_bits == 128 {
        u128::MAX
    } else if host_bits == 0 {
        0
    } else {
        u128::MAX >> (128 - host_bits)
    };
    let number = match ip {
        IpAddr::V4(v) => u32::from(v) as u128,
        IpAddr::V6(v) => u128::from(v),
    };
    let start = number & !mask;
    let last = if v4 { u32::MAX as u128 } else { u128::MAX };
    Some((v4, start, (start | mask).min(last)))
}
#[cfg(any(target_os = "macos", test))]
fn macos_capture_routes(table: &str, interface: &str, excluded: &[String]) -> bool {
    let mut v6 = false;
    let mut prefixes = vec![];
    for line in table.lines() {
        if line.trim() == "Internet6:" {
            v6 = true;
        }
        if line.trim() == "Internet:" {
            v6 = false;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if !fields.contains(&interface) {
            continue;
        }
        if let Some(dst) = fields.first() {
            prefixes.push(
                match *dst {
                    "default" if v6 => "::/0",
                    "default" => "0.0.0.0/0",
                    "0/1" | "0.0/1" => "0.0.0.0/1",
                    "128/1" | "128.0/1" => "128.0.0.0/1",
                    other => other,
                }
                .to_owned(),
            );
        }
    }
    capture_prefixes(&prefixes, excluded)
}
/// Read-only cleanup check. Never removes routes owned by another VPN.
pub async fn tun_routes_present(interface: &str) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        for family in ["-4", "-6"] {
            let data = output("ip", &["-j", family, "route", "show", "table", "all"]).await?;
            let routes: Vec<serde_json::Value> = serde_json::from_str(&data)?;
            if routes.iter().any(|v| v["dev"].as_str() == Some(interface)) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(route_table_mentions(
            &output("/usr/sbin/netstat", &["-rn"]).await?,
            interface,
        ))
    }
    #[cfg(windows)]
    {
        // Read JSON and compare locally; the interface name is never interpolated into PowerShell.
        let data=output("powershell.exe", &["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; ConvertTo-Json -Compress -InputObject @(Get-NetRoute | Select-Object -ExpandProperty InterfaceAlias)"]).await?;
        let routes: Vec<String> = serde_json::from_str(&data)?;
        Ok(routes.iter().any(|v| v == interface))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        anyhow::bail!("route cleanup inspection unsupported")
    }
}
#[cfg(any(target_os = "macos", test))]
fn route_table_mentions(table: &str, interface: &str) -> bool {
    table
        .lines()
        .any(|line| line.split_whitespace().any(|field| field == interface))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_changes_require_two_observations_and_ignore_tun_routes() {
        let mut c = Changes::default();
        let a = Snapshot {
            identity: "wifi".into(),
            online: true,
        };
        let b = Snapshot {
            identity: "ethernet".into(),
            online: true,
        };
        assert!(!c.observe(a.clone()));
        assert!(!c.observe(b.clone()));
        assert!(!c.observe(a));
        assert!(!c.observe(b.clone()));
        assert!(c.observe(b));
        let first = linux_snapshot(
            r#"[{"dev":"eth0","gateway":"192.0.2.1"}]"#,
            "[]",
            r#"[{"ifname":"eth0","operstate":"UP","addr_info":[{"local":"192.0.2.2"}]}]"#,
        )
        .unwrap();
        let with_tun=linux_snapshot(r#"[{"dev":"eth0","gateway":"192.0.2.1"}]"#,"[]",r#"[{"ifname":"eth0","operstate":"UP","addr_info":[{"local":"192.0.2.2"}]},{"ifname":"tun0","addr_info":[{"local":"172.30.111.1"}]}]"#).unwrap();
        assert_eq!(first, with_tun);
        let renewing=linux_snapshot(r#"[{"dev":"eth0","gateway":"192.0.2.1"}]"#,"[]",r#"[{"ifname":"eth0","operstate":"UP","addr_info":[{"local":"192.0.2.2","valid_life_time":60}]}]"#).unwrap();
        assert_eq!(first, renewing);
        assert!(!linux_snapshot("[]", "[]", "[]").unwrap().online);
    }
    #[test]
    fn dns_change_preserves_first_observation() {
        let mut c = Changes::default();
        let ip = "192.0.2.1".parse().unwrap();
        assert!(!c.dns_changed(vec![ip]));
        assert!(!c.dns_changed(vec![ip]));
        let other = "192.0.2.2".parse().unwrap();
        assert!(
            !c.dns_changed(vec![ip, other]),
            "overlapping DNS pools should not restart a healthy transport"
        );
        assert!(c.dns_changed(vec![other]));
    }
    #[tokio::test]
    async fn interruption_signals_cleanup_instead_of_aborting_it() {
        let (tx, rx) = watch::channel(NetworkState::default());
        let token = CancellationToken::new();
        let _task = interrupt_on_change(rx, token.clone());
        tx.send_modify(|s| s.online = Some(true));
        tokio::task::yield_now().await;
        assert!(!token.is_cancelled());
        tx.send_modify(|s| s.generation += 1);
        tokio::time::timeout(Duration::from_secs(1), token.cancelled())
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod route_cleanup_tests {
    use super::*;
    #[test]
    fn route_detection_matches_the_owned_interface_exactly() {
        let routes = "Destination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGSc en0\n0/1 172.30.111.1 UGSc utun9\n::/1 link#20 UGc utun9";
        assert!(route_table_mentions(routes, "utun9"));
        assert!(!route_table_mentions(routes, "utun"));
        assert!(!route_table_mentions("default 192.0.2.1 UGSc en0", "utun9"));
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    #[test]
    fn connected_subnets_and_other_interfaces_do_not_verify_capture() {
        let routes = "Internet:\n172.30.111/30 link#20 Uc utun9\nInternet6:\nfdfe:dcba:9876::/126 link#20 Uc utun9";
        assert!(!macos_capture_routes(routes, "utun9", &[]));
        let routes = format!(
            "{routes}\nInternet:\n0/1 link#20 Uc utun9\n128.0/1 link#20 Uc utun9\nInternet6:\n::/1 link#20 Uc utun9\n8000::/1 link#20 Uc utun9"
        );
        assert!(macos_capture_routes(&routes, "utun9", &[]));
        assert!(!macos_capture_routes(&routes, "utun8", &[]));
        assert!(!capture_prefixes(&["0.0.0.0/0".into()], &[]));
        assert!(capture_prefixes(&["0.0.0.0/0".into(), "::/0".into()], &[]));
    }
}

#[cfg(test)]
mod split_capture_tests {
    use super::*;
    #[test]
    fn split_capture_ranges_allow_only_the_declared_upstream_holes() {
        let prefixes = [
            "1/8", "2/7", "4/6", "8/5", "16/4", "32/3", "64/2", "128/1", "100::/8", "200::/7",
            "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2", "8000::/1",
        ]
        .map(str::to_owned)
        .to_vec();
        assert!(capture_prefixes(&prefixes, &[]));
        let without_first = prefixes[1..].to_vec();
        assert!(!capture_prefixes(&without_first, &[]));
        // Model a split around one upstream IPv4 host without creating any routes.
        let mut ranges = (1..=32)
            .map(|prefix| {
                let address =
                    std::net::Ipv4Addr::from(u32::MAX.checked_shl(33 - prefix).unwrap_or(0));
                format!("{address}/{prefix}")
            })
            .collect::<Vec<_>>();
        ranges.push("::/0".into());
        assert!(!capture_prefixes(&ranges, &[]));
        assert!(capture_prefixes(&ranges, &["255.255.255.255/32".into()]));
    }
}
