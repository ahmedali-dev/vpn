//! Connection preparation service
//!
//! Resolves upstream endpoints and validates route exclusions before networking starts.

use super::status::Reporter;
use crate::config::Config;
use crate::config::parse_proxy;
use crate::transport;
use anyhow::Result;
use anyhow::ensure;
use std::time::Duration;
use tokio::net::lookup_host;

pub(super) async fn prepare(c: &mut Config, r: &Reporter) -> Result<Vec<String>> {
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
