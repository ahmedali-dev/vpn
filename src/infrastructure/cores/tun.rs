//! Networking core tun service.
//!
//! Generates sing-box capture, DNS, routing and upstream-exclusion settings.

use crate::config::Config;
use serde_json::Value;
use serde_json::json;

pub fn tun_config(c: &Config, excluded: &[String], platform: &str) -> Value {
    let ssh = c.mode() == "ssh";
    let ipv4 = ssh && c.boolean("ssh-ipv4-only");
    let mut inbound = json!({"type":"tun","tag":"device","address":["172.30.111.1/30","fdfe:dcba:9876::1/126"],"mtu":c.number("tun-mtu",1500).unwrap_or(1500),"auto_route":true,"strict_route":true,"route_exclude_address":excluded});
    let settings = crate::tun::Settings::from_config(c).expect("validated TUN settings");
    inbound["address"] = json!(
        settings
            .addresses
            .iter()
            .map(|a| a.cidr())
            .collect::<Vec<_>>()
    );
    if settings.stack != "auto" {
        inbound["stack"] = json!(settings.stack);
    }
    if platform != "macos" {
        inbound["interface_name"] = json!("TunnelNest");
    }
    if platform == "linux" {
        inbound["auto_redirect"] = json!(true);
    }
    let mut outbound = json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":c.socks_port(),"version":"5"});
    let mut rules = vec![json!({"port":53,"action":"hijack-dns"})];
    if c.boolean("block-quic") {
        rules.push(json!({"network":"udp","port":443,"action":"reject"}));
    }
    let policy = c.routing_rules().expect("validated routing rules");
    if policy
        .iter()
        .any(|r| r.kind == crate::routing::Match::Domain)
    {
        rules.insert(
            1,
            json!({"action":"sniff","sniffer":["http","tls","quic"],"timeout":"300ms"}),
        );
    }
    rules.extend(crate::routing::core_rules(&policy, ssh));
    if c.boolean("bypass-lan") {
        rules.push(json!({"ip_is_private":true,"action":"route","outbound":"direct"}));
    }
    if ssh {
        outbound["network"] = json!("tcp");
        rules.push(json!({"network":"udp","action":"reject"}));
    }
    // HTTPS/SVCB records can contain IPv6 hints even when AAAA is filtered.
    // Empty successful answers let clients fall back to ordinary IPv4 DNS.
    let dns_rules = if ipv4 {
        vec![json!({"query_type":["AAAA","HTTPS","SVCB"],"action":"predefined","rcode":"NOERROR"})]
    } else {
        vec![]
    };
    let mut outbounds = vec![outbound];
    if c.boolean("bypass-lan")
        || policy
            .iter()
            .any(|r| r.action == crate::routing::Action::Direct)
    {
        outbounds.push(json!({"type":"direct","tag":"direct"}));
    }
    let mut config = json!({"log":{"level":"info","timestamp":true},"inbounds":[inbound],"outbounds":outbounds,"dns":{"servers":[{"type":"tcp","tag":"tunnel-dns","server":"1.1.1.1","detour":"proxy"}],"rules":dns_rules,"final":"tunnel-dns","strategy":if ipv4{"ipv4_only"}else{"prefer_ipv4"}},"route":{"auto_detect_interface":true,"rules":rules,"final":"proxy"}});
    if !policy.is_empty() {
        config["route"]["default_domain_resolver"] = json!("tunnel-dns");
    }
    if policy
        .iter()
        .any(|r| r.kind == crate::routing::Match::Domain)
    {
        config["dns"]["reverse_mapping"] = json!(true);
    }
    config
}
