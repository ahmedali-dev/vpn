//! Portable full-device connection routing. DNS interception has higher priority.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Match {
    Domain,
    Ip,
    Process,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Direct,
    Proxy,
    Block,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub kind: Match,
    pub value: String,
    pub action: Action,
}

pub fn parse(text: &str) -> Result<Vec<Rule>> {
    ensure!(text.len() <= 8192, "routing rules exceed 8192 bytes");
    let mut rules: Vec<Rule> = serde_json::from_str(text)?;
    ensure!(rules.len() <= 64, "at most 64 routing rules are allowed");
    for rule in &mut rules {
        rule.value = rule.value.trim().to_owned();
        ensure!(
            !rule.value.is_empty()
                && rule.value.len() <= 253
                && !rule.value.chars().any(char::is_control),
            "invalid routing rule value"
        );
        match rule.kind {
            Match::Domain => {
                rule.value = rule.value.trim_end_matches('.').to_ascii_lowercase();
                ensure!(
                    rule.value.parse::<IpAddr>().is_err()
                        && rule.value.split('.').all(|s| !s.is_empty()
                            && s.len() <= 63
                            && !s.starts_with('-')
                            && !s.ends_with('-')
                            && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')),
                    "use a domain name without a URL, wildcard, or port"
                );
            }
            Match::Ip => {
                let (ip, prefix) = rule
                    .value
                    .split_once('/')
                    .map_or((rule.value.as_str(), None), |(ip, p)| (ip, Some(p)));
                let ip: IpAddr = ip.parse()?;
                let bits = if ip.is_ipv4() { 32 } else { 128 };
                let prefix = prefix.map(str::parse::<u8>).transpose()?.unwrap_or(bits);
                ensure!(prefix <= bits, "invalid IP prefix length");
                rule.value = format!("{ip}/{prefix}");
            }
            Match::Process => ensure!(
                !rule.value.contains(['/', '\\']) && rule.value.len() <= 128,
                "use an application process name, such as firefox.exe or curl"
            ),
        }
    }
    Ok(rules)
}
pub fn core_rules(rules: &[Rule], ssh: bool) -> Vec<Value> {
    let mut result = vec![];
    for rule in rules {
        let key = match rule.kind {
            Match::Domain => "domain_suffix",
            Match::Ip => "ip_cidr",
            Match::Process => "process_name",
        };
        let mut matcher = json!({});
        matcher[key] = json!([rule.value]);
        // SSH cannot carry UDP through SOCKS; an explicit proxy rule must not evade this restriction.
        if ssh && rule.action == Action::Proxy {
            result.push(json!({"type":"logical","mode":"and","rules":[matcher.clone(),{"network":"udp"}],"action":"reject"}));
        }
        matcher["action"] = json!(if rule.action == Action::Block {
            "reject"
        } else {
            "route"
        });
        if rule.action != Action::Block {
            matcher["outbound"] = json!(if rule.action == Action::Direct {
                "direct"
            } else {
                "proxy"
            });
        }
        result.push(matcher);
    }
    result
}
