//! Connection configuration feature.
//!
//! Validates CLI/profile options before any connection or route change. Protocol parsing lives in protocols.rs.

use anyhow::{Result, ensure};
use std::collections::HashMap;
use url::Url;

pub const BOOL_FLAGS: &[&str] = &[
    "tun",
    "auto-route",
    "ui",
    "ui-helper",
    "ui-no-browser",
    "ssh-trust-on-first-use",
    "ssh-ipv4-only",
    "block-quic",
    "bypass-lan",
];
pub const VALUE_FLAGS: &[&str] = &[
    "routing-rules",
    "tun-address4",
    "tun-address6",
    "tun-stack",
    "mode",
    "H",
    "P",
    "u",
    "p",
    "S",
    "socks-port",
    "pac-port",
    "max-conns",
    "ssh-connect-timeout",
    "ssh-handshake-timeout",
    "ssh-channel-timeout",
    "ssh-keepalive-interval",
    "ssh-keepalive-max",
    "ssh-inactivity-timeout",
    "tun-mtu",
    "startup-timeout",
    "health-timeout",
    "tls-version",
    "ssh-host-key",
    "ssh-known-hosts",
    "ssh-cert-sha256",
    "tls-ca",
    "proxy",
    "payload-file",
    "payload-stage",
    "v2ray-link",
    "v2ray-sni",
    "v2ray-cert-sha256",
    "v2ray-protocol",
    "v2ray-uuid",
    "v2ray-addr",
    "v2ray-port",
    "v2ray-network",
    "v2ray-security",
    "v2ray-path",
    "v2ray-host",
    "v2ray-service",
    "v2ray-config",
    "v2ray-binary",
    "tun-binary",
    "ui-port",
    "ui-ready-file",
    "ui-helper-address-file",
];

#[derive(Clone, Default)]
pub struct Config {
    pub flags: HashMap<String, String>,
}
impl Config {
    pub fn parse(args: &[String]) -> Result<Self> {
        ensure!(args.len() <= 256, "too many arguments");
        let mut flags = HashMap::new();
        let mut i = 0;
        while i < args.len() {
            ensure!(args[i].starts_with('-'), "unexpected positional argument");
            let raw = args[i].trim_start_matches('-');
            let (key, inline) = raw
                .split_once('=')
                .map_or((raw, None), |(k, v)| (k, Some(v)));
            let value = if BOOL_FLAGS.contains(&key) {
                let v = inline.unwrap_or("true");
                ensure!(["true", "false"].contains(&v), "invalid boolean for {key}");
                v.to_owned()
            } else {
                ensure!(VALUE_FLAGS.contains(&key), "unknown option: -{key}");
                match inline {
                    Some(v) => v.to_owned(),
                    None => {
                        i += 1;
                        args.get(i)
                            .ok_or_else(|| anyhow::anyhow!("missing value for -{key}"))?
                            .clone()
                    }
                }
            };
            ensure!(
                value.len() <= 65536 && !value.contains('\0'),
                "invalid option value"
            );
            flags.insert(key.to_owned(), value);
            i += 1;
        }
        let c = Self { flags };
        ensure!(
            ["ssh", "xray", "v2ray"].contains(&c.mode()),
            "mode must be ssh, xray, or v2ray"
        );
        for (key, default, zero) in [
            ("socks-port", 1080, false),
            ("pac-port", 0, true),
            ("ui-port", 0, true),
        ] {
            let n = c.number(key, default)?;
            ensure!(n <= 65535 && (zero || n > 0), "invalid {key}");
        }
        ensure!(
            c.number("max-conns", 2000)? > 0 && c.number("max-conns", 2000)? <= 65536,
            "invalid max-conns"
        );
        ensure!(
            c.number("pac-port", 0)? == 0
                || c.number("pac-port", 0)? != c.number("socks-port", 1080)?,
            "PAC and SOCKS ports must differ"
        );
        ensure!(
            ["auto", "tls1.2", "tls1.3"].contains(&c.get("tls-version", "auto")),
            "invalid TLS version"
        );
        ensure!(
            ["before-tls", "after-tls"].contains(&c.get("payload-stage", "before-tls")),
            "invalid payload stage"
        );
        for key in ["ssh-cert-sha256", "v2ray-cert-sha256"] {
            let v = c.get(key, "auto");
            ensure!(
                ["auto", "none", "insecure"].contains(&v)
                    || hex::decode(v).is_ok_and(|x| x.len() == 32),
                "invalid certificate SHA256 pin"
            );
        }
        for (key, default, minimum, maximum) in [
            ("ssh-connect-timeout", 45, 5, 300),
            ("ssh-handshake-timeout", 30, 5, 300),
            ("ssh-channel-timeout", 30, 1, 300),
            ("ssh-keepalive-interval", 15, 0, 300),
            ("ssh-keepalive-max", 3, 1, 10),
            ("ssh-inactivity-timeout", 90, 0, 3600),
            ("tun-mtu", 1500, 1280, 9000),
            ("startup-timeout", 30, 5, 180),
            ("health-timeout", 20, 5, 120),
        ] {
            let value = c.number(key, default)?;
            ensure!(
                (minimum..=maximum).contains(&value),
                "invalid {key}: expected {minimum}..={maximum}"
            );
        }
        let idle = c.number("ssh-inactivity-timeout", 90)?;
        let keepalive = c.number("ssh-keepalive-interval", 15)?;
        ensure!(
            idle == 0 || keepalive == 0 || idle > keepalive * c.number("ssh-keepalive-max", 3)?,
            "SSH inactivity timeout must exceed the keepalive failure window (or use 0 to disable it)"
        );
        if !c.get("proxy", "").is_empty() {
            parse_proxy(c.get("proxy", ""))?;
        }
        c.routing_rules()?;
        crate::tun::Settings::from_config(&c)?;
        if c.boolean("ui") {
            return Ok(c);
        }
        if c.mode() == "ssh" {
            ensure!(
                !c.get("H", "").is_empty()
                    && !c.get("u", "").is_empty()
                    && !c.get("p", "").is_empty(),
                "SSH requires -H, -P, -u and -p"
            );
            let p = c.number("P", 0)?;
            ensure!(p > 0 && p <= 65535, "invalid SSH port");
            ensure!(
                !c.get("H", "").contains(['\r', '\n', ' ']),
                "invalid SSH host"
            );
        } else {
            ensure!(
                c.get("proxy", "").is_empty() && c.get("payload-file", "").is_empty(),
                "proxy/payload options apply only to SSH"
            );
            if c.get("v2ray-config", "").is_empty() {
                let p = c.protocol()?;
                ensure!(
                    p.security == "tls"
                        || ["auto", "none"].contains(&c.get("v2ray-cert-sha256", "auto")),
                    "certificate pins require TLS"
                );
            } else {
                ensure!(
                    !c.boolean("block-quic"),
                    "set UDP/QUIC policy inside a custom core configuration"
                );
                ensure!(
                    !c.tun(),
                    "TUN requires a generated config and server address"
                );
                ensure!(
                    ["auto", "none"].contains(&c.get("v2ray-cert-sha256", "auto")),
                    "custom configs retain their own TLS settings"
                );
                ensure!(
                    !c.flags.contains_key("v2ray-sni"),
                    "set SNI inside custom config"
                );
            }
        }
        Ok(c)
    }
    pub fn canonical_args(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.flags.keys().collect();
        keys.sort();
        let mut args = vec![];
        for key in keys {
            if BOOL_FLAGS.contains(&key.as_str()) {
                args.push(if self.boolean(key) {
                    format!("-{key}")
                } else {
                    format!("-{key}=false")
                });
            } else {
                args.push(format!("-{key}"));
                args.push(self.flags[key].clone());
            }
        }
        args
    }
    pub fn get<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.flags.get(key).map(String::as_str).unwrap_or(default)
    }
    pub fn boolean(&self, key: &str) -> bool {
        self.get(key, "false") == "true"
    }
    pub fn number(&self, key: &str, default: u32) -> Result<u32> {
        Ok(match self.flags.get(key) {
            Some(v) => v.parse()?,
            None => default,
        })
    }
    pub fn mode(&self) -> &str {
        self.get("mode", "ssh")
    }
    pub fn tun(&self) -> bool {
        self.boolean("tun") || self.boolean("auto-route")
    }
    pub fn routing_rules(&self) -> Result<Vec<crate::routing::Rule>> {
        crate::routing::parse(self.get("routing-rules", "[]"))
    }
    pub fn health_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.number("health-timeout", 20).unwrap_or(20) as u64)
    }
    pub fn socks_port(&self) -> u16 {
        self.number("socks-port", 1080).unwrap_or(1080) as u16
    }
    pub fn protocol(&self) -> Result<Protocol> {
        let mut p = if !self.get("v2ray-link", "").is_empty() {
            Protocol::parse(self.get("v2ray-link", ""))?
        } else {
            Protocol {
                protocol: self.get("v2ray-protocol", "vmess").into(),
                uuid: self.get("v2ray-uuid", "").into(),
                address: self.get("v2ray-addr", "").into(),
                port: self.number("v2ray-port", 0)?,
                network: self.get("v2ray-network", "tcp").into(),
                security: self.get("v2ray-security", "none").into(),
                path: self.get("v2ray-path", "/").into(),
                host: self.get("v2ray-host", "").into(),
                service_name: self.get("v2ray-service", "").into(),
                ..Protocol::default()
            }
        };
        if let Some(sni) = self.flags.get("v2ray-sni") {
            p.sni = sni.clone();
            p.sni_source = "override".into();
        }
        p.finish()?;
        Ok(p)
    }
}
pub fn parse_proxy(s: &str) -> Result<Url> {
    let u = Url::parse(s)?;
    ensure!(
        ["http", "https"].contains(&u.scheme())
            && u.host_str().is_some()
            && u.port_or_known_default().is_some()
            && u.path() == "/"
            && u.query().is_none()
            && u.fragment().is_none(),
        "proxy must be an HTTP(S) origin"
    );
    Ok(u)
}

mod protocols;
pub use protocols::{Protocol, decode64, unescape};
