use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
pub fn decode64(s: &str) -> Result<Vec<u8>> {
    for e in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        if let Ok(v) = e.decode(s) {
            return Ok(v);
        }
    }
    bail!("invalid base64")
}
pub fn unescape(s: &str) -> Result<String> {
    Ok(percent_encoding::percent_decode_str(s)
        .decode_utf8()?
        .into_owned())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Protocol {
    pub enabled: bool,
    pub protocol: String,
    #[serde(rename = "UUID")]
    pub uuid: String,
    pub address: String,
    pub port: u32,
    pub network: String,
    pub security: String,
    #[serde(rename = "SNI")]
    pub sni: String,
    #[serde(rename = "SNISource")]
    pub sni_source: String,
    #[serde(rename = "EffectiveSNI")]
    pub effective_sni: String,
    pub fingerprint: String,
    #[serde(rename = "ALPN")]
    pub alpn: Vec<String>,
    pub cipher: String,
    pub flow: String,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub path: String,
    pub host: String,
    pub service_name: String,
    #[serde(rename = "XHTTPMode")]
    pub xhttp_mode: String,
    #[serde(rename = "XHTTPExtra")]
    pub xhttp_extra: Value,
    pub reality_spider_x: String,
}
impl Default for Protocol {
    fn default() -> Self {
        Self {
            enabled: true,
            protocol: String::new(),
            uuid: String::new(),
            address: String::new(),
            port: 0,
            network: "tcp".into(),
            security: "none".into(),
            sni: String::new(),
            sni_source: String::new(),
            effective_sni: String::new(),
            fingerprint: String::new(),
            alpn: vec![],
            cipher: "auto".into(),
            flow: String::new(),
            reality_public_key: String::new(),
            reality_short_id: String::new(),
            path: "/".into(),
            host: String::new(),
            service_name: String::new(),
            xhttp_mode: "auto".into(),
            xhttp_extra: Value::Null,
            reality_spider_x: "/".into(),
        }
    }
}
impl Protocol {
    pub fn parse(link: &str) -> Result<Self> {
        let link = link.trim();
        ensure!(link.len() <= 65536, "link too large");
        let mut p = Self::default();
        if let Some(encoded) = link.strip_prefix("vmess://") {
            let v: Value = serde_json::from_slice(&decode64(encoded)?)?;
            let s = |key: &str| -> String {
                match &v[key] {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                }
            };
            p.protocol = "vmess".into();
            p.address = s("add");
            p.uuid = s("id");
            p.port = s("port").parse()?;
            if !s("net").is_empty() {
                p.network = s("net");
            }
            p.security = match &v["tls"] {
                Value::Null => "none",
                Value::Bool(true) => "tls",
                Value::Bool(false) => "none",
                Value::String(x) if ["tls", "true", "1"].contains(&x.as_str()) => "tls",
                Value::String(x) if ["", "none", "false", "0"].contains(&x.as_str()) => "none",
                Value::Number(x) if x.as_u64() == Some(1) => "tls",
                Value::Number(x) if x.as_u64() == Some(0) => "none",
                _ => bail!("unsupported VMess TLS value; refusing to silently disable TLS"),
            }
            .into();
            p.sni = s("sni");
            p.host = s("host");
            if !s("path").is_empty() {
                p.path = s("path");
            }
            p.service_name = s("serviceName");
            if p.network == "grpc" && p.service_name.is_empty() {
                p.service_name = s("path").trim_start_matches('/').into();
            }
            if p.network == "xhttp" && !s("mode").is_empty() {
                p.xhttp_mode = s("mode");
            }
            if p.network == "xhttp" {
                p.xhttp_extra = parse_xhttp_extra(&v["extra"])?;
            }
            p.fingerprint = s("fp");
            if !s("scy").is_empty() {
                p.cipher = s("scy");
            }
            if !s("alpn").is_empty() && s("alpn") != "none" {
                p.alpn = s("alpn").split(',').map(str::to_owned).collect();
            }
            ensure!(
                s("aid").is_empty() || s("aid") == "0",
                "legacy VMess alterId is unsupported"
            );
        } else if let Some(raw) = link.strip_prefix("ss://") {
            let (content, _) = raw.split_once('#').unwrap_or((raw, ""));
            let expanded = if content.contains('@') {
                content.to_owned()
            } else {
                String::from_utf8(decode64(content)?)?
            };
            let u = Url::parse(&format!("ss://{expanded}"))?;
            ensure!(
                u.query_pairs().all(|(k, v)| k != "plugin" || v.is_empty()),
                "Shadowsocks plugins are unsupported; use a plain SIP002 link"
            );
            let auth = if let Some(password) = u.password() {
                format!("{}:{}", unescape(u.username())?, unescape(password)?)
            } else {
                String::from_utf8(decode64(&unescape(u.username())?)?)?
            };
            let (method, password) = auth
                .split_once(':')
                .context("Shadowsocks link requires method and password")?;
            p.protocol = "shadowsocks".into();
            p.cipher = method.into();
            p.uuid = password.into();
            p.address = u.host_str().unwrap_or("").trim_matches(['[', ']']).into();
            p.port = u.port().unwrap_or(0).into();
        } else {
            let u = Url::parse(link)?;
            ensure!(
                ["vless", "trojan"].contains(&u.scheme()),
                "supported links: vmess, vless, trojan, ss"
            );
            p.protocol = u.scheme().into();
            p.uuid = unescape(u.username())?;
            p.address = u.host_str().unwrap_or("").trim_matches(['[', ']']).into();
            p.port = u.port().unwrap_or(0).into();
            let q: HashMap<_, _> = u.query_pairs().into_owned().collect();
            let get = |k: &str, d: &str| q.get(k).cloned().unwrap_or_else(|| d.into());
            p.network = get("type", "tcp");
            p.security = get(
                "security",
                if p.protocol == "trojan" {
                    "tls"
                } else {
                    "none"
                },
            );
            p.sni = q
                .get("sni")
                .or_else(|| q.get("peer"))
                .or_else(|| q.get("serverName"))
                .cloned()
                .unwrap_or_default();
            p.host = get("host", "");
            p.path = get("path", "/");
            p.service_name = get("serviceName", "");
            p.fingerprint = get("fp", "");
            if p.network == "xhttp" {
                p.xhttp_mode = get("mode", "auto");
                p.xhttp_extra = parse_xhttp_extra(&Value::String(get("extra", "")))?;
            }
            p.reality_spider_x = get("spx", "/");
            p.flow = get("flow", "");
            p.reality_public_key = get("pbk", "");
            p.reality_short_id = get("sid", "");
            let a = get("alpn", "");
            if !a.is_empty() && a != "none" {
                p.alpn = a.split(',').map(str::to_owned).collect();
            }
        }
        if !p.sni.is_empty() {
            p.sni_source = "link".into();
        }
        p.finish()?;
        Ok(p)
    }
    pub fn finish(&mut self) -> Result<()> {
        ensure!(
            ["vmess", "vless", "trojan", "shadowsocks"].contains(&self.protocol.as_str()),
            "unsupported protocol"
        );
        ensure!(
            !self.address.is_empty() && !self.uuid.is_empty() && (1..=65535).contains(&self.port),
            "server, credentials and valid port required"
        );
        ensure!(
            !self.address.contains(['\r', '\n', ' ']),
            "invalid server address"
        );
        ensure!(
            [
                "tcp",
                "raw",
                "ws",
                "grpc",
                "http",
                "h2",
                "httpupgrade",
                "xhttp"
            ]
            .contains(&self.network.as_str()),
            "unsupported network"
        );
        ensure!(
            ["none", "tls", "reality"].contains(&self.security.as_str()),
            "unsupported security"
        );
        ensure!(
            ["auto", "packet-up", "stream-up", "stream-one"].contains(&self.xhttp_mode.as_str()),
            "unsupported XHTTP mode"
        );
        if self.protocol == "shadowsocks" {
            ensure!(
                [
                    "aes-128-gcm",
                    "aes-256-gcm",
                    "chacha20-poly1305",
                    "chacha20-ietf-poly1305",
                    "2022-blake3-aes-128-gcm",
                    "2022-blake3-aes-256-gcm",
                    "2022-blake3-chacha20-poly1305"
                ]
                .contains(&self.cipher.as_str()),
                "unsupported Shadowsocks cipher"
            );
        }
        if self.security == "reality" {
            ensure!(
                !self.sni.is_empty() && !self.reality_public_key.is_empty(),
                "REALITY requires SNI and public key"
            );
        }
        if self.sni.is_empty() {
            if self.protocol == "vmess"
                && self.security == "tls"
                && ["ws", "httpupgrade"].contains(&self.network.as_str())
                && !self.host.is_empty()
            {
                self.effective_sni = Url::parse(&format!("http://{}", self.host))?
                    .host_str()
                    .unwrap_or(&self.host)
                    .trim_matches(['[', ']'])
                    .into();
                self.sni_source = "host".into();
            } else {
                self.effective_sni = self.address.clone();
                self.sni_source = "server".into();
            }
        } else {
            self.effective_sni = self.sni.clone();
        }
        Ok(())
    }
}

fn parse_xhttp_extra(value: &Value) -> Result<Value> {
    let parsed = match value {
        Value::Null => return Ok(Value::Null),
        Value::String(s) if s.trim().is_empty() => return Ok(Value::Null),
        Value::String(s) => {
            ensure!(s.len() <= 8192, "XHTTP extra is too large");
            serde_json::from_str(s)?
        }
        v => v.clone(),
    };
    ensure!(
        parsed.is_object() && serde_json::to_vec(&parsed)?.len() <= 8192,
        "XHTTP extra must be a JSON object under 8192 bytes"
    );
    Ok(parsed)
}
