//! Protocol import service.
//!
//! Parses VMess, VLESS, Trojan and Shadowsocks links while keeping imported SNI distinct from its effective TLS name.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

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
