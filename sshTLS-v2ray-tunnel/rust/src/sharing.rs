use crate::{
    config::{BOOL_FLAGS, Config, decode64},
    store::{Profile, decrypt, derive, encrypt, random},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::*};
use flate2::{
    Compression,
    read::{DeflateDecoder, ZlibDecoder},
    write::DeflateEncoder,
};
use std::io::{Cursor, Read, Write};

pub const FLAGS: &[&str] = &[
    "-mode",
    "-H",
    "-P",
    "-u",
    "-p",
    "-S",
    "-socks-port",
    "-pac-port",
    "-max-conns",
    "-tls-version",
    "-ssh-host-key",
    "-ssh-cert-sha256",
    "-proxy",
    "-payload-stage",
    "-v2ray-link",
    "-v2ray-sni",
    "-v2ray-cert-sha256",
    "-v2ray-protocol",
    "-v2ray-uuid",
    "-v2ray-addr",
    "-v2ray-port",
    "-v2ray-network",
    "-v2ray-security",
    "-v2ray-path",
    "-v2ray-host",
    "-v2ray-service",
    "-tun",
    "-auto-route",
    "-ssh-trust-on-first-use",
    "-ssh-ipv4-only",
];
const MAX: usize = 65536;
fn boolean(f: &str) -> bool {
    BOOL_FLAGS.contains(&f.trim_start_matches('-'))
}
pub fn validate(mut p: Profile) -> Result<Profile> {
    p.name = p.name.trim().into();
    ensure!(
        !p.name.is_empty() && p.name.len() <= 100,
        "invalid shared profile name"
    );
    ensure!(
        !p.args.is_empty() && p.args.len() <= 128,
        "invalid shared arguments"
    );
    let mut seen = std::collections::HashSet::new();
    let mut i = 0;
    while i < p.args.len() {
        let f = &p.args[i];
        ensure!(
            FLAGS.contains(&f.as_str()) && seen.insert(f.clone()),
            "unsafe or duplicate shared option"
        );
        i += 1;
        if !boolean(f) {
            ensure!(
                i < p.args.len() && p.args[i].len() <= 8192,
                "invalid shared value"
            );
            i += 1;
        }
    }
    let c = Config::parse(&p.args)?;
    ensure!(
        ["ssh", "xray", "v2ray"].contains(&p.mode.as_str())
            && (p.mode == "ssh") == (c.mode() == "ssh"),
        "shared mode mismatch"
    );
    p.mode = c.mode().into();
    Ok(p)
}
fn portable(mut p: Profile) -> Result<Profile> {
    let mut args = vec![];
    let mut i = 0;
    while i < p.args.len() {
        let f = &p.args[i];
        ensure!(
            ![
                "-payload-file",
                "-tls-ca",
                "-ssh-known-hosts",
                "-v2ray-config"
            ]
            .contains(&f.as_str()),
            "remove local file references before sharing"
        );
        if ["-v2ray-binary", "-tun-binary"].contains(&f.as_str()) {
            ensure!(i + 1 < p.args.len(), "missing binary path");
            i += 2;
            continue;
        }
        args.push(f.clone());
        i += 1;
        if !boolean(f) {
            args.push(
                p.args
                    .get(i)
                    .context("missing shared option value")?
                    .clone(),
            );
            i += 1;
        }
    }
    p.args = args;
    validate(p)
}
fn put(out: &mut Vec<u8>, data: &[u8]) {
    let mut n = data.len();
    loop {
        let b = (n & 127) as u8;
        n >>= 7;
        out.push(b | if n > 0 { 128 } else { 0 });
        if n == 0 {
            break;
        }
    }
    out.extend(data);
}
fn byte(c: &mut Cursor<&[u8]>) -> Result<u8> {
    let mut b = [0];
    c.read_exact(&mut b)?;
    Ok(b[0])
}
fn field(c: &mut Cursor<&[u8]>, limit: usize) -> Result<Vec<u8>> {
    let mut n = 0u64;
    let mut shift = 0;
    loop {
        let b = byte(c)?;
        ensure!(
            shift < 64 && (shift != 63 || b <= 1),
            "invalid compact length"
        );
        n |= ((b & 127) as u64) << shift;
        if b & 128 == 0 {
            break;
        }
        shift += 7;
    }
    ensure!(
        n <= limit as u64 && n <= c.get_ref().len().saturating_sub(c.position() as usize) as u64,
        "invalid compact field length"
    );
    let mut data = vec![0; n as usize];
    c.read_exact(&mut data)?;
    Ok(data)
}
fn pack(p: &Profile) -> Result<Vec<u8>> {
    let mut out = vec![match p.mode.as_str() {
        "ssh" => 0,
        "xray" => 1,
        _ => 2,
    }];
    put(&mut out, p.name.as_bytes());
    let mut i = 0;
    while i < p.args.len() {
        let flag = &p.args[i];
        out.push(
            FLAGS
                .iter()
                .position(|f| *f == flag)
                .context("invalid option")? as u8,
        );
        i += 1;
        if boolean(flag) {
            continue;
        }
        let s = &p.args[i];
        let mut data = s.as_bytes().to_vec();
        let mut kind = 0;
        if flag == "-v2ray-link"
            && let Some(v) = s.strip_prefix("vmess://")
        {
            for (n, e) in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
                .iter()
                .enumerate()
            {
                if let Ok(decoded) = e.decode(v)
                    && e.encode(&decoded) == v
                {
                    kind = (n + 1) as u8;
                    data = decoded;
                    break;
                }
            }
        }
        out.push(kind);
        put(&mut out, &data);
        i += 1;
    }
    ensure!(out.len() <= MAX, "profile too large");
    Ok(out)
}
fn unpack(data: &[u8]) -> Result<Profile> {
    let mut c = Cursor::new(data);
    let mode = byte(&mut c)?;
    ensure!(mode <= 2, "invalid mode");
    let mut p = Profile {
        name: String::from_utf8(field(&mut c, 100)?)?,
        mode: ["ssh", "xray", "v2ray"][mode as usize].into(),
        ..Default::default()
    };
    while (c.position() as usize) < data.len() {
        let index = byte(&mut c)? as usize;
        let flag = *FLAGS.get(index).context("invalid compact option")?;
        p.args.push(flag.into());
        ensure!(p.args.len() <= 128, "too many arguments");
        if boolean(flag) {
            continue;
        }
        let kind = byte(&mut c)?;
        let data = field(&mut c, 8192)?;
        let value = if kind == 0 {
            String::from_utf8(data)?
        } else {
            ensure!(
                flag == "-v2ray-link" && kind <= 4,
                "invalid compact value type"
            );
            format!(
                "vmess://{}",
                [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD][kind as usize - 1]
                    .encode(data)
            )
        };
        p.args.push(value);
    }
    validate(p)
}
fn inflate(data: &[u8], legacy: bool) -> Result<Vec<u8>> {
    let mut out = vec![];
    if legacy {
        ZlibDecoder::new(data)
            .take((MAX + 1) as u64)
            .read_to_end(&mut out)?;
    } else {
        ensure!(data.len() >= 2, "invalid compact profile");
        match data[0] {
            0 => out.extend(&data[1..]),
            1 => {
                DeflateDecoder::new(&data[1..])
                    .take((MAX + 1) as u64)
                    .read_to_end(&mut out)?;
            }
            _ => bail!("invalid compression"),
        }
    }
    ensure!(out.len() <= MAX, "inflated profile too large");
    Ok(out)
}
fn password_key(password: &str, salt: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    ensure!(
        (8..=1024).contains(&password.len()),
        "share password must contain 8–1024 bytes"
    );
    derive(password, salt)
}
pub fn encode(p: Profile, password: &str) -> Result<String> {
    let data = pack(&portable(p)?)?;
    let mut deflate = DeflateEncoder::new(Vec::new(), Compression::best());
    deflate.write_all(&data)?;
    let compressed = deflate.finish()?;
    let compressed = if compressed.len() < data.len() {
        [vec![1], compressed].concat()
    } else {
        [vec![0], data].concat()
    };
    let (prefix, envelope) = if password.is_empty() {
        (
            "TN2.",
            [
                crc32fast::hash(&compressed).to_be_bytes().to_vec(),
                compressed,
            ]
            .concat(),
        )
    } else {
        let salt = random::<16>();
        let key = password_key(password, &salt)?;
        (
            "TN2P.",
            [
                salt.to_vec(),
                encrypt(key.as_slice(), &compressed, b"TN2P.")?,
            ]
            .concat(),
        )
    };
    let code = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(envelope));
    ensure!(code.len() <= 24576, "share code too large");
    Ok(code)
}
pub fn decode(code: &str, password: &str) -> Result<Profile> {
    let code = code.trim();
    ensure!(code.len() <= 24576, "share code too large");
    let (prefix, raw) = code.split_once('.').context("invalid share code")?;
    let data = decode64(raw)?;
    let compressed = match prefix {
        "TN2" => {
            ensure!(data.len() >= 6, "invalid share code");
            ensure!(
                crc32fast::hash(&data[4..]) == u32::from_be_bytes(data[..4].try_into()?),
                "share checksum mismatch"
            );
            data[4..].to_vec()
        }
        "TN2P" | "TN1" => {
            ensure!(data.len() >= 44, "invalid protected share code");
            let key = password_key(password, &data[..16])?;
            decrypt(key.as_slice(), &data[16..], format!("{prefix}.").as_bytes())?
        }
        _ => bail!("unsupported share version"),
    };
    let data = inflate(&compressed, prefix == "TN1")?;
    if prefix == "TN1" {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Legacy {
            n: String,
            m: String,
            a: Vec<String>,
        }
        let p: Legacy = serde_json::from_slice(&data)?;
        validate(Profile {
            name: p.n,
            mode: p.m,
            args: p.a,
            ..Default::default()
        })
    } else {
        unpack(&data)
    }
}
