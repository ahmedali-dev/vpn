//! Profile business rules.
//!
//! Validates and canonicalizes a profile before persistence. This service performs no database or OS-keychain operations.

use super::Profile;
use crate::config::{BOOL_FLAGS, Config};
use anyhow::{Result, ensure};

/// Validate business rules before the repository writes or encrypts any profile.
pub fn prepare_for_save(mut p: Profile) -> Result<Profile> {
    p.name = p.name.trim().into();
    ensure!(
        !p.name.is_empty() && p.name.len() <= 100,
        "profile name must be 1–100 bytes"
    );
    ensure!(
        !p.args.is_empty() && p.args.len() <= 128,
        "invalid profile arguments"
    );
    let cfg = Config::parse(&p.args)?;
    ensure!(!cfg.boolean("ui"), "nested control servers are forbidden");
    p.mode = cfg.mode().into();
    p.args = cfg.canonical_args();
    Ok(p)
}

/// Remove login secrets for profiles whose credentials should last only this session.
pub fn credentials_removed(args: &[String]) -> Vec<String> {
    let mut out = args.to_vec();
    let mut i = 0;
    while i < out.len() {
        if BOOL_FLAGS.contains(
            &out[i]
                .trim_start_matches('-')
                .split('=')
                .next()
                .unwrap_or_default(),
        ) {
            i += 1;
            continue;
        }
        if i + 1 >= out.len() {
            break;
        }
        match out[i].as_str() {
            "-u" | "-p" | "-v2ray-uuid" | "-v2ray-link" => out[i + 1].clear(),
            "-proxy" => {
                if let Ok(mut u) = url::Url::parse(&out[i + 1]) {
                    let _ = u.set_username("");
                    let _ = u.set_password(None);
                    out[i + 1] = u.to_string();
                }
            }
            _ => (),
        };
        i += 2;
    }
    out
}
