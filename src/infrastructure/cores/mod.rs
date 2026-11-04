//! External networking core adapters.
//!
//! Configuration generation is separate from process lifecycle. Callers retain the original core API.

use crate::recovery::PermanentFailure;
use anyhow::Context;
use anyhow::Result;
use std::path::PathBuf;
pub fn find_core(explicit: &str, names: &[&str]) -> Result<PathBuf> {
    if !explicit.is_empty() {
        return Ok(PathBuf::from(explicit));
    }
    let exe = std::env::current_exe()?;
    let parent = exe.parent().context("no executable directory")?;
    for name in names {
        let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);
        let mut locations = vec![parent.join("cores")];
        if cfg!(target_os = "macos") {
            locations.push(parent.join("../Resources/cores"));
        }
        locations.push(parent.into());
        for dir in locations {
            let path = dir.join(&filename);
            if path.is_file() {
                return Ok(path);
            }
        }
        if let Some(paths) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&paths) {
                let path = dir.join(&filename);
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
    }
    Err(anyhow::anyhow!(
        "required core {} not found; set its binary path or put it in cores/ beside tunnel",
        names.join("/")
    )
    .context(PermanentFailure::Configuration))
}
mod process;
mod tun;
mod xray;
pub use process::CoreProcess;
pub use tun::tun_config;
pub use xray::xray_config;
