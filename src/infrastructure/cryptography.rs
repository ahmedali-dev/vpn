//! Vault cryptography service.
//!
//! Owns secure randomness, password key derivation and authenticated encryption. Preserve AAD and wire formats.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use rand::RngCore;
use zeroize::Zeroizing;

pub fn random<const N: usize>() -> [u8; N] {
    let mut v = [0; N];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}
pub fn derive(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    scrypt::scrypt(
        password.as_bytes(),
        salt,
        &scrypt::Params::new(15, 8, 1, 32)?,
        key.as_mut(),
    )?;
    Ok(key)
}
pub fn encrypt(key: &[u8], raw: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::<12>();
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid key"))?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: raw, aad })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok([nonce.to_vec(), encrypted].concat())
}
pub fn decrypt(key: &[u8], raw: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ensure!(raw.len() >= 28, "invalid encrypted data");
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid key"))?
        .decrypt(
            Nonce::from_slice(&raw[..12]),
            Payload {
                msg: &raw[12..],
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("incorrect password or damaged encrypted data"))
}
pub(crate) fn seal(key: &[u8], data: &[u8]) -> Result<String> {
    Ok(format!(
        "vault1.{}",
        STANDARD_NO_PAD.encode(encrypt(key, data, b"TunnelNest profile v1")?)
    ))
}
pub(crate) fn open(key: &[u8], value: &str) -> Result<Vec<u8>> {
    decrypt(
        key,
        &STANDARD_NO_PAD.decode(
            value
                .strip_prefix("vault1.")
                .context("invalid vault data")?,
        )?,
        b"TunnelNest profile v1",
    )
}
