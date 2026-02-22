//! AES-256-GCM encryption with positioned nonces for out-of-order chunk processing.
//!
//! - Each file has a random 8-byte nonce base
//! - Per-chunk nonce = base + chunk_index (4-byte big-endian counter)
//! - Client derives same nonce from chunk position (no transmission overhead)
//!

use crate::crypto::types::Nonce;
use anyhow::Result;
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce as AeadNonce};

pub fn encrypt_chunk_in_place(
    key: &LessSafeKey,
    nonce_base: &Nonce,
    buffer: &mut Vec<u8>,
    counter: u32,
) -> Result<()> {
    let full_nonce = nonce_base.with_counter(counter);
    let nonce = AeadNonce::assume_unique_for_key(full_nonce);

    key.seal_in_place_append_tag(nonce, Aad::empty(), buffer)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e:?}"))
}

pub fn decrypt_chunk_in_place(
    key: &LessSafeKey,
    nonce_base: &Nonce,
    buffer: &mut Vec<u8>,
    counter: u32,
) -> Result<()> {
    let full_nonce = nonce_base.with_counter(counter);
    let nonce = AeadNonce::assume_unique_for_key(full_nonce);

    let plaintext_len = key
        .open_in_place(nonce, Aad::empty(), buffer)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e:?}"))?
        .len();
    buffer.truncate(plaintext_len);
    Ok(())
}
