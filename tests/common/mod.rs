#![allow(dead_code)]

pub mod config_test_utils;
pub mod receive_http;
pub mod send_http;

use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
use dropt::common::TransferSettings;
use dropt::crypto::types::EncryptionKey;
use tempfile::TempDir;

pub const CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10MB

pub fn default_config() -> TransferSettings {
    TransferSettings {
        chunk_size: CHUNK_SIZE as u64,
        concurrency: 8,
    }
}

pub fn setup_temp_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

pub fn create_cipher(key: &EncryptionKey) -> LessSafeKey {
    let unbound = UnboundKey::new(&AES_256_GCM, key.as_bytes()).expect("valid 32-byte AES-256 key");
    LessSafeKey::new(unbound)
}
