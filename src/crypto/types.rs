use base64::{Engine, engine::general_purpose};
use rand::RngCore;
use rand::rngs::OsRng;

// OSRng pulls from Operating system
// It is more cryptographically secure than PRNG, but slower

/// AES-256-GCM encryption key (32 bytes)
#[derive(Debug, Clone)]
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        // remove unsafe URL chars
        general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64(b64: &str) -> anyhow::Result<Self> {
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(b64)?;
        if bytes.len() != 32 {
            anyhow::bail!("Invalid key length");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
}

impl Default for EncryptionKey {
    fn default() -> Self {
        Self::new()
    }
}

/// 8-byte base + 4-byte counter (chunk index) for positioned encryption.
///
/// Full nonce = [8-byte random | 4-byte counter]. Enables out-of-order decryption.
#[derive(Debug, Clone, PartialEq)]
pub struct Nonce([u8; 8]);

impl Nonce {
    pub fn new() -> Self {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        Self(nonce)
    }

    // raw bytes (for creating stream encryptor/decryptor)
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    // for URL
    pub fn to_base64(&self) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64(b64: &str) -> anyhow::Result<Self> {
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(b64)?;
        if bytes.len() != 8 {
            anyhow::bail!("Invalid nonce length");
        }
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&bytes);
        Ok(Self(nonce))
    }

    /// Returns 12-byte nonce: [8-byte base | 4-byte big-endian counter].
    pub fn with_counter(&self, counter: u32) -> [u8; 12] {
        let mut full_nonce = [0u8; 12];
        full_nonce[0..8].copy_from_slice(&self.0); // 8-byte nonce base
        full_nonce[8..12].copy_from_slice(&counter.to_be_bytes()); // 4-byte counter
        full_nonce
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Self::new()
    }
}
