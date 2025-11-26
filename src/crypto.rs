use aes_gcm::{
    aead::{
        generic_array::GenericArray,
        stream::{DecryptorBE32, EncryptorBE32},
        OsRng,
    },
    Aes256Gcm,
};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;

pub struct Encryptor {
    key: [u8; 32],
    // EncryptorBE32 adds 32-bit counter + 8-bit last-block flag
    // 7 bytes nonce + 4 bytes counter + 1 byte flag = 12 bytes
    nonce: [u8; 7],
}

impl Encryptor {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 7];
        OsRng::default().fill_bytes(&mut key);
        OsRng::default().fill_bytes(&mut nonce);

        Self { key, nonce }
    }

    pub fn create_stream_encryptor(&self) -> EncryptorBE32<Aes256Gcm> {
        // Convert [u8] to GenericArray<u8, U32> for aes_gcm crate
        let key = GenericArray::from_slice(&self.key);
        let nonce = GenericArray::from_slice(&self.nonce);

        // EncryptorBE32 handles nonce increment automatically
        // Internally constructs: [7 random bytes][5 bytes for counter]
        EncryptorBE32::new(key, nonce)
    }

    pub fn create_stream_decryptor(&self) -> DecryptorBE32<Aes256Gcm> {
        let key = GenericArray::from_slice(&self.key);
        let nonce = GenericArray::from_slice(&self.nonce);

        // Decryptor also handles nonce
        // expects same format as EncryptorBE32
        DecryptorBE32::new(key, nonce)
    }
    pub fn get_key_base64(&self) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(&self.key)
    }

    pub fn get_nonce_base64(&self) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(&self.nonce)
    }
}
