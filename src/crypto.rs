use aes_gcm::{
    aead::{OsRng},
    aead::stream::{EncryptorBE32},  // ← Stream types
    aead::generic_array::GenericArray,  // ← For type conversions
    Aes256Gcm,
};
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
    pub fn get_key_base64(&self) -> String {
        base64::encode(&self.key)
    }

    pub fn get_nonce_base64(&self) -> String {
        base64::encode(&self.nonce)
    }
}

pub fn test_encryption() {
    // Test 1: Same encryptor
    let encryptor = Encryptor::new();
    let mut stream1 = encryptor.create_stream_encryptor();
    let mut stream2 = encryptor.create_stream_encryptor();
    
    let plaintext = b"Test";
    let enc1 = stream1.encrypt_last(plaintext.as_ref()).unwrap();
    let enc2 = stream2.encrypt_last(plaintext.as_ref()).unwrap();
    
    println!("Same Key");
    println!("Encrypted1: {:?}", &enc1[..10]);
    println!("Encrypted2: {:?}", &enc2[..10]);
    println!("Equal? {} ✅ (expected)\n", enc1 == enc2);
    
    // Test 2: Different encryptor (different key)
    let encryptor2 = Encryptor::new();  // New random key
    let mut stream3 = encryptor2.create_stream_encryptor();
    let enc3 = stream3.encrypt_last(plaintext.as_ref()).unwrap();
    
    println!("Different Key");
    println!("Encrypted1: {:?}", &enc1[..10]);
    println!("Encrypted3: {:?}", &enc3[..10]);
    println!("Equal? {} ✅ (expected: false)\n", enc1 == enc3);
    
    // Test 3: Multiple chunks increment nonce
    let mut stream4 = encryptor.create_stream_encryptor();
    let chunk1 = stream4.encrypt_next(b"First".as_ref()).unwrap();
    let chunk2 = stream4.encrypt_last(b"Second".as_ref()).unwrap();
    
    println!("Different Chunks (nonce increments)");
    println!("Chunk1: {:?}", &chunk1[..8]);
    println!("Chunk2: {:?}", &chunk2[..8]);
    println!("Equal? {} ✅ (expected: false)", chunk1 == chunk2);
}
