use archdrop::crypto::types::{EncryptionKey, Nonce};
use archdrop::crypto::{decrypt_chunk_in_place, encrypt_chunk_in_place};
use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM};

fn make_key(key: &EncryptionKey) -> LessSafeKey {
    let unbound = UnboundKey::new(&AES_256_GCM, key.as_bytes()).expect("valid key");
    LessSafeKey::new(unbound)
}

#[test]
fn test_encrypt_decrypt_chunk() {
    let key = EncryptionKey::new();
    let nonce = Nonce::new();
    let cipher = make_key(&key);

    let plaintext = b"Hello, ArchDrop!";
    let counter = 0;

    // Encrypt in place
    let mut buffer = plaintext.to_vec();
    encrypt_chunk_in_place(&cipher, &nonce, &mut buffer, counter)
        .expect("Encryption should succeed");

    assert_ne!(plaintext.to_vec(), buffer, "Encrypted data should differ");

    // Decrypt in place
    decrypt_chunk_in_place(&cipher, &nonce, &mut buffer, counter)
        .expect("Decryption should succeed");

    assert_eq!(
        plaintext.to_vec(),
        buffer,
        "Decrypted should match original"
    );
}

#[test]
fn test_encrypt_multiple_chunks() {
    let key = EncryptionKey::new();
    let nonce = Nonce::new();
    let cipher = make_key(&key);

    let chunks: [&[u8]; 3] = [b"chunk1", b"chunk2", b"chunk3"];
    let mut encrypted_chunks = Vec::new();

    // Encrypt multiple chunks with different counters
    for (i, chunk) in chunks.iter().enumerate() {
        let mut buffer = chunk.to_vec();
        encrypt_chunk_in_place(&cipher, &nonce, &mut buffer, i as u32)
            .expect("Encryption should succeed");
        encrypted_chunks.push(buffer);
    }

    // Decrypt and verify
    for (i, (original, encrypted)) in chunks.iter().zip(encrypted_chunks.iter()).enumerate() {
        let mut buffer = encrypted.clone();
        decrypt_chunk_in_place(&cipher, &nonce, &mut buffer, i as u32)
            .expect("Decryption should succeed");
        assert_eq!(original.to_vec(), buffer);
    }
}

#[test]
fn test_wrong_key_fails_decryption() {
    let key1 = EncryptionKey::new();
    let key2 = EncryptionKey::new();
    let nonce = Nonce::new();

    let cipher1 = make_key(&key1);
    let cipher2 = make_key(&key2);

    let plaintext = b"secret data";

    let mut buffer = plaintext.to_vec();
    encrypt_chunk_in_place(&cipher1, &nonce, &mut buffer, 0).expect("Encryption should succeed");

    // Try to decrypt with wrong key
    let result = decrypt_chunk_in_place(&cipher2, &nonce, &mut buffer, 0);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn test_wrong_counter_fails_decryption() {
    let key = EncryptionKey::new();
    let nonce = Nonce::new();
    let cipher = make_key(&key);

    let plaintext = b"test data";

    let mut buffer = plaintext.to_vec();
    encrypt_chunk_in_place(&cipher, &nonce, &mut buffer, 5).expect("Encryption should succeed");

    // Try to decrypt with wrong counter
    let result = decrypt_chunk_in_place(&cipher, &nonce, &mut buffer, 10);
    assert!(result.is_err(), "Decryption with wrong counter should fail");
}

#[test]
fn test_key_base64_roundtrip() {
    let key = EncryptionKey::new();
    let b64 = key.to_base64();
    let decoded = EncryptionKey::from_base64(&b64).expect("Should decode successfully");

    assert_eq!(key.as_bytes(), decoded.as_bytes());
}

#[test]
fn test_nonce_base64_roundtrip() {
    let nonce = Nonce::new();
    let b64 = nonce.to_base64();
    let decoded = Nonce::from_base64(&b64).expect("Should decode successfully");

    assert_eq!(nonce.as_bytes(), decoded.as_bytes());
}

#[test]
fn test_invalid_key_base64() {
    let result = EncryptionKey::from_base64("invalid!@#$");
    assert!(result.is_err(), "Invalid base64 should fail");

    // Too short
    let result = EncryptionKey::from_base64("YWJj");
    assert!(result.is_err(), "Wrong length should fail");
}

#[test]
fn test_invalid_nonce_base64() {
    let result = Nonce::from_base64("invalid!@#$");
    assert!(result.is_err(), "Invalid base64 should fail");

    // Too short
    let result = Nonce::from_base64("YQ");
    assert!(result.is_err(), "Wrong length should fail");
}
