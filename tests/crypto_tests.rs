use aes_gcm::{Aes256Gcm, KeyInit};
use archdrop::crypto::{decrypt_chunk_at_position, encrypt_chunk_at_position};
use archdrop::crypto::types::{EncryptionKey, Nonce};
use sha2::digest::generic_array::GenericArray;

#[test]
fn test_encrypt_decrypt_chunk() {
    let key = EncryptionKey::new();
    let nonce = Nonce::new();
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()));

    let plaintext = b"Hello, ArchDrop!";
    let counter = 0;

    // Encrypt
    let encrypted = encrypt_chunk_at_position(&cipher, &nonce, plaintext, counter)
        .expect("Encryption should succeed");

    assert_ne!(
        plaintext.to_vec(),
        encrypted,
        "Encrypted data should differ"
    );

    // Decrypt
    let decrypted = decrypt_chunk_at_position(&cipher, &nonce, &encrypted, counter)
        .expect("Decryption should succeed");

    assert_eq!(
        plaintext.to_vec(),
        decrypted,
        "Decrypted should match original"
    );
}

#[test]
fn test_encrypt_multiple_chunks() {
    let key = EncryptionKey::new();
    let nonce = Nonce::new();
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()));

    let chunks = vec![b"chunk1", b"chunk2", b"chunk3"];
    let mut encrypted_chunks = Vec::new();

    // Encrypt multiple chunks with different counters
    for (i, chunk) in chunks.iter().enumerate() {
        let encrypted = encrypt_chunk_at_position(&cipher, &nonce, *chunk, i as u32)
            .expect("Encryption should succeed");
        encrypted_chunks.push(encrypted);
    }

    // Decrypt and verify
    for (i, (original, encrypted)) in chunks.iter().zip(encrypted_chunks.iter()).enumerate() {
        let decrypted = decrypt_chunk_at_position(&cipher, &nonce, encrypted, i as u32)
            .expect("Decryption should succeed");
        assert_eq!(original.to_vec(), decrypted);
    }
}

#[test]
fn test_wrong_key_fails_decryption() {
    let key1 = EncryptionKey::new();
    let key2 = EncryptionKey::new();
    let nonce = Nonce::new();

    let cipher1 = Aes256Gcm::new(GenericArray::from_slice(key1.as_bytes()));
    let cipher2 = Aes256Gcm::new(GenericArray::from_slice(key2.as_bytes()));

    let plaintext = b"secret data";

    let encrypted = encrypt_chunk_at_position(&cipher1, &nonce, plaintext, 0)
        .expect("Encryption should succeed");

    // Try to decrypt with wrong key
    let result = decrypt_chunk_at_position(&cipher2, &nonce, &encrypted, 0);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn test_wrong_counter_fails_decryption() {
    let key = EncryptionKey::new();
    let nonce = Nonce::new();
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()));

    let plaintext = b"test data";

    let encrypted = encrypt_chunk_at_position(&cipher, &nonce, plaintext, 5)
        .expect("Encryption should succeed");

    // Try to decrypt with wrong counter
    let result = decrypt_chunk_at_position(&cipher, &nonce, &encrypted, 10);
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
