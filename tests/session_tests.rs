use archdrop::server::state::TransferConfig;
use archdrop::server::Session;
use archdrop::transfer::manifest::Manifest;
use archdrop::crypto::types::EncryptionKey;
use tempfile::TempDir;

fn default_config() -> TransferConfig {
    TransferConfig {
        chunk_size: 10 * 1024 * 1024,
        concurrency: 8,
    }
}

#[tokio::test]
async fn test_send_session_creation() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    std::fs::write(&test_file, b"test content").unwrap();

    let config = default_config();
    let manifest = Manifest::new(vec![test_file], None, config.clone()).await.unwrap();
    let key = EncryptionKey::new();
    let total_chunks = manifest.total_chunks(config.chunk_size);

    let session = Session::new_send(manifest, key, total_chunks);
    let token = session.token().to_string();

    assert!(!token.is_empty(), "Token should not be empty");

    // manifest() returns Option<&Arc<Manifest>>
    let manifest = session.manifest().expect("Should have manifest");
    assert!(!manifest.files.is_empty(), "Should have files in manifest");
}

#[tokio::test]
async fn test_receive_session_creation() {
    let temp_dir = TempDir::new().unwrap();
    let dest_path = temp_dir.path().to_path_buf();
    let key = EncryptionKey::new();

    let session = Session::new_receive(dest_path.clone(), key, 0);
    let token = session.token().to_string();

    assert!(!token.is_empty(), "Token should not be empty");

    // destination() returns Option<&PathBuf>
    assert_eq!(
        session.destination().expect("Should have destination"),
        &dest_path
    );
}

#[tokio::test]
async fn test_session_claim_valid_token() {
    let temp_dir = TempDir::new().unwrap();
    let dest_path = temp_dir.path().to_path_buf();
    let key = EncryptionKey::new();

    let session = Session::new_receive(dest_path, key, 0);
    let token = session.token();
    let client_id = "test-client-123";

    // First claim should succeed
    assert!(
        session.claim(token, client_id),
        "First claim should succeed"
    );

    // Second claim with same client_id should succeed (idempotent)
    assert!(
        session.claim(token, client_id),
        "Second claim with same client should succeed"
    );

    // Claim with different client_id should fail
    assert!(
        !session.claim(token, "different-client"),
        "Claim with different client should fail"
    );
}

#[tokio::test]
async fn test_session_claim_invalid_token() {
    let temp_dir = TempDir::new().unwrap();
    let dest_path = temp_dir.path().to_path_buf();
    let key = EncryptionKey::new();

    let session = Session::new_receive(dest_path, key, 0);
    let client_id = "test-client-123";

    // Wrong token should fail
    assert!(
        !session.claim("wrong-token", client_id),
        "Wrong token should fail"
    );
}

#[tokio::test]
async fn test_session_is_active() {
    let temp_dir = TempDir::new().unwrap();
    let dest_path = temp_dir.path().to_path_buf();
    let key = EncryptionKey::new();

    let session = Session::new_receive(dest_path, key, 0);
    let token = session.token();
    let client_id = "test-client-123";

    // Not active before claim
    assert!(
        !session.is_active(token, client_id),
        "Should not be active initially"
    );

    // Claim it
    session.claim(token, client_id);

    // Now should be active
    assert!(
        session.is_active(token, client_id),
        "Should be active after claim"
    );

    // Different client_id should not be active
    assert!(
        !session.is_active(token, "different-client"),
        "Different client should not be active"
    );
}

#[tokio::test]
async fn test_session_complete() {
    let temp_dir = TempDir::new().unwrap();
    let dest_path = temp_dir.path().to_path_buf();
    let key = EncryptionKey::new();

    let session = Session::new_receive(dest_path, key, 0);
    let token = session.token();
    let client_id = "test-client-123";

    // Complete without claim should fail
    assert!(
        !session.complete(token, client_id),
        "Complete should fail before claim"
    );

    // Claim and then complete
    session.claim(token, client_id);
    assert!(
        session.complete(token, client_id),
        "Complete should succeed after claim"
    );

    // Note: Session remains active even after complete in the current implementation
    // This might be a design choice or could be updated if needed
}

#[tokio::test]
async fn test_send_session_get_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file1 = temp_dir.path().join("file1.txt");
    let test_file2 = temp_dir.path().join("file2.txt");
    std::fs::write(&test_file1, b"content1").unwrap();
    std::fs::write(&test_file2, b"content2").unwrap();

    let config = default_config();
    let manifest = Manifest::new(vec![test_file1, test_file2], None, config.clone())
        .await
        .unwrap();
    let key = EncryptionKey::new();
    let total_chunks = manifest.total_chunks(config.chunk_size);

    let session = Session::new_send(manifest, key, total_chunks);

    // Get files by index
    let file0 = session.get_file(0).expect("Should get file 0");
    let file1 = session.get_file(1).expect("Should get file 1");

    assert_eq!(file0.index, 0);
    assert_eq!(file1.index, 1);
    assert_eq!(file0.name, "file1.txt");
    assert_eq!(file1.name, "file2.txt");

    // Out of bounds should return None
    assert!(session.get_file(999).is_none());
}

#[tokio::test]
async fn test_session_modes() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    std::fs::write(&test_file, b"test content").unwrap();

    let config = default_config();
    let manifest = Manifest::new(vec![test_file], None, config.clone()).await.unwrap();
    let key1 = EncryptionKey::new();
    let key2 = EncryptionKey::new();
    let total_chunks = manifest.total_chunks(config.chunk_size);

    // Create send session
    let send_session = Session::new_send(manifest, key1, total_chunks);
    assert!(send_session.manifest().is_some(), "Send session should have manifest");
    assert!(send_session.destination().is_none(), "Send session should not have destination");

    // Create receive session
    let dest_path = temp_dir.path().to_path_buf();
    let receive_session = Session::new_receive(dest_path, key2, 0);
    assert!(receive_session.manifest().is_none(), "Receive session should not have manifest");
    assert!(receive_session.destination().is_some(), "Receive session should have destination");
}

#[tokio::test]
async fn test_session_claim_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let dest_path = temp_dir.path().to_path_buf();
    let key = EncryptionKey::new();

    let session = Session::new_receive(dest_path, key, 0);
    let token = session.token();
    let client_id = "test-client-123";

    // Test complete workflow: claim -> active -> complete
    assert!(session.claim(token, client_id), "Claim should succeed");
    assert!(session.is_active(token, client_id), "Should be active after claim");
    assert!(session.complete(token, client_id), "Complete should succeed");
}
