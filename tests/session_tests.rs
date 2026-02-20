mod common;

use dropt::common::Manifest;
use dropt::common::Session;
use dropt::crypto::types::EncryptionKey;
use dropt::receive::ReceiveAppState;
use dropt::send::SendAppState;
use dropt::server::progress::ProgressTracker;
use common::default_config;
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_receive_session_creation() {
    let temp_dir = TempDir::new().unwrap();
    let dest_path = temp_dir.path().to_path_buf();
    let key = EncryptionKey::new();
    let progress = Arc::new(ProgressTracker::new());
    let config = default_config();

    let state = ReceiveAppState::new(key, dest_path.clone(), progress, config);
    let token = state.session.token().to_string();

    assert!(!token.is_empty(), "Token should not be empty");

    // destination() returns &PathBuf (not Option)
    assert_eq!(state.destination(), &dest_path);
}

#[tokio::test]
async fn test_session_claim_valid_token() {
    let key = EncryptionKey::new();
    let session = Session::new(key);
    let token = session.token().to_string();

    // First claim should succeed
    let lock_token = session.claim(&token).expect("First claim should succeed");

    // Second claim should fail once already claimed
    assert!(session.claim(&token).is_err(), "Second claim should fail");

    // Claimed lock should be active
    assert!(session.is_active(&token, &lock_token));
}

#[tokio::test]
async fn test_session_claim_invalid_token() {
    let key = EncryptionKey::new();
    let session = Session::new(key);

    // Wrong token should fail
    assert!(
        session.claim("wrong-token").is_err(),
        "Wrong token should fail"
    );
}

#[tokio::test]
async fn test_session_is_active() {
    let key = EncryptionKey::new();
    let session = Session::new(key);
    let token = session.token().to_string();

    // Not active before claim
    assert!(
        !session.is_active(&token, "any-lock"),
        "Should not be active initially"
    );

    // Claim it
    let lock_token = session.claim(&token).expect("claim should succeed");

    // Now should be active
    assert!(
        session.is_active(&token, &lock_token),
        "Should be active after claim"
    );

    // Different lock token should not be active
    assert!(
        !session.is_active(&token, "different-lock"),
        "Different lock should not be active"
    );
}

#[tokio::test]
async fn test_session_complete() {
    let key = EncryptionKey::new();
    let session = Session::new(key);
    let token = session.token().to_string();

    // Complete without claim should fail
    assert!(
        !session.complete(&token, "missing-lock"),
        "Complete should fail before claim"
    );

    // Claim and then complete
    let lock_token = session.claim(&token).expect("claim should succeed");
    assert!(
        session.complete(&token, &lock_token),
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
    let manifest = Manifest::new(vec![test_file1, test_file2], None, config)
        .await
        .unwrap();
    let key = EncryptionKey::new();
    let total_chunks = manifest.total_chunks(config.chunk_size);
    let progress = Arc::new(ProgressTracker::new());

    let state = SendAppState::new(key, manifest, total_chunks, progress, config);

    // Get files by index
    let file0 = state.get_file(0).expect("Should get file 0");
    let file1 = state.get_file(1).expect("Should get file 1");

    assert_eq!(file0.index, 0);
    assert_eq!(file1.index, 1);
    assert_eq!(file0.name, "file1.txt");
    assert_eq!(file1.name, "file2.txt");

    // Out of bounds should return None
    assert!(state.get_file(999).is_none());
}
