mod common;

use axum::{
    http::{Method, StatusCode},
    Router,
};
use common::send_http::{
    assert_error_response, build_bearer_request, create_send_test_app, extract_bytes, extract_json,
};
use common::{create_cipher, setup_temp_dir, CHUNK_SIZE};
use dropt::crypto::types::{EncryptionKey, Nonce};
use std::path::PathBuf;
use tempfile::TempDir;
use tower::ServiceExt;

// Create test files and manifest
async fn create_test_files(temp_dir: &TempDir, files: Vec<(&str, &[u8])>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for (name, content) in files {
        let path = temp_dir.path().join(name);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .expect("Failed to create parent dir");
        }
        tokio::fs::write(&path, content)
            .await
            .expect("Failed to write test file");
        paths.push(path);
    }
    paths
}

async fn create_test_send_app(
    file_paths: Vec<PathBuf>,
    key: EncryptionKey,
) -> (Router, dropt::send::SendAppState, u64) {
    create_send_test_app(file_paths, key).await
}

async fn claim_lock_token(app: &Router, token: &str) -> String {
    let request = build_bearer_request(Method::GET, "/send/manifest", token, None);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to claim session");
    assert_eq!(response.status(), StatusCode::OK);
    let json = extract_json(response).await;
    json["lockToken"]
        .as_str()
        .expect("manifest should include lockToken")
        .to_string()
}

//===================
// Happy Path Tests
//===================

#[tokio::test]
async fn test_health_check() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let file_data = b"test";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;
    let (app, _state, _) = create_test_send_app(paths, key.clone()).await;

    let request = build_bearer_request(Method::GET, "/health", "unused", None);
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_manifest_handler_returns_file_list() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    // Create test files
    let file1_data = b"File 1 content";
    let file2_data = b"File 2 content with more data";
    let file3_data = b"File 3";

    let paths = create_test_files(
        &temp_dir,
        vec![
            ("file1.txt", file1_data),
            ("file2.txt", file2_data),
            ("dir/file3.txt", file3_data),
        ],
    )
    .await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;

    // Request manifest
    let token = state.session.token();
    let request = build_bearer_request(Method::GET, "/send/manifest", token, None);
    let response = app.oneshot(request).await.expect("Failed to send request");

    // Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let json = extract_json(response).await;
    let files = json["files"].as_array().expect("files should be array");

    // Should have 3 files
    assert_eq!(files.len(), 3);

    // Verify each file has required fields
    for file in files {
        assert!(file["relative_path"].is_string());
        assert!(file["size"].is_u64());
        assert!(file["nonce"].is_string());

        // Nonce should be valid base64
        let nonce_str = file["nonce"].as_str().unwrap();
        assert!(dropt::crypto::types::Nonce::from_base64(nonce_str).is_ok());
    }
}

#[tokio::test]
async fn test_chunk_handler_returns_encrypted_data() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    // Create file with 3MB (3 chunks)
    let file_data = vec![0xAB; CHUNK_SIZE * 3];
    let paths = create_test_files(&temp_dir, vec![("large.bin", &file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    // Claim session first by requesting manifest
    let lock_token = claim_lock_token(&app, &token).await;

    // Request chunk 1 (middle chunk)
    let request = build_bearer_request(Method::GET, "/send/0/chunk/1", &token, Some(&lock_token));
    let response = app.oneshot(request).await.expect("Failed to send request");

    // Verify response
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );

    let encrypted_chunk = extract_bytes(response).await;

    // Encrypted chunk should be ~1MB (plus 16 bytes for GCM tag)
    assert!(encrypted_chunk.len() > CHUNK_SIZE);
    assert!(encrypted_chunk.len() <= CHUNK_SIZE + 16);
}

#[tokio::test]
async fn test_chunk_decryption_correctness() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let cipher = create_cipher(&key);

    // Create file with distinct patterns for each chunk
    let mut file_data = Vec::new();
    file_data.extend(vec![0x00; CHUNK_SIZE]); // Chunk 0: all zeros
    file_data.extend(vec![0x11; CHUNK_SIZE]); // Chunk 1: all 0x11
    file_data.extend(vec![0x22; CHUNK_SIZE]); // Chunk 2: all 0x22

    let paths = create_test_files(&temp_dir, vec![("test.bin", &file_data)]).await;
    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    // Claim session
    let manifest_req = build_bearer_request(Method::GET, "/send/manifest", &token, None);
    let manifest_resp = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");
    let manifest_json = extract_json(manifest_resp).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();
    let file_nonce_str = manifest_json["files"][0]["nonce"].as_str().unwrap();
    let file_nonce = Nonce::from_base64(file_nonce_str).unwrap();

    // Download and decrypt each chunk
    for chunk_idx in 0..3 {
        let chunk_uri = format!("/send/0/chunk/{}", chunk_idx);
        let request = build_bearer_request(Method::GET, &chunk_uri, &token, Some(&lock_token));
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), StatusCode::OK);

        let encrypted_chunk = extract_bytes(response).await;

        // Decrypt
        let mut decrypted = encrypted_chunk.clone();
        dropt::crypto::decrypt_chunk_in_place(
            &cipher,
            &file_nonce,
            &mut decrypted,
            chunk_idx as u32,
        )
        .expect("Failed to decrypt chunk");

        // Verify pattern
        let expected_byte = match chunk_idx {
            0 => 0x00,
            1 => 0x11,
            2 => 0x22,
            _ => unreachable!(),
        };

        assert_eq!(decrypted.len(), CHUNK_SIZE);
        assert!(decrypted.iter().all(|&b| b == expected_byte));
    }
}

#[tokio::test]
async fn test_complete_download_succeeds() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Small file content";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    // Claim session
    let lock_token = claim_lock_token(&app, &token).await;

    // Fetch required chunk before completing transfer
    let chunk_request =
        build_bearer_request(Method::GET, "/send/0/chunk/0", &token, Some(&lock_token));
    let chunk_response = app
        .clone()
        .oneshot(chunk_request)
        .await
        .expect("Failed to fetch chunk");
    assert_eq!(chunk_response.status(), StatusCode::OK);

    // Complete download
    let request = build_bearer_request(Method::POST, "/send/complete", &token, Some(&lock_token));
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let json = extract_json(response).await;
    assert_eq!(json["success"], true);
}

//===================
// Authentication Tests
//===================

#[tokio::test]
async fn test_manifest_requires_claim() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Test file";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    // First claim should succeed
    let request = build_bearer_request(Method::GET, "/send/manifest", &token, None);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send request");

    // Should succeed (this claims the session)
    assert_eq!(response.status(), StatusCode::OK);

    // Second claim should fail (already claimed)
    let request2 = build_bearer_request(Method::GET, "/send/manifest", &token, None);
    let response2 = app.oneshot(request2).await.expect("Failed to send request");

    assert_error_response(
        response2,
        StatusCode::CONFLICT,
        "conflict",
        "already claimed",
    )
    .await;
}

#[tokio::test]
async fn test_chunk_requires_active_session() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Test file content";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    // Try to request chunk without claiming session first
    let request = build_bearer_request(Method::GET, "/send/0/chunk/0", &token, None);
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_error_response(
        response,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing transfer",
    )
    .await;
}

#[tokio::test]
async fn test_invalid_lock_token_rejected() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Test file";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    let lock_token = claim_lock_token(&app, &token).await;

    // Try to request chunk with wrong lock token
    let bad_lock = format!("{}-bad", lock_token);
    let request = build_bearer_request(Method::GET, "/send/0/chunk/0", &token, Some(&bad_lock));
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_error_response(
        response,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "session not active",
    )
    .await;
}

//===================
// Edge Cases
//===================

#[tokio::test]
async fn test_chunk_index_out_of_bounds() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    // File with only 1 chunk
    let file_data = vec![0xAA; CHUNK_SIZE / 2];
    let paths = create_test_files(&temp_dir, vec![("small.bin", &file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    // Claim session
    let lock_token = claim_lock_token(&app, &token).await;

    // Request chunk 999 (out of bounds)
    let request = build_bearer_request(Method::GET, "/send/0/chunk/999", &token, Some(&lock_token));
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_error_response(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "internal",
    )
    .await;
}

#[tokio::test]
async fn test_file_index_out_of_bounds() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Test file";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    // Claim session
    let lock_token = claim_lock_token(&app, &token).await;

    // Request file index 999 (out of bounds)
    let request = build_bearer_request(Method::GET, "/send/999/chunk/0", &token, Some(&lock_token));
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_error_response(
        response,
        StatusCode::BAD_REQUEST,
        "bad_request",
        "file_index",
    )
    .await;
}

#[tokio::test]
async fn test_duplicate_chunk_request_idempotent() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = vec![0xFF; CHUNK_SIZE * 2];
    let paths = create_test_files(&temp_dir, vec![("test.bin", &file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();

    // Claim session
    let lock_token = claim_lock_token(&app, &token).await;

    // Request same chunk twice
    let chunk_uri = "/send/0/chunk/0";

    let request1 = build_bearer_request(Method::GET, chunk_uri, &token, Some(&lock_token));
    let response1 = app
        .clone()
        .oneshot(request1)
        .await
        .expect("Failed to send request");
    let data1 = extract_bytes(response1).await;

    let request2 = build_bearer_request(Method::GET, chunk_uri, &token, Some(&lock_token));
    let response2 = app.oneshot(request2).await.expect("Failed to send request");
    let data2 = extract_bytes(response2).await;

    // Both requests should return same data
    assert_eq!(data1, data2);
}

#[tokio::test]
async fn test_last_chunk_partial_size() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    // File with 2.5MB (3 chunks: 1MB, 1MB, 0.5MB)
    let file_data = vec![0xCC; CHUNK_SIZE * 2 + CHUNK_SIZE / 2];
    let paths = create_test_files(&temp_dir, vec![("partial.bin", &file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();
    let cipher = create_cipher(&key);

    // Claim session and get nonce
    let manifest_req = build_bearer_request(Method::GET, "/send/manifest", &token, None);
    let manifest_resp = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");
    let manifest_json = extract_json(manifest_resp).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();
    let file_nonce_str = manifest_json["files"][0]["nonce"].as_str().unwrap();
    let file_nonce = Nonce::from_base64(file_nonce_str).unwrap();

    // Request last chunk (chunk 2)
    let request = build_bearer_request(Method::GET, "/send/0/chunk/2", &token, Some(&lock_token));
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let encrypted_chunk = extract_bytes(response).await;

    // Decrypt
    let mut decrypted = encrypted_chunk;
    dropt::crypto::decrypt_chunk_in_place(&cipher, &file_nonce, &mut decrypted, 2)
        .expect("Failed to decrypt chunk");

    // Last chunk should be 0.5MB, not 1MB
    assert_eq!(decrypted.len(), CHUNK_SIZE / 2);
    assert!(decrypted.iter().all(|&b| b == 0xCC));
}

// Issue 1: incomplete transfer must be rejected, not silently marked complete
#[tokio::test]
async fn test_complete_rejected_when_chunks_not_all_served() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Small file content"; // 1 chunk, but we won't fetch it
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();
    let lock_token = claim_lock_token(&app, &token).await;

    // Complete WITHOUT fetching any chunks
    let request = build_bearer_request(Method::POST, "/send/complete", &token, Some(&lock_token));
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_error_response(
        response,
        StatusCode::BAD_REQUEST,
        "bad_request",
        "incomplete",
    )
    .await;
}

// Issue 2: out-of-bounds chunk_index must not inflate the sent chunk count
#[tokio::test]
async fn test_out_of_bounds_chunk_does_not_increment_sent_count() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = vec![0xAA; CHUNK_SIZE / 2]; // 1 chunk
    let paths = create_test_files(&temp_dir, vec![("small.bin", &file_data)]).await;

    let (app, state, _) = create_test_send_app(paths, key.clone()).await;
    let token = state.session.token().to_string();
    let lock_token = claim_lock_token(&app, &token).await;

    // Request out-of-bounds chunk (process_chunk will reject it)
    let request = build_bearer_request(Method::GET, "/send/0/chunk/999", &token, Some(&lock_token));
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        state.unique_chunks_sent(),
        0,
        "failed chunk request must not increment sent_chunks count"
    );
}
