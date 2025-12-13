use aes_gcm::{Aes256Gcm, KeyInit};
use archdrop::crypto::types::{EncryptionKey, Nonce};
use archdrop::server::state::TransferConfig;
use archdrop::server::{routes, AppState, Session};
use archdrop::transfer::manifest::Manifest;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tempfile::TempDir;
use tower::ServiceExt;

//===============
// Test Helpers
//===============
const CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10MB
const CLIENT_ID: &str = "test-client-123";

fn default_config() -> TransferConfig {
    TransferConfig {
        chunk_size: CHUNK_SIZE as u64,
        concurrency: 8,
    }
}

fn setup_temp_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

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

// Create send router with state
async fn create_test_send_app(
    file_paths: Vec<PathBuf>,
    key: EncryptionKey,
) -> (Router, Session, u64) {
    let config = default_config();
    let manifest = Manifest::new(file_paths, None, config.clone())
        .await
        .expect("Failed to create manifest");

    let total_chunks = manifest
        .files
        .iter()
        .map(|f| (f.size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64)
        .sum();

    let session = Session::new_send(manifest, key, total_chunks);
    let (progress_sender, _) = tokio::sync::watch::channel(0.0);
    let state = AppState::new_send(session.clone(), progress_sender, config);
    let app = routes::create_send_router(&state);

    (app, session, total_chunks)
}

fn create_cipher(key: &EncryptionKey) -> Aes256Gcm {
    Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()))
}

// Helper to build GET request with query params
fn build_get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("Failed to build request")
}

// Helper to build POST request
fn build_post_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(Body::empty())
        .expect("Failed to build request")
}

// Helper to extract JSON from response
async fn extract_json(response: axum::response::Response) -> serde_json::Value {
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();
    serde_json::from_slice(&body_bytes).expect("Failed to parse JSON")
}

// Helper to extract bytes from response
async fn extract_bytes(response: axum::response::Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes()
        .to_vec()
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
    let (app, _session, _) = create_test_send_app(paths, key.clone()).await;

    let request = build_get_request("/health");
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

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Request manifest
    let uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let request = build_get_request(&uri);
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
        assert!(archdrop::crypto::types::Nonce::from_base64(nonce_str).is_ok());
    }
}

#[tokio::test]
async fn test_chunk_handler_returns_encrypted_data() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    // Create file with 3MB (3 chunks)
    let file_data = vec![0xAB; CHUNK_SIZE * 3];
    let paths = create_test_files(&temp_dir, vec![("large.bin", &file_data)]).await;

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Claim session first by requesting manifest
    let manifest_uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let manifest_req = build_get_request(&manifest_uri);
    let _ = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");

    // Request chunk 1 (middle chunk)
    let chunk_uri = format!(
        "/send/{}/{}/chunk/{}?clientId={}",
        session.token(),
        0,
        1,
        CLIENT_ID
    );
    let request = build_get_request(&chunk_uri);
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
    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Claim session
    let manifest_uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let manifest_req = build_get_request(&manifest_uri);
    let manifest_resp = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");
    let manifest_json = extract_json(manifest_resp).await;
    let file_nonce_str = manifest_json["files"][0]["nonce"].as_str().unwrap();
    let file_nonce = Nonce::from_base64(file_nonce_str).unwrap();

    // Download and decrypt each chunk
    for chunk_idx in 0..3 {
        let chunk_uri = format!(
            "/send/{}/0/chunk/{}?clientId={}",
            session.token(),
            chunk_idx,
            CLIENT_ID
        );
        let request = build_get_request(&chunk_uri);
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), StatusCode::OK);

        let encrypted_chunk = extract_bytes(response).await;

        // Decrypt
        let decrypted = archdrop::crypto::decrypt_chunk_at_position(
            &cipher,
            &file_nonce,
            &encrypted_chunk,
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

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Claim session
    let manifest_uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let manifest_req = build_get_request(&manifest_uri);
    let _ = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");

    // Complete download
    let complete_uri = format!("/send/{}/complete?clientId={}", session.token(), CLIENT_ID);
    let request = build_post_request(&complete_uri);
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let json = extract_json(response).await;
    assert_eq!(json["success"], true);
}

#[tokio::test]
async fn test_hash_handler_returns_sha256() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Test content for hashing";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    // Calculate expected hash
    let mut hasher = Sha256::new();
    hasher.update(file_data);
    let expected_hash = hex::encode(hasher.finalize());

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Claim session
    let manifest_uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let manifest_req = build_get_request(&manifest_uri);
    let _ = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");

    // Request hash
    let hash_uri = format!("/send/{}/0/hash?clientId={}", session.token(), CLIENT_ID);
    let request = build_get_request(&hash_uri);
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let json = extract_json(response).await;
    assert_eq!(json["sha256"].as_str().unwrap(), expected_hash);
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

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Try to request manifest without client_id (should fail or require it)
    // Note: The actual behavior depends on how Axum handles missing query params
    // For now, test with valid client_id to ensure claiming works
    let uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let request = build_get_request(&uri);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send request");

    // Should succeed (this claims the session)
    assert_eq!(response.status(), StatusCode::OK);

    // Now try with different client_id - should fail
    let uri2 = format!(
        "/send/{}/manifest?clientId=different-client",
        session.token()
    );
    let request2 = build_get_request(&uri2);
    let response2 = app.oneshot(request2).await.expect("Failed to send request");

    // Should fail because session is claimed by different client
    // Note: AppError returns 500 for all errors, so we check for any error status
    assert!(
        response2.status().is_client_error() || response2.status().is_server_error(),
        "Expected error status, got: {}",
        response2.status()
    );
}

#[tokio::test]
async fn test_chunk_requires_active_session() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Test file content";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Try to request chunk without claiming session first
    let chunk_uri = format!("/send/{}/0/chunk/0?clientId={}", session.token(), CLIENT_ID);
    let request = build_get_request(&chunk_uri);
    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should fail because session is not claimed
    // Note: AppError returns 500 for all errors, so we check for any error status
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Expected error status, got: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_different_client_id_rejected() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Test file";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Claim with client A
    let manifest_uri = format!("/send/{}/manifest?clientId=client_a", session.token());
    let manifest_req = build_get_request(&manifest_uri);
    let _ = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");

    // Try to request chunk with client B
    let chunk_uri = format!("/send/{}/0/chunk/0?clientId=client_b", session.token());
    let request = build_get_request(&chunk_uri);
    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should fail - different client ID should be rejected
    // Note: AppError returns 500 for all errors, so we check for any error status
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Expected error status, got: {}",
        response.status()
    );
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

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Claim session
    let manifest_uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let manifest_req = build_get_request(&manifest_uri);
    let _ = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");

    // Request chunk 999 (out of bounds)
    let chunk_uri = format!(
        "/send/{}/0/chunk/999?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_get_request(&chunk_uri);
    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should fail
    assert!(response.status().is_client_error() || response.status().is_server_error());
}

#[tokio::test]
async fn test_file_index_out_of_bounds() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = b"Test file";
    let paths = create_test_files(&temp_dir, vec![("test.txt", file_data)]).await;

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Claim session
    let manifest_uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let manifest_req = build_get_request(&manifest_uri);
    let _ = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");

    // Request file index 999 (out of bounds)
    let chunk_uri = format!(
        "/send/{}/999/chunk/0?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_get_request(&chunk_uri);
    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should fail
    assert!(response.status().is_client_error() || response.status().is_server_error());
}

#[tokio::test]
async fn test_duplicate_chunk_request_idempotent() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    let file_data = vec![0xFF; CHUNK_SIZE * 2];
    let paths = create_test_files(&temp_dir, vec![("test.bin", &file_data)]).await;

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;

    // Claim session
    let manifest_uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let manifest_req = build_get_request(&manifest_uri);
    let _ = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");

    // Request same chunk twice
    let chunk_uri = format!("/send/{}/0/chunk/0?clientId={}", session.token(), CLIENT_ID);

    let request1 = build_get_request(&chunk_uri);
    let response1 = app
        .clone()
        .oneshot(request1)
        .await
        .expect("Failed to send request");
    let data1 = extract_bytes(response1).await;

    let request2 = build_get_request(&chunk_uri);
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

    let (app, session, _) = create_test_send_app(paths, key.clone()).await;
    let cipher = create_cipher(&key);

    // Claim session and get nonce
    let manifest_uri = format!("/send/{}/manifest?clientId={}", session.token(), CLIENT_ID);
    let manifest_req = build_get_request(&manifest_uri);
    let manifest_resp = app
        .clone()
        .oneshot(manifest_req)
        .await
        .expect("Failed to get manifest");
    let manifest_json = extract_json(manifest_resp).await;
    let file_nonce_str = manifest_json["files"][0]["nonce"].as_str().unwrap();
    let file_nonce = Nonce::from_base64(file_nonce_str).unwrap();

    // Request last chunk (chunk 2)
    let chunk_uri = format!("/send/{}/0/chunk/2?clientId={}", session.token(), CLIENT_ID);
    let request = build_get_request(&chunk_uri);
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let encrypted_chunk = extract_bytes(response).await;

    // Decrypt
    let decrypted =
        archdrop::crypto::decrypt_chunk_at_position(&cipher, &file_nonce, &encrypted_chunk, 2)
            .expect("Failed to decrypt chunk");

    // Last chunk should be 0.5MB, not 1MB
    assert_eq!(decrypted.len(), CHUNK_SIZE / 2);
    assert!(decrypted.iter().all(|&b| b == 0xCC));
}
