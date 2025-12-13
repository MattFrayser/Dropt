use aes_gcm::{Aes256Gcm, KeyInit};
use archdrop::crypto::types::{EncryptionKey, Nonce};
use archdrop::server::state::TransferConfig;
use archdrop::server::{routes, AppState, Session};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use sha2::digest::generic_array::GenericArray;
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

// Create router with state for testing
fn create_test_app(output_dir: PathBuf, key: EncryptionKey) -> (Router, Session) {
    let session = Session::new_receive(output_dir, key, 0);
    let (progress_sender, _) = tokio::sync::watch::channel(0.0);
    let config = default_config();
    let state = AppState::new_receive(session.clone(), progress_sender, config);
    let app = routes::create_receive_router(&state);
    (app, session)
}

fn create_cipher(key: &EncryptionKey) -> Aes256Gcm {
    Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()))
}

fn create_test_data(pattern: u8, size: usize) -> Vec<u8> {
    vec![pattern; size]
}

// Helper to build POST request with JSON body
fn build_json_request(uri: &str, json: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json).expect("Failed to serialize JSON"),
        ))
        .expect("Failed to build request")
}

// Helper to build multipart request for chunk upload
fn build_multipart_request(
    uri: &str,
    relative_path: &str,
    chunk_index: usize,
    total_chunks: usize,
    file_size: u64,
    nonce: &str,
    client_id: &str,
    chunk_data: Vec<u8>,
) -> Request<Body> {
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Helper to write a text field
    let write_field = |body: &mut Vec<u8>, name: &str, value: &str| {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    };

    // Add text fields
    write_field(&mut body, "relativePath", relative_path);
    write_field(&mut body, "chunkIndex", &chunk_index.to_string());
    write_field(&mut body, "totalChunks", &total_chunks.to_string());
    write_field(&mut body, "fileSize", &file_size.to_string());
    write_field(&mut body, "nonce", nonce);
    write_field(&mut body, "clientId", client_id);

    // Add binary chunk field
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunk\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&chunk_data);
    body.extend_from_slice(b"\r\n");

    // End boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(Body::from(body))
        .expect("Failed to build multipart request")
}

// Helper to build finalize request
fn build_finalize_request(uri: &str, relative_path: &str) -> Request<Body> {
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"relativePath\"\r\n\r\n");
    body.extend_from_slice(relative_path.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(Body::from(body))
        .expect("Failed to build finalize request")
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

//===================
// Happy Path
//===================
#[tokio::test]
async fn test_complete_file_upload() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    // Generate test file
    let file_data = b"Hello, ArchDrop! This is test data.";
    let nonce = Nonce::new();

    // Send manifest
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "test.txt",
                "size": file_data.len() as u64
            }
        ]
    });

    let request = build_json_request(&manifest_uri, manifest);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    assert_eq!(response.status(), StatusCode::OK);

    // Send chunk
    let cipher = create_cipher(&key);
    let encrypted = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, file_data, 0)
        .expect("Failed to encrypt chunk");

    let chunk_uri = format!("/receive/{}/chunk", session.token());
    let request = build_multipart_request(
        &chunk_uri,
        "test.txt",
        0,
        1,
        file_data.len() as u64,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted,
    );

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk");
    assert_eq!(response.status(), StatusCode::OK);

    // Finalize
    let finalize_uri = format!(
        "/receive/{}/finalize?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_finalize_request(&finalize_uri, "test.txt");

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to finalize upload");
    assert_eq!(response.status(), StatusCode::OK);

    let json = extract_json(response).await;
    let returned_hash = json["sha256"]
        .as_str()
        .expect("Missing sha256 field in response");

    // Verify file written correctly
    let written_file = temp_dir.path().join("test.txt");
    assert!(written_file.exists());

    let contents = tokio::fs::read(&written_file)
        .await
        .expect("Failed to read written file");
    assert_eq!(contents, file_data);

    // Verify hash matches
    use sha2::{Digest, Sha256};
    let expected_hash = hex::encode(Sha256::digest(file_data));
    assert_eq!(returned_hash, expected_hash);
}

//================
// Data Integrity
//================
#[tokio::test]
async fn test_chunk_decryption_correctness() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    let plaintext = b"Known test data for verification";
    let nonce = Nonce::new();

    // Send manifest
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "decrypt_test.bin",
                "size": plaintext.len() as u64
            }
        ]
    });

    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Encrypt and upload chunk
    let cipher = create_cipher(&key);
    let encrypted = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, plaintext, 0)
        .expect("Failed to encrypt chunk");

    let chunk_uri = format!("/receive/{}/chunk", session.token());
    let request = build_multipart_request(
        &chunk_uri,
        "decrypt_test.bin",
        0,
        1,
        plaintext.len() as u64,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted,
    );

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk");
    assert_eq!(response.status(), StatusCode::OK);

    // Finalize
    let finalize_uri = format!(
        "/receive/{}/finalize?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_finalize_request(&finalize_uri, "decrypt_test.bin");

    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to finalize");

    // Verify decryption was exact
    let output_file = temp_dir.path().join("decrypt_test.bin");
    let decrypted_content = tokio::fs::read(&output_file)
        .await
        .expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext, "Decryption must be exact");
}

#[tokio::test]
async fn test_out_of_order_chunks() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    // Create 3-chunk file with distinct patterns
    let chunk0 = create_test_data(0x00, CHUNK_SIZE);
    let chunk1 = create_test_data(0x11, CHUNK_SIZE);
    let chunk2 = create_test_data(0x22, CHUNK_SIZE);
    let file_size = (3 * CHUNK_SIZE) as u64;
    let nonce = Nonce::new();

    // Send manifest
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "ordered.bin",
                "size": file_size
            }
        ]
    });

    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    let cipher = create_cipher(&key);
    let chunk_uri = format!("/receive/{}/chunk", session.token());

    // Upload in order: 2, 0, 1 (out of order)

    // Chunk 2
    let encrypted2 = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, &chunk2, 2)
        .expect("Failed to encrypt chunk 2");
    let request = build_multipart_request(
        &chunk_uri,
        "ordered.bin",
        2,
        3,
        file_size,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted2,
    );
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk 2");

    // Chunk 0
    let encrypted0 = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, &chunk0, 0)
        .expect("Failed to encrypt chunk 0");
    let request = build_multipart_request(
        &chunk_uri,
        "ordered.bin",
        0,
        3,
        file_size,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted0,
    );
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk 0");

    // Chunk 1
    let encrypted1 = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, &chunk1, 1)
        .expect("Failed to encrypt chunk 1");
    let request = build_multipart_request(
        &chunk_uri,
        "ordered.bin",
        1,
        3,
        file_size,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted1,
    );
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk 1");

    // Finalize
    let finalize_uri = format!(
        "/receive/{}/finalize?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_finalize_request(&finalize_uri, "ordered.bin");
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to finalize");

    // Verify chunks are in correct positions
    let output_file = temp_dir.path().join("ordered.bin");
    let contents = tokio::fs::read(&output_file)
        .await
        .expect("Failed to read file");

    // Verify chunk 0 is at start
    assert_eq!(&contents[0..10], &[0x00; 10]);
    // Verify chunk 1 is in middle
    assert_eq!(&contents[CHUNK_SIZE..CHUNK_SIZE + 10], &[0x11; 10]);
    // Verify chunk 2 is at end
    assert_eq!(&contents[2 * CHUNK_SIZE..2 * CHUNK_SIZE + 10], &[0x22; 10]);
}

//===================
// Concurrent Uploads
//===================
#[tokio::test]
async fn test_concurrent_chunks_same_file() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    // Send manifest for 6-chunk file
    let num_chunks = 6;
    let file_size = (num_chunks * CHUNK_SIZE) as u64;
    let nonce = Nonce::new();

    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "concurrent.bin",
                "size": file_size
            }
        ]
    });

    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Upload all 6 chunks concurrently
    let mut tasks = vec![];
    for chunk_idx in 0..num_chunks {
        let app = app.clone();
        let session_token = session.token().to_string();
        let key = key.clone();
        let nonce = nonce.clone();

        tasks.push(tokio::spawn(async move {
            // Create distinct chunk data
            let pattern = (chunk_idx as u8) + 0x20;
            let chunk_data = create_test_data(pattern, CHUNK_SIZE);

            // Encrypt
            let cipher = create_cipher(&key);
            let encrypted = archdrop::crypto::encrypt_chunk_at_position(
                &cipher,
                &nonce,
                &chunk_data,
                chunk_idx as u32,
            )
            .expect("Failed to encrypt chunk");

            // Upload
            let chunk_uri = format!("/receive/{}/chunk", session_token);
            let request = build_multipart_request(
                &chunk_uri,
                "concurrent.bin",
                chunk_idx,
                num_chunks,
                file_size,
                &nonce.to_base64(),
                CLIENT_ID,
                encrypted,
            );

            app.oneshot(request).await.expect("Failed to upload chunk")
        }));
    }

    // Wait for all uploads
    for task in tasks {
        let response = task.await.expect("Task panicked");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Finalize
    let finalize_uri = format!(
        "/receive/{}/finalize?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_finalize_request(&finalize_uri, "concurrent.bin");

    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to finalize");

    // Verify no corruption
    let output_file = temp_dir.path().join("concurrent.bin");
    let contents = tokio::fs::read(&output_file)
        .await
        .expect("Failed to read output file");

    // Verify each chunk's pattern intact
    for chunk_idx in 0..num_chunks {
        let offset = chunk_idx * CHUNK_SIZE;
        let pattern = (chunk_idx as u8) + 0x20;

        for i in 0..100 {
            assert_eq!(
                contents[offset + i],
                pattern,
                "Chunk {} corrupted by concurrent writes",
                chunk_idx
            );
        }
    }
}

//===============
// Error Handling
//===============
#[tokio::test]
async fn test_chunk_wrong_nonce() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    let data = b"Test data for wrong nonce";
    let correct_nonce = Nonce::new();
    let wrong_nonce = Nonce::new();

    // Send manifest with correct nonce
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "test.bin",
                "size": data.len() as u64
            }
        ]
    });

    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Encrypt with WRONG nonce
    let cipher = create_cipher(&key);
    let encrypted = archdrop::crypto::encrypt_chunk_at_position(&cipher, &wrong_nonce, data, 0)
        .expect("Failed to encrypt chunk");

    // Upload chunk with correct nonce in metadata but wrong encrypted data
    let chunk_uri = format!("/receive/{}/chunk", session.token());
    let request = build_multipart_request(
        &chunk_uri,
        "test.bin",
        0,
        1,
        data.len() as u64,
        &correct_nonce.to_base64(),
        CLIENT_ID,
        encrypted,
    );

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send chunk");

    // Should fail decryption
    assert!(
        response.status().is_server_error(),
        "Expected server error for wrong nonce, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_chunk_without_manifest() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    let data = b"Test data";
    let nonce = Nonce::new();
    let cipher = create_cipher(&key);
    let encrypted = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, data, 0)
        .expect("Failed to encrypt chunk");

    // Skip manifest, send chunk directly
    let chunk_uri = format!("/receive/{}/chunk", session.token());
    let request = build_multipart_request(
        &chunk_uri,
        "test.bin",
        0,
        1,
        data.len() as u64,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted,
    );

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send chunk");

    // Should reject (no FileReceiveState exists)
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Expected error for missing manifest, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_duplicate_chunk_detection() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    let data = b"Duplicate test data";
    let nonce = Nonce::new();

    // Send manifest
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "duplicate.bin",
                "size": data.len() as u64
            }
        ]
    });

    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Encrypt chunk
    let cipher = create_cipher(&key);
    let encrypted = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, data, 0)
        .expect("Failed to encrypt chunk");

    let chunk_uri = format!("/receive/{}/chunk", session.token());

    // Upload chunk 0
    let request1 = build_multipart_request(
        &chunk_uri,
        "duplicate.bin",
        0,
        1,
        data.len() as u64,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted.clone(),
    );
    let response1 = app
        .clone()
        .oneshot(request1)
        .await
        .expect("Failed to upload chunk first time");
    assert_eq!(response1.status(), StatusCode::OK);

    // Upload chunk 0 again (network retry)
    let request2 = build_multipart_request(
        &chunk_uri,
        "duplicate.bin",
        0,
        1,
        data.len() as u64,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted,
    );
    let response2 = app
        .clone()
        .oneshot(request2)
        .await
        .expect("Failed to upload chunk second time");
    assert_eq!(response2.status(), StatusCode::OK); // Should succeed but not re-write

    // Check for duplicate flag in response
    let json = extract_json(response2).await;
    assert_eq!(
        json["duplicate"].as_bool(),
        Some(true),
        "Expected duplicate flag in response"
    );
}

//===========
// Secure
//===========
#[tokio::test]
async fn test_manifest_requires_authentication() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key);

    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "test.bin",
                "size": 100
            }
        ]
    });

    // Send manifest without clientId parameter
    let uri = format!("/receive/{}/manifest", session.token());
    let request = build_json_request(&uri, manifest);

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send request");

    // Should reject due to missing clientId
    assert!(
        response.status().is_client_error(),
        "Expected client error for missing clientId, got {}",
        response.status()
    );
}
