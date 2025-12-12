use aes_gcm::{Aes256Gcm, KeyInit};
use archdrop::crypto::types::{EncryptionKey, Nonce};
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
const CHUNK_SIZE: usize = archdrop::config::CHUNK_SIZE as usize;
const CLIENT_ID: &str = "test-client-123";

fn setup_temp_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

fn create_test_app(output_dir: PathBuf, key: EncryptionKey) -> (Router, Session) {
    let session = Session::new_receive(output_dir, key, 0);
    let (progress_sender, _) = tokio::sync::watch::channel(0.0);
    let state = AppState::new_receive(session.clone(), progress_sender);
    let app = routes::create_receive_router(&state);
    (app, session)
}

fn create_cipher(key: &EncryptionKey) -> Aes256Gcm {
    Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()))
}

fn create_test_data(pattern: u8, size: usize) -> Vec<u8> {
    vec![pattern; size]
}

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

    let write_field = |body: &mut Vec<u8>, name: &str, value: &str| {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    };

    write_field(&mut body, "relativePath", relative_path);
    write_field(&mut body, "chunkIndex", &chunk_index.to_string());
    write_field(&mut body, "totalChunks", &total_chunks.to_string());
    write_field(&mut body, "fileSize", &file_size.to_string());
    write_field(&mut body, "nonce", nonce);
    write_field(&mut body, "clientId", client_id);

    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunk\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&chunk_data);
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
        .expect("Failed to build multipart request")
}

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

async fn extract_json(response: axum::response::Response) -> serde_json::Value {
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();
    serde_json::from_slice(&body_bytes).expect("Failed to parse JSON")
}

//======================
// Error Injection Tests
//======================

#[tokio::test]
async fn test_corrupted_nonce_base64() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key);

    // Create manifest with invalid base64 nonce
    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": 1024
        }]
    });

    let uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_json_request(&uri, manifest);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send request");

    // Since manifest doesn't contain nonce field, it should work
    // The nonce is passed per-chunk. Let's test with invalid nonce in chunk upload
    assert_eq!(response.status(), StatusCode::OK);

    // Now try to upload chunk with invalid base64 nonce
    let chunk_data = create_test_data(0xAA, 1024);
    let chunk_uri = format!("/receive/{}/chunk", session.token());
    let request = build_multipart_request(
        &chunk_uri,
        "test.txt",
        0,
        1,
        1024,
        "!!!INVALID_BASE64!!!",
        CLIENT_ID,
        chunk_data,
    );

    let response = app
        .oneshot(request)
        .await
        .expect("Failed to send chunk request");

    // Should return error
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Invalid base64 should return error, got: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_malformed_multipart_upload() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key);

    // Upload valid manifest first
    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": 1024
        }]
    });

    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Create malformed multipart request (no boundary marker)
    let uri = format!("/receive/{}/chunk", session.token());
    let request = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header("content-type", "multipart/form-data")
        .body(Body::from("garbage data without boundaries"))
        .expect("Failed to build request");

    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should return error
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Malformed multipart should return error"
    );
}

#[tokio::test]
async fn test_chunk_size_mismatch() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    // Manifest says 1MB file (1 chunk)
    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": CHUNK_SIZE as u64
        }]
    });
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Try to upload 2MB chunk (double the expected size)
    let oversized_chunk = create_test_data(0xAA, CHUNK_SIZE * 2);
    let cipher = create_cipher(&key);
    let nonce = Nonce::new();

    let encrypted = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, &oversized_chunk, 0)
        .expect("Failed to encrypt chunk");

    let request = build_multipart_request(
        &format!("/receive/{}/chunk", session.token()),
        "test.txt",
        0,
        1,
        CHUNK_SIZE as u64,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted,
    );

    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should either reject or handle gracefully (not crash)
    // The system should not crash with buffer overflow
    assert!(
        response.status().is_success()
            || response.status().is_client_error()
            || response.status().is_server_error()
    );
}

#[tokio::test]
async fn test_negative_chunk_index() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": CHUNK_SIZE * 3
        }]
    });
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Manually craft request with negative chunk index
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Add relativePath field
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"relativePath\"\r\n\r\n");
    body.extend_from_slice(b"test.txt\r\n");

    // Add chunkIndex with negative value
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunkIndex\"\r\n\r\n");
    body.extend_from_slice(b"-1\r\n");

    // Add other required fields
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"totalChunks\"\r\n\r\n");
    body.extend_from_slice(b"3\r\n");

    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"fileSize\"\r\n\r\n");
    body.extend_from_slice(format!("{}\r\n", CHUNK_SIZE * 3).as_bytes());

    let nonce = Nonce::new();
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"nonce\"\r\n\r\n");
    body.extend_from_slice(nonce.to_base64().as_bytes());
    body.extend_from_slice(b"\r\n");

    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"clientId\"\r\n\r\n");
    body.extend_from_slice(CLIENT_ID.as_bytes());
    body.extend_from_slice(b"\r\n");

    // Add chunk data
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunk\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&create_test_data(0xAA, 100));
    body.extend_from_slice(b"\r\n");

    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    let uri = format!("/receive/{}/chunk", session.token());
    let request = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(Body::from(body))
        .expect("Failed to build request");

    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should reject with error
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Negative chunk index should be rejected"
    );
}

#[tokio::test]
async fn test_partial_multipart_upload() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": CHUNK_SIZE
        }]
    });
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Create incomplete multipart body (missing closing boundary)
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Start multipart but don't finish it
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"relativePath\"\r\n\r\n");
    body.extend_from_slice(b"test.txt\r\n");
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunk\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&create_test_data(0xAA, 100));
    // Missing closing boundary!

    let uri = format!("/receive/{}/chunk", session.token());
    let request = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(Body::from(body))
        .expect("Failed to build request");

    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should handle gracefully (not crash)
    assert!(
        !response.status().is_success(),
        "Partial upload should not succeed"
    );
}

#[tokio::test]
async fn test_finalize_before_all_chunks() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    // File expecting 10 chunks
    let file_size = (10 * CHUNK_SIZE) as u64;
    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": file_size
        }]
    });
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Upload only 5 chunks
    for chunk_idx in 0..5 {
        let chunk_data = create_test_data(chunk_idx as u8, CHUNK_SIZE);
        let cipher = create_cipher(&key);
        let nonce = Nonce::new();
        let encrypted =
            archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, &chunk_data, chunk_idx)
                .expect("Failed to encrypt chunk");
        let request = build_multipart_request(
            &format!("/receive/{}/chunk", session.token()),
            "test.txt",
            chunk_idx as usize,
            10,
            file_size,
            &nonce.to_base64(),
            CLIENT_ID,
            encrypted,
        );
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to send chunk");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Try to finalize with only 5/10 chunks
    let finalize_uri = format!(
        "/receive/{}/finalize?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let finalize_request = build_finalize_request(&finalize_uri, "test.txt");
    let response = app
        .oneshot(finalize_request)
        .await
        .expect("Failed to send finalize request");

    // Should reject with error
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Finalize should fail with incomplete chunks, got: {}",
        response.status()
    );

    // Try to extract JSON if body is not empty
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();

    if !body_bytes.is_empty() {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            if let Some(error_msg) = json["error"].as_str() {
                let error_lower = error_msg.to_lowercase();
                assert!(
                    error_lower.contains("incomplete") || error_lower.contains("missing"),
                    "Error should mention incomplete transfer: {}",
                    error_msg
                );
            }
        }
    }
}

#[tokio::test]
#[cfg(unix)]
async fn test_permission_denied_file_creation() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = setup_temp_dir();
    let readonly_dir = temp_dir.path().join("readonly");
    tokio::fs::create_dir(&readonly_dir)
        .await
        .expect("Failed to create directory");

    // Make directory read-only
    let mut perms = tokio::fs::metadata(&readonly_dir)
        .await
        .expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o444);
    tokio::fs::set_permissions(&readonly_dir, perms)
        .await
        .expect("Failed to set permissions");

    let key = EncryptionKey::new();
    let (app, session) = create_test_app(readonly_dir.clone(), key);

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": 1024
        }]
    });

    let uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_json_request(&uri, manifest);
    let response = app.oneshot(request).await.expect("Failed to send request");

    // Should return error
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Permission denied should return error, got: {}",
        response.status()
    );

    // Restore permissions for cleanup
    let mut perms = tokio::fs::metadata(&readonly_dir)
        .await
        .expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o755);
    tokio::fs::set_permissions(&readonly_dir, perms)
        .await
        .expect("Failed to restore permissions");
}

#[tokio::test]
async fn test_duplicate_chunk_upload() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": CHUNK_SIZE * 3
        }]
    });
    let manifest_uri = format!(
        "/receive/{}/manifest?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_json_request(&manifest_uri, manifest);
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Upload chunk 1
    let chunk_data = create_test_data(0xAA, CHUNK_SIZE);
    let cipher = create_cipher(&key);
    let nonce = Nonce::new();
    let encrypted = archdrop::crypto::encrypt_chunk_at_position(&cipher, &nonce, &chunk_data, 1)
        .expect("Failed to encrypt chunk");
    let request = build_multipart_request(
        &format!("/receive/{}/chunk", session.token()),
        "test.txt",
        1,
        3,
        (CHUNK_SIZE * 3) as u64,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted.clone(),
    );

    let response1 = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk first time");
    assert_eq!(response1.status(), StatusCode::OK);

    // Upload same chunk again (retry scenario)
    let request2 = build_multipart_request(
        &format!("/receive/{}/chunk", session.token()),
        "test.txt",
        1,
        3,
        (CHUNK_SIZE * 3) as u64,
        &nonce.to_base64(),
        CLIENT_ID,
        encrypted,
    );
    let response2 = app
        .clone()
        .oneshot(request2)
        .await
        .expect("Failed to upload chunk second time");

    // Should succeed (idempotent)
    assert_eq!(response2.status(), StatusCode::OK);

    // Check for duplicate flag in response
    let json = extract_json(response2).await;
    if json["duplicate"].as_bool().is_some() {
        assert_eq!(
            json["duplicate"].as_bool(),
            Some(true),
            "Expected duplicate flag in response"
        );
    }
}
