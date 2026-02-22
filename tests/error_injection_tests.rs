//! Error Injection Tests
//!
//! These tests validate error handling under various failure conditions.
//! Heavy tests are marked #[ignore] to keep the default suite fast.
//! Smoke/error-shape tests run by default.
//!
//! Run default: cargo test --test error_injection_tests
//! Run heavy: cargo test --test error_injection_tests -- --ignored
//! Run all: cargo test --test error_injection_tests -- --include-ignored

mod common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use common::receive_http::{
    build_json_request, build_multipart_request, create_receive_test_app, extract_json,
    with_lock_token,
};
use common::{CHUNK_SIZE, create_cipher, setup_temp_dir};
use dropt::crypto::types::{EncryptionKey, Nonce};
use tower::ServiceExt;

fn create_test_app(
    output_dir: std::path::PathBuf,
    key: EncryptionKey,
) -> (axum::Router, dropt::receive::ReceiveAppState) {
    create_receive_test_app(output_dir, key)
}

fn create_test_data(pattern: u8, size: usize) -> Vec<u8> {
    vec![pattern; size]
}

async fn assert_error_response(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_type: &str,
    expected_message_contains: &str,
) {
    assert_eq!(response.status(), expected_status);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], expected_type);
    let message = json["error"]["message"]
        .as_str()
        .expect("error.message should be a string")
        .to_lowercase();
    assert!(
        message.contains(&expected_message_contains.to_lowercase()),
        "error message should contain '{expected_message_contains}', got '{message}'"
    );
}

//======================
// Error Injection Tests
//======================

#[tokio::test]
async fn test_corrupted_nonce_base64() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key);
    let token = state.session.token().to_string();

    // Create manifest with invalid base64 nonce
    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": 1024
        }]
    });

    let uri = "/receive/manifest";
    let request = build_json_request(uri, manifest, &token);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send request");

    // Since manifest doesn't contain nonce field, it should work
    // The nonce is passed per-chunk. Let's test with invalid nonce in chunk upload
    assert_eq!(response.status(), StatusCode::OK);
    let manifest_json = extract_json(response).await;
    let lock_token = manifest_json["lockToken"]
        .as_str()
        .expect("manifest should include lockToken")
        .to_string();

    // Now try to upload chunk with invalid base64 nonce
    let chunk_data = create_test_data(0xAA, 1024);
    let request = build_multipart_request(
        "/receive/chunk",
        "test.txt",
        0,
        1,
        1024,
        "!!!INVALID_BASE64!!!",
        chunk_data,
        &token,
    );

    let response = app
        .oneshot(with_lock_token(request, &lock_token))
        .await
        .expect("Failed to send chunk request");

    assert_error_response(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "internal",
    )
    .await;
}

#[tokio::test]
#[ignore = "stress test: writes 20MB, ~5s - run with --ignored"]
async fn test_chunk_size_mismatch() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    // Manifest says 1MB file (1 chunk)
    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": CHUNK_SIZE as u64
        }]
    });
    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    assert_eq!(manifest_response.status(), StatusCode::OK);
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"]
        .as_str()
        .expect("manifest should include lockToken")
        .to_string();

    // Try to upload 2MB chunk (double the expected size)
    let oversized_chunk = create_test_data(0xAA, CHUNK_SIZE * 2);
    let cipher = create_cipher(&key);
    let nonce = Nonce::new();

    let mut encrypted = oversized_chunk.clone();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted, 0)
        .expect("Failed to encrypt chunk");

    let request = build_multipart_request(
        "/receive/chunk",
        "test.txt",
        0,
        1,
        CHUNK_SIZE as u64,
        &nonce.to_base64(),
        encrypted,
        &token,
    );

    let response = app
        .oneshot(with_lock_token(request, &lock_token))
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_negative_chunk_index() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": CHUNK_SIZE * 3
        }]
    });
    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    assert_eq!(manifest_response.status(), StatusCode::OK);
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"]
        .as_str()
        .expect("manifest should include lockToken")
        .to_string();

    // Manually craft request with negative chunk index
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Add relativePath field
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"relativePath\"\r\n\r\n");
    body.extend_from_slice(b"test.txt\r\n");

    // Add chunkIndex with negative value
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunkIndex\"\r\n\r\n");
    body.extend_from_slice(b"-1\r\n");

    // Add other required fields
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"totalChunks\"\r\n\r\n");
    body.extend_from_slice(b"3\r\n");

    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"fileSize\"\r\n\r\n");
    body.extend_from_slice(format!("{}\r\n", CHUNK_SIZE * 3).as_bytes());

    let nonce = Nonce::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"nonce\"\r\n\r\n");
    body.extend_from_slice(nonce.to_base64().as_bytes());
    body.extend_from_slice(b"\r\n");

    // Add chunk data
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunk\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&create_test_data(0xAA, 100));
    body.extend_from_slice(b"\r\n");

    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let request = Request::builder()
        .method(Method::POST)
        .uri("/receive/chunk")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Transfer-Lock", &lock_token)
        .body(Body::from(body))
        .expect("Failed to build request");

    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_partial_multipart_upload() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": CHUNK_SIZE
        }]
    });
    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    assert_eq!(manifest_response.status(), StatusCode::OK);
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"]
        .as_str()
        .expect("manifest should include lockToken")
        .to_string();

    // Create incomplete multipart body (missing closing boundary)
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Start multipart but don't finish it
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"relativePath\"\r\n\r\n");
    body.extend_from_slice(b"test.txt\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunk\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&create_test_data(0xAA, 100));
    // Missing closing boundary!

    let request = Request::builder()
        .method(Method::POST)
        .uri("/receive/chunk")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .expect("Failed to build request");

    let response = app
        .oneshot(with_lock_token(request, &lock_token))
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
    let (app, state) = create_test_app(readonly_dir.clone(), key);
    let token = state.session.token().to_string();

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.txt",
            "size": 1024
        }]
    });

    let uri = "/receive/manifest";
    let request = build_json_request(uri, manifest, &token);
    let response = app.oneshot(request).await.expect("Failed to send request");

    assert_error_response(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "internal",
    )
    .await;

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
