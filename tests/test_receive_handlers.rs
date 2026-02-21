mod common;

use dropt::crypto::types::{EncryptionKey, Nonce};
use axum::{
    http::StatusCode,
};
use common::receive_http::{
    build_finalize_request, build_json_request, build_multipart_request, create_receive_test_app,
    extract_json, with_lock_token,
};
use common::{create_cipher, setup_temp_dir, CHUNK_SIZE};
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


//===================
// Happy Path
//===================
#[tokio::test]
async fn test_complete_file_upload() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    // Generate test file
    let file_data = b"Hello, ArchDrop! This is test data.";
    let nonce = Nonce::new();

    // Send manifest
    let manifest_uri = "/receive/manifest";
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "test.txt",
                "size": file_data.len() as u64
            }
        ]
    });

    let request = build_json_request(manifest_uri, manifest, &token);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    assert_eq!(response.status(), StatusCode::OK);
    let manifest_json = extract_json(response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Send chunk
    let cipher = create_cipher(&key);
    let mut encrypted = file_data.to_vec();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted, 0)
        .expect("Failed to encrypt chunk");

    let request = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "test.txt",
            0,
            1,
            file_data.len() as u64,
            &nonce.to_base64(),
            encrypted,
            &token,
        ),
        &lock_token,
    );

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk");
    assert_eq!(response.status(), StatusCode::OK);

    // Finalize
    let finalize_uri = "/receive/finalize";
    let request = with_lock_token(
        build_finalize_request(finalize_uri, "test.txt", &token),
        &lock_token,
    );

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

#[tokio::test]
async fn test_out_of_order_chunks() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    // Create 3-chunk file with distinct patterns
    let chunk0 = create_test_data(0x00, CHUNK_SIZE);
    let chunk1 = create_test_data(0x11, CHUNK_SIZE);
    let chunk2 = create_test_data(0x22, CHUNK_SIZE);
    let file_size = (3 * CHUNK_SIZE) as u64;
    let nonce = Nonce::new();

    // Send manifest
    let manifest_uri = "/receive/manifest";
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "ordered.bin",
                "size": file_size
            }
        ]
    });

    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    let cipher = create_cipher(&key);

    // Upload in order: 2, 0, 1 (out of order)

    // Chunk 2
    let mut encrypted2 = chunk2.clone();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted2, 2)
        .expect("Failed to encrypt chunk 2");
    let request = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "ordered.bin",
            2,
            3,
            file_size,
            &nonce.to_base64(),
            encrypted2,
            &token,
        ),
        &lock_token,
    );
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk 2");

    // Chunk 0
    let mut encrypted0 = chunk0.clone();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted0, 0)
        .expect("Failed to encrypt chunk 0");
    let request = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "ordered.bin",
            0,
            3,
            file_size,
            &nonce.to_base64(),
            encrypted0,
            &token,
        ),
        &lock_token,
    );
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk 0");

    // Chunk 1
    let mut encrypted1 = chunk1.clone();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted1, 1)
        .expect("Failed to encrypt chunk 1");
    let request = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "ordered.bin",
            1,
            3,
            file_size,
            &nonce.to_base64(),
            encrypted1,
            &token,
        ),
        &lock_token,
    );
    app.clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk 1");

    // Finalize
    let finalize_uri = "/receive/finalize";
    let request = with_lock_token(
        build_finalize_request(finalize_uri, "ordered.bin", &token),
        &lock_token,
    );
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
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    // Send manifest for 6-chunk file
    let num_chunks = 6;
    let file_size = (num_chunks * CHUNK_SIZE) as u64;
    let nonce = Nonce::new();

    let manifest_uri = "/receive/manifest";
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "concurrent.bin",
                "size": file_size
            }
        ]
    });

    let request = build_json_request(manifest_uri, manifest, &token);
    let resp = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    assert_eq!(resp.status(), StatusCode::OK, "Manifest request failed");
    let manifest_json = extract_json(resp).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Upload all 6 chunks concurrently
    let mut tasks = vec![];
    for chunk_idx in 0..num_chunks {
        let app = app.clone();
        let token = token.clone();
        let key = key.clone();
        let nonce = nonce.clone();
        let lock_token = lock_token.clone();

        tasks.push(tokio::spawn(async move {
            // Create distinct chunk data
            let pattern = (chunk_idx as u8) + 0x20;
            let chunk_data = create_test_data(pattern, CHUNK_SIZE);

            // Encrypt
            let cipher = create_cipher(&key);
            let mut encrypted = chunk_data.clone();
            dropt::crypto::encrypt_chunk_in_place(
                &cipher,
                &nonce,
                &mut encrypted,
                chunk_idx as u32,
            )
            .expect("Failed to encrypt chunk");

            // Upload
            let request = with_lock_token(
                build_multipart_request(
                    "/receive/chunk",
                    "concurrent.bin",
                    chunk_idx,
                    num_chunks,
                    file_size,
                    &nonce.to_base64(),
                    encrypted,
                    &token,
                ),
                &lock_token,
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
    let finalize_uri = "/receive/finalize";
    let request = with_lock_token(
        build_finalize_request(finalize_uri, "concurrent.bin", &token),
        &lock_token,
    );

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
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    let data = b"Test data for wrong nonce";
    let correct_nonce = Nonce::new();
    let wrong_nonce = Nonce::new();

    // Send manifest with correct nonce
    let manifest_uri = "/receive/manifest";
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "test.bin",
                "size": data.len() as u64
            }
        ]
    });

    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Encrypt with WRONG nonce
    let cipher = create_cipher(&key);
    let mut encrypted = data.to_vec();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &wrong_nonce, &mut encrypted, 0)
        .expect("Failed to encrypt chunk");

    // Upload chunk with correct nonce in metadata but wrong encrypted data
    let request = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "test.bin",
            0,
            1,
            data.len() as u64,
            &correct_nonce.to_base64(),
            encrypted,
            &token,
        ),
        &lock_token,
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
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    let data = b"Test data";
    let nonce = Nonce::new();
    let cipher = create_cipher(&key);
    let mut encrypted = data.to_vec();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted, 0)
        .expect("Failed to encrypt chunk");

    // Skip manifest, send chunk directly
    let request = build_multipart_request(
        "/receive/chunk",
        "test.bin",
        0,
        1,
        data.len() as u64,
        &nonce.to_base64(),
        encrypted,
        &token,
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
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    let data = b"Duplicate test data";
    let nonce = Nonce::new();

    // Send manifest
    let manifest_uri = "/receive/manifest";
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "duplicate.bin",
                "size": data.len() as u64
            }
        ]
    });

    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Encrypt chunk
    let cipher = create_cipher(&key);
    let mut encrypted = data.to_vec();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted, 0)
        .expect("Failed to encrypt chunk");

    // Upload chunk 0
    let request1 = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "duplicate.bin",
            0,
            1,
            data.len() as u64,
            &nonce.to_base64(),
            encrypted.clone(),
            &token,
        ),
        &lock_token,
    );
    let response1 = app
        .clone()
        .oneshot(request1)
        .await
        .expect("Failed to upload chunk first time");
    assert_eq!(response1.status(), StatusCode::OK);

    // Upload chunk 0 again (network retry)
    let request2 = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "duplicate.bin",
            0,
            1,
            data.len() as u64,
            &nonce.to_base64(),
            encrypted,
            &token,
        ),
        &lock_token,
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

#[tokio::test]
async fn test_premature_finalize_does_not_break_chunk_retries() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    let chunk0 = create_test_data(0xAA, CHUNK_SIZE);
    let chunk1 = create_test_data(0xBB, CHUNK_SIZE);
    let file_size = (2 * CHUNK_SIZE) as u64;
    let nonce = Nonce::new();

    // Send manifest
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "retry-after-finalize.bin",
                "size": file_size
            }
        ]
    });
    let request = build_json_request("/receive/manifest", manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    assert_eq!(manifest_response.status(), StatusCode::OK);
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    let cipher = create_cipher(&key);

    // Upload first chunk only
    let mut encrypted0 = chunk0.clone();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted0, 0)
        .expect("Failed to encrypt chunk 0");
    let request = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "retry-after-finalize.bin",
            0,
            2,
            file_size,
            &nonce.to_base64(),
            encrypted0,
            &token,
        ),
        &lock_token,
    );
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk 0");
    assert_eq!(response.status(), StatusCode::OK);

    // Premature finalize should fail as incomplete
    let request = with_lock_token(
        build_finalize_request("/receive/finalize", "retry-after-finalize.bin", &token),
        &lock_token,
    );
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to call premature finalize");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Retry remaining chunk should still work after failed finalize
    let mut encrypted1 = chunk1.clone();
    dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted1, 1)
        .expect("Failed to encrypt chunk 1");
    let request = with_lock_token(
        build_multipart_request(
            "/receive/chunk",
            "retry-after-finalize.bin",
            1,
            2,
            file_size,
            &nonce.to_base64(),
            encrypted1,
            &token,
        ),
        &lock_token,
    );
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to upload chunk 1");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "chunk retry after failed finalize should succeed"
    );

    // Finalize should now succeed
    let request = with_lock_token(
        build_finalize_request("/receive/finalize", "retry-after-finalize.bin", &token),
        &lock_token,
    );
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to finalize upload");
    assert_eq!(response.status(), StatusCode::OK);

    // Verify output content assembled correctly
    let output_file = temp_dir.path().join("retry-after-finalize.bin");
    let contents = tokio::fs::read(&output_file)
        .await
        .expect("Failed to read output file");
    assert_eq!(&contents[0..16], &[0xAA; 16]);
    assert_eq!(&contents[CHUNK_SIZE..CHUNK_SIZE + 16], &[0xBB; 16]);
}

//=======================
// Disk Space
//=======================
#[tokio::test]
async fn test_manifest_overflow_protection() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key);
    let token = state.session.token().to_string();

    // Create manifest with file sizes that would overflow u64 when summed
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "file1.bin",
                "size": u64::MAX
            },
            {
                "relative_path": "file2.bin",
                "size": 1u64
            }
        ]
    });

    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Should reject due to overflow with 400 Bad Request (client error)
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 Bad Request for invalid manifest, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_manifest_rejects_nonce_counter_overflow() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key);
    let token = state.session.token().to_string();

    let too_many_chunks_size = ((u32::MAX as u64) + 2) * CHUNK_SIZE as u64;
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "nonce-overflow.bin",
                "size": too_many_chunks_size
            }
        ]
    });

    let request = build_json_request("/receive/manifest", manifest, &token);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for nonce counter overflow"
    );

    let json = extract_json(response).await;
    let message = json["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("too large for secure chunk encryption"),
        "Expected clean UX error message, got: {}",
        message
    );
}

#[tokio::test]
async fn test_manifest_accepts_small_transfer() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key);
    let token = state.session.token().to_string();

    // Small transfer that will definitely fit - validates disk space check passes
    let one_mb = 1024 * 1024;
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "small1.bin",
                "size": one_mb
            },
            {
                "relative_path": "small2.bin",
                "size": one_mb
            }
        ]
    });

    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Small transfers should always succeed - validates disk check works
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Small transfer should pass disk space validation"
    );
}

#[tokio::test]
async fn test_manifest_rejects_duplicate_relative_paths() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key);
    let token = state.session.token().to_string();

    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "dup.bin",
                "size": 1024
            },
            {
                "relative_path": "dup.bin",
                "size": 2048
            }
        ]
    });

    let request = build_json_request("/receive/manifest", manifest, &token);
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for duplicate manifest paths"
    );

    let json = extract_json(response).await;
    let message = json["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("duplicate relative_path"),
        "Expected duplicate path error message, got: {}",
        message
    );
}

#[tokio::test]
async fn test_manifest_rejects_on_insufficient_space() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key);
    let token = state.session.token().to_string();

    // Request 1 petabyte - should fail disk space check (no test system has this)
    let one_pb = 1024u64 * 1024 * 1024 * 1024 * 1024;
    let manifest = serde_json::json!({
        "files": [
            {
                "relative_path": "huge.bin",
                "size": one_pb
            }
        ]
    });

    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    // Should fail with server error due to insufficient space
    assert!(
        response.status().is_server_error(),
        "1 PB transfer should be rejected due to insufficient disk space, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_manifest_empty_files_list() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key);
    let token = state.session.token().to_string();

    // Empty manifest should be valid (no overflow, no disk needed)
    let manifest = serde_json::json!({
        "files": []
    });

    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Empty manifest should be accepted"
    );
}
