//! Concurrency Stress Tests
//!
//! These tests validate concurrent file transfer behavior under realistic conditions.
//! Most tests use production chunk sizes (10MB) and are marked #[ignore] due to:
//! - High disk I/O (100-500MB per test)
//! - Encryption overhead with large buffers
//! - Test suite would take 2+ minutes by default
//!
//! Run default: cargo test --test concurrency_stress_tests
//! Run heavy: cargo test --test concurrency_stress_tests -- --ignored
//! Run all: cargo test --test concurrency_stress_tests -- --include-ignored

mod common;

use axum::{http::StatusCode, Router};
use common::receive_http::{
    build_finalize_request, build_json_request, build_multipart_request, create_receive_test_app,
    extract_json, with_lock_token,
};
use common::{create_cipher, setup_temp_dir, CHUNK_SIZE};
use dropt::common::CollisionPolicy;
use dropt::common::Session;
use dropt::common::TransferSettings;
use dropt::crypto::types::{EncryptionKey, Nonce};
use dropt::receive::ChunkStorage;
use dropt::receive::ReceiveAppState;
use dropt::server::progress::ProgressTracker;
use dropt::server::routes;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

const CHUNK_1MB: usize = 1024 * 1024;

fn create_test_app(output_dir: PathBuf, key: EncryptionKey) -> (Router, ReceiveAppState) {
    create_receive_test_app(output_dir, key)
}

fn create_test_app_with_config(
    output_dir: PathBuf,
    key: EncryptionKey,
    config: TransferSettings,
) -> (Router, ReceiveAppState) {
    let progress = Arc::new(ProgressTracker::new());
    let state = ReceiveAppState::new(
        key,
        output_dir,
        progress,
        config,
        CollisionPolicy::default(),
    );
    let app = routes::create_receive_router(&state);
    (app, state)
}

fn create_test_data(pattern: u8, size: usize) -> Vec<u8> {
    vec![pattern; size]
}

fn create_chunk_data(pattern: u8, size_mb: usize) -> Vec<u8> {
    vec![pattern; size_mb * CHUNK_1MB]
}

//======================
// Concurrency Stress Tests
//======================

#[tokio::test]
#[ignore = "stress test: writes 100MB, ~15s - run with --ignored"]
async fn test_concurrent_different_files_same_directory() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    // Create manifest with 10 different files
    let num_files = 10;
    let mut file_entries = vec![];
    let file_size = CHUNK_SIZE as u64;

    for i in 0..num_files {
        file_entries.push(serde_json::json!({
            "relative_path": format!("file{}.bin", i),
            "size": file_size
        }));
    }

    let manifest = serde_json::json!({ "files": file_entries });
    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Upload all files concurrently
    let mut tasks = vec![];
    for file_idx in 0..num_files {
        let app = app.clone();
        let token = token.clone();
        let key = key.clone();
        let lock_token = lock_token.clone();

        tasks.push(tokio::spawn(async move {
            let filename = format!("file{}.bin", file_idx);
            let pattern = file_idx as u8;
            let chunk_data = create_test_data(pattern, CHUNK_SIZE);
            let nonce = Nonce::new();

            let cipher = create_cipher(&key);
            let mut encrypted = chunk_data.clone();
            dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted, 0)
                .expect("Failed to encrypt chunk");

            let request = with_lock_token(
                build_multipart_request(
                    "/receive/chunk",
                    &filename,
                    0,
                    1,
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

    // Verify all files exist with correct content
    for file_idx in 0..num_files {
        let filename = format!("file{}.bin", file_idx);
        let path = temp_dir.path().join(&filename);
        assert!(path.exists(), "File {} should exist", filename);

        // Finalize each file
        let finalize_uri = "/receive/finalize";
        let request = with_lock_token(
            build_finalize_request(finalize_uri, &filename, &token),
            &lock_token,
        );
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to finalize");
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content
        let contents = tokio::fs::read(&path).await.expect("Failed to read file");
        let pattern = file_idx as u8;
        assert!(
            contents.iter().all(|&b| b == pattern),
            "File {} should contain pattern {:02x}",
            filename,
            pattern
        );
    }

    // Verify no extra files were created
    let mut read_dir = tokio::fs::read_dir(temp_dir.path())
        .await
        .expect("Failed to read directory");
    let mut count = 0;
    while let Some(entry) = read_dir.next_entry().await.expect("Failed to read entry") {
        if entry
            .file_type()
            .await
            .expect("Failed to get file type")
            .is_file()
        {
            count += 1;
        }
    }
    assert_eq!(count, num_files, "Should have exactly {} files", num_files);
}

#[tokio::test]
#[ignore = "stress test: writes 180MB, ~20s - run with --ignored"]
async fn test_concurrent_chunks_different_files() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    // 3 files, each 6 chunks
    let num_files = 3;
    let chunks_per_file = 6;
    let file_size = (chunks_per_file * CHUNK_SIZE) as u64;

    let mut file_entries = vec![];
    for i in 0..num_files {
        file_entries.push(serde_json::json!({
            "relative_path": format!("file{}.bin", i),
            "size": file_size
        }));
    }

    let manifest = serde_json::json!({ "files": file_entries });
    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Upload all 18 chunks concurrently (3 files x 6 chunks)
    // Each file stream must keep a stable base nonce across all chunks.
    let file_nonce_b64: Vec<String> = (0..num_files).map(|_| Nonce::new().to_base64()).collect();
    let mut tasks = vec![];
    for file_idx in 0..num_files {
        for chunk_idx in 0..chunks_per_file {
            let app = app.clone();
            let token = token.clone();
            let key = key.clone();
            let lock_token = lock_token.clone();
            let filename = format!("file{}.bin", file_idx);
            let nonce_b64 = file_nonce_b64[file_idx].clone();
            let nonce = Nonce::from_base64(&nonce_b64).unwrap();

            tasks.push(tokio::spawn(async move {
                // Distinct pattern: file_idx * 10 + chunk_idx
                let pattern = (file_idx * 10 + chunk_idx) as u8;
                let chunk_data = create_test_data(pattern, CHUNK_SIZE);

                let cipher = create_cipher(&key);
                let mut encrypted = chunk_data.clone();
                dropt::crypto::encrypt_chunk_in_place(
                    &cipher,
                    &nonce,
                    &mut encrypted,
                    chunk_idx as u32,
                )
                .expect("Failed to encrypt chunk");

                let request = with_lock_token(
                    build_multipart_request(
                        "/receive/chunk",
                        &filename,
                        chunk_idx,
                        chunks_per_file,
                        file_size,
                        &nonce_b64,
                        encrypted,
                        &token,
                    ),
                    &lock_token,
                );

                app.oneshot(request).await.expect("Failed to upload chunk")
            }));
        }
    }

    // Wait for all
    for task in tasks {
        let response = task.await.expect("Task panicked");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Finalize all files and verify
    for file_idx in 0..num_files {
        let filename = format!("file{}.bin", file_idx);
        let finalize_uri = "/receive/finalize";
        let request = with_lock_token(
            build_finalize_request(finalize_uri, &filename, &token),
            &lock_token,
        );
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to finalize");
        assert_eq!(response.status(), StatusCode::OK);

        // Verify chunk patterns
        let path = temp_dir.path().join(&filename);
        let contents = tokio::fs::read(&path).await.expect("Failed to read file");

        for chunk_idx in 0..chunks_per_file {
            let offset = chunk_idx * CHUNK_SIZE;
            let expected_pattern = (file_idx * 10 + chunk_idx) as u8;

            // Check first 100 bytes of each chunk
            for i in 0..100 {
                assert_eq!(
                    contents[offset + i],
                    expected_pattern,
                    "File {} chunk {} corrupted at offset {}",
                    file_idx,
                    chunk_idx,
                    i
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "stress test: writes 3MB, ~5s - run with --ignored"]
async fn test_race_finalize_vs_drop() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("race_test.bin");

    // Create storage with all chunks
    let file_size = 3 * CHUNK_1MB as u64;
    let storage = Arc::new(Mutex::new(
        ChunkStorage::new(file_path.clone(), file_size, CHUNK_1MB as u64)
            .await
            .expect("Failed to create storage"),
    ));

    // Write all chunks
    for i in 0..3 {
        let mut storage = storage.lock().await;
        storage
            .store_chunk(i, &create_chunk_data(0xAA, 1))
            .await
            .expect("Failed to store chunk");
    }

    // Spawn two racing tasks
    let storage_clone1 = storage.clone();
    let storage_clone2 = storage.clone();

    // Task 1: Finalize after 10ms delay
    let finalize_task = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let mut storage = storage_clone1.lock().await;
        storage.finalize().await
    });

    // Task 2: Drop immediately (releases reference)
    let drop_task = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        drop(storage_clone2);
    });

    // Wait for both
    let finalize_result = finalize_task.await.expect("Task panicked");
    drop_task.await.expect("Task panicked");

    // Finalize should succeed - file should exist
    assert!(
        finalize_result.is_ok(),
        "Finalize should succeed: {:?}",
        finalize_result
    );
    assert!(
        file_path.exists(),
        "File should be preserved after finalize"
    );

    // Verify hash
    let hash = finalize_result.unwrap();
    assert_eq!(hash.len(), 64, "SHA256 hash should be 64 hex chars");
}

#[tokio::test]
#[ignore = "stress test: writes 10MB, ~5s - run with --ignored"]
async fn test_dashmap_concurrent_session_access() {
    use dashmap::DashMap;

    let temp_dir = setup_temp_dir();

    // Create 10 different file sessions in DashMap
    let sessions = Arc::new(DashMap::new());

    for i in 0..10 {
        let filename = format!("file{}.bin", i);
        let file_path = temp_dir.path().join(&filename);
        let storage = ChunkStorage::new(file_path, CHUNK_1MB as u64, CHUNK_1MB as u64)
            .await
            .expect("Failed to create storage");

        sessions.insert(filename, Arc::new(Mutex::new(storage)));
    }

    // Spawn 10 tasks, each accessing different session
    let mut tasks = vec![];
    for i in 0..10 {
        let sessions = sessions.clone();
        let filename = format!("file{}.bin", i);

        tasks.push(tokio::spawn(async move {
            let pattern = (i * 10) as u8;
            let chunk_data = create_chunk_data(pattern, 1);

            // Access session from DashMap
            let file_state = sessions.get(&filename).expect("Session not found");
            let mut state = file_state.lock().await;

            // Write chunk
            state
                .store_chunk(0, &chunk_data)
                .await
                .expect("Failed to store chunk");

            // Finalize
            state.finalize().await
        }));
    }

    // Wait for all - should complete without deadlocks
    for task in tasks {
        let result = task.await.expect("Task panicked");
        assert!(
            result.is_ok(),
            "Each session should finalize successfully: {:?}",
            result
        );
    }

    // Verify 10 separate sessions, no interference
    assert_eq!(sessions.len(), 10);
}

#[tokio::test]
#[ignore = "stress test: writes 500MB, ~60s+ - run with --ignored"]
async fn test_concurrent_chunk_uploads_mutex_contention() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, state) = create_test_app(temp_dir.path().to_path_buf(), key.clone());
    let token = state.session.token().to_string();

    // Single file, 50 chunks
    let num_chunks = 50;
    let file_size = (num_chunks * CHUNK_SIZE) as u64;

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "large.bin",
            "size": file_size
        }]
    });
    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Upload all 50 chunks concurrently - all chunks share a base nonce.
    let shared_nonce = Nonce::new();
    let nonce_b64 = shared_nonce.to_base64();
    let mut tasks = vec![];
    for chunk_idx in 0..num_chunks {
        let app = app.clone();
        let token = token.clone();
        let key = key.clone();
        let lock_token = lock_token.clone();
        let nonce_b64 = nonce_b64.clone();
        let nonce = Nonce::from_base64(&nonce_b64).unwrap();

        tasks.push(tokio::spawn(async move {
            let pattern = chunk_idx as u8;
            let chunk_data = create_test_data(pattern, CHUNK_SIZE);

            let cipher = create_cipher(&key);
            let mut encrypted = chunk_data.clone();
            dropt::crypto::encrypt_chunk_in_place(
                &cipher,
                &nonce,
                &mut encrypted,
                chunk_idx as u32,
            )
            .expect("Failed to encrypt chunk");

            let request = with_lock_token(
                build_multipart_request(
                    "/receive/chunk",
                    "large.bin",
                    chunk_idx,
                    num_chunks,
                    file_size,
                    &nonce_b64,
                    encrypted,
                    &token,
                ),
                &lock_token,
            );

            app.oneshot(request).await.expect("Failed to upload chunk")
        }));
    }

    // Wait for all
    for task in tasks {
        let response = task.await.expect("Task panicked");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Finalize and verify
    let finalize_uri = "/receive/finalize";
    let request = with_lock_token(
        build_finalize_request(finalize_uri, "large.bin", &token),
        &lock_token,
    );
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to finalize");
    assert_eq!(response.status(), StatusCode::OK);

    // File should exist with correct size
    let path = temp_dir.path().join("large.bin");
    let metadata = tokio::fs::metadata(&path)
        .await
        .expect("Failed to get metadata");
    assert_eq!(metadata.len(), file_size);

    // Verify chunks in correct positions
    let contents = tokio::fs::read(&path).await.expect("Failed to read file");
    for chunk_idx in 0..num_chunks {
        let offset = chunk_idx * CHUNK_SIZE;
        let pattern = chunk_idx as u8;

        // Check first 10 bytes of each chunk
        for i in 0..10 {
            assert_eq!(
                contents[offset + i],
                pattern,
                "Chunk {} corrupted at offset {}",
                chunk_idx,
                i
            );
        }
    }
}

//======================
// Fast Smoke Tests (always run)
//======================

/// Fast smoke test: validates concurrent file upload with small chunks
#[tokio::test]
async fn test_concurrent_upload_smoke() {
    const SMALL_CHUNK: usize = 64 * 1024; // 64KB (fast)

    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let small_config = TransferSettings {
        chunk_size: SMALL_CHUNK as u64,
        concurrency: 4,
    };
    let (app, state) =
        create_test_app_with_config(temp_dir.path().to_path_buf(), key.clone(), small_config);
    let token = state.session.token().to_string();

    // 3 files, 64KB each = 192KB total (fast)
    let mut file_entries = vec![];
    for i in 0..3 {
        file_entries.push(serde_json::json!({
            "relative_path": format!("file{}.bin", i),
            "size": SMALL_CHUNK as u64
        }));
    }

    let manifest = serde_json::json!({ "files": file_entries });
    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Upload all files concurrently
    let mut tasks = vec![];
    for file_idx in 0..3 {
        let app = app.clone();
        let token = token.clone();
        let key = key.clone();
        let lock_token = lock_token.clone();

        tasks.push(tokio::spawn(async move {
            let filename = format!("file{}.bin", file_idx);
            let pattern = file_idx as u8;
            let chunk_data = create_test_data(pattern, SMALL_CHUNK);
            let nonce = Nonce::new();

            let cipher = create_cipher(&key);
            let mut encrypted = chunk_data.clone();
            dropt::crypto::encrypt_chunk_in_place(&cipher, &nonce, &mut encrypted, 0)
                .expect("Failed to encrypt chunk");

            let request = with_lock_token(
                build_multipart_request(
                    "/receive/chunk",
                    &filename,
                    0,
                    1,
                    SMALL_CHUNK as u64,
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

    // Verify all files exist
    for file_idx in 0..3 {
        let filename = format!("file{}.bin", file_idx);
        let path = temp_dir.path().join(&filename);
        assert!(path.exists(), "File {} should exist", filename);
    }
}

/// Fast smoke test: validates concurrent chunk upload with small data
#[tokio::test]
async fn test_concurrent_chunks_smoke() {
    const SMALL_CHUNK: usize = 64 * 1024; // 64KB

    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let small_config = TransferSettings {
        chunk_size: SMALL_CHUNK as u64,
        concurrency: 4,
    };
    let (app, state) =
        create_test_app_with_config(temp_dir.path().to_path_buf(), key.clone(), small_config);
    let token = state.session.token().to_string();

    // 1 file, 4 chunks = 256KB total (fast)
    let num_chunks = 4;
    let file_size = (num_chunks * SMALL_CHUNK) as u64;

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "test.bin",
            "size": file_size
        }]
    });
    let manifest_uri = "/receive/manifest";
    let request = build_json_request(manifest_uri, manifest, &token);
    let manifest_response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to send manifest");
    let manifest_json = extract_json(manifest_response).await;
    let lock_token = manifest_json["lockToken"].as_str().unwrap().to_string();

    // Upload all chunks concurrently — all chunks share a single nonce (correct protocol)
    let shared_nonce = Nonce::new();
    let nonce_b64 = shared_nonce.to_base64();
    let mut tasks = vec![];
    for chunk_idx in 0..num_chunks {
        let app = app.clone();
        let token = token.clone();
        let key = key.clone();
        let lock_token = lock_token.clone();
        let nonce_b64 = nonce_b64.clone();
        let nonce = Nonce::from_base64(&nonce_b64).unwrap();

        tasks.push(tokio::spawn(async move {
            let pattern = chunk_idx as u8;
            let chunk_data = create_test_data(pattern, SMALL_CHUNK);

            let cipher = create_cipher(&key);
            let mut encrypted = chunk_data.clone();
            dropt::crypto::encrypt_chunk_in_place(
                &cipher,
                &nonce,
                &mut encrypted,
                chunk_idx as u32,
            )
            .expect("Failed to encrypt chunk");

            let request = with_lock_token(
                build_multipart_request(
                    "/receive/chunk",
                    "test.bin",
                    chunk_idx,
                    num_chunks,
                    file_size,
                    &nonce_b64,
                    encrypted,
                    &token,
                ),
                &lock_token,
            );

            app.oneshot(request).await.expect("Failed to upload chunk")
        }));
    }

    // Wait for all
    for task in tasks {
        let response = task.await.expect("Task panicked");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Verify file exists with correct size
    let path = temp_dir.path().join("test.bin");
    let metadata = tokio::fs::metadata(&path)
        .await
        .expect("Failed to get metadata");
    assert_eq!(metadata.len(), file_size);
}

#[tokio::test]
async fn test_concurrent_session_claim_attempts() {
    let key = EncryptionKey::new();

    // Create session directly (only need claim/token for this test)
    let session = Session::new(key);
    let token = session.token().to_string();

    // 5 clients try to claim simultaneously
    let mut tasks = vec![];
    for i in 0..5 {
        let session = session.clone();
        let token = token.clone();

        tasks.push(tokio::spawn(async move {
            // Small random delay to simulate network jitter
            let delay_ms = (i * 2) as u64;
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

            session.claim(&token).is_ok()
        }));
    }

    // Collect results
    let mut results = vec![];
    for task in tasks {
        let claimed = task.await.expect("Task panicked");
        results.push(claimed);
    }

    // Exactly 1 should succeed, 4 should fail
    let success_count = results.iter().filter(|&&r| r).count();
    assert_eq!(
        success_count, 1,
        "Exactly one client should claim session, got {}",
        success_count
    );
}
