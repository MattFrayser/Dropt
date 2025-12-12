use aes_gcm::{Aes256Gcm, KeyInit};
use archdrop::crypto::types::{EncryptionKey, Nonce};
use archdrop::server::{routes, AppState, Session};
use archdrop::transfer::manifest::Manifest;
use archdrop::transfer::storage::ChunkStorage;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use sha2::digest::generic_array::GenericArray;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;
use tower::ServiceExt;

//===============
// Test Helpers
//===============
const CHUNK_SIZE: usize = archdrop::config::CHUNK_SIZE as usize;
const CHUNK_1MB: usize = 1024 * 1024;
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

fn create_chunk_data(pattern: u8, size_mb: usize) -> Vec<u8> {
    vec![pattern; size_mb * CHUNK_1MB]
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
// Concurrency Stress Tests
//======================

#[tokio::test]
async fn test_concurrent_different_files_same_directory() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

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

    // Upload all files concurrently
    let mut tasks = vec![];
    for file_idx in 0..num_files {
        let app = app.clone();
        let session_token = session.token().to_string();
        let key = key.clone();

        tasks.push(tokio::spawn(async move {
            let filename = format!("file{}.bin", file_idx);
            let pattern = file_idx as u8;
            let chunk_data = create_test_data(pattern, CHUNK_SIZE);
            let nonce = Nonce::new();

            let cipher = create_cipher(&key);
            let encrypted = archdrop::crypto::encrypt_chunk_at_position(
                &cipher,
                &nonce,
                &chunk_data,
                0,
            )
            .expect("Failed to encrypt chunk");

            let chunk_uri = format!("/receive/{}/chunk", session_token);
            let request = build_multipart_request(
                &chunk_uri,
                &filename,
                0,
                1,
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

    // Verify all files exist with correct content
    for file_idx in 0..num_files {
        let filename = format!("file{}.bin", file_idx);
        let path = temp_dir.path().join(&filename);
        assert!(path.exists(), "File {} should exist", filename);

        // Finalize each file
        let finalize_uri = format!(
            "/receive/{}/finalize?clientId={}",
            session.token(),
            CLIENT_ID
        );
        let request = build_finalize_request(&finalize_uri, &filename);
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to finalize");
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content
        let contents = tokio::fs::read(&path)
            .await
            .expect("Failed to read file");
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
        if entry.file_type().await.expect("Failed to get file type").is_file() {
            count += 1;
        }
    }
    assert_eq!(
        count,
        num_files,
        "Should have exactly {} files",
        num_files
    );
}

#[tokio::test]
async fn test_concurrent_chunks_different_files() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

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

    // Upload all 18 chunks concurrently (3 files × 6 chunks)
    let mut tasks = vec![];
    for file_idx in 0..num_files {
        for chunk_idx in 0..chunks_per_file {
            let app = app.clone();
            let session_token = session.token().to_string();
            let key = key.clone();
            let filename = format!("file{}.bin", file_idx);

            tasks.push(tokio::spawn(async move {
                // Distinct pattern: file_idx * 10 + chunk_idx
                let pattern = (file_idx * 10 + chunk_idx) as u8;
                let chunk_data = create_test_data(pattern, CHUNK_SIZE);
                let nonce = Nonce::new();

                let cipher = create_cipher(&key);
                let encrypted = archdrop::crypto::encrypt_chunk_at_position(
                    &cipher,
                    &nonce,
                    &chunk_data,
                    chunk_idx as u32,
                )
                .expect("Failed to encrypt chunk");

                let chunk_uri = format!("/receive/{}/chunk", session_token);
                let request = build_multipart_request(
                    &chunk_uri,
                    &filename,
                    chunk_idx,
                    chunks_per_file,
                    file_size,
                    &nonce.to_base64(),
                    CLIENT_ID,
                    encrypted,
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
        let finalize_uri = format!(
            "/receive/{}/finalize?clientId={}",
            session.token(),
            CLIENT_ID
        );
        let request = build_finalize_request(&finalize_uri, &filename);
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
async fn test_race_finalize_vs_drop() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("race_test.bin");

    // Create storage with all chunks
    let file_size = 3 * CHUNK_1MB as u64;
    let storage = Arc::new(Mutex::new(
        ChunkStorage::new(file_path.clone(), file_size)
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
    let storage_clone1 = Arc::clone(&storage);
    let storage_clone2 = Arc::clone(&storage);

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
async fn test_dashmap_concurrent_session_access() {
    use dashmap::DashMap;

    let temp_dir = setup_temp_dir();

    // Create 10 different file sessions in DashMap
    let sessions = Arc::new(DashMap::new());

    for i in 0..10 {
        let filename = format!("file{}.bin", i);
        let file_path = temp_dir.path().join(&filename);
        let storage = ChunkStorage::new(file_path, 1024 * 1024)
            .await
            .expect("Failed to create storage");

        sessions.insert(filename, Arc::new(Mutex::new(storage)));
    }

    // Spawn 10 tasks, each accessing different session
    let mut tasks = vec![];
    for i in 0..10 {
        let sessions = Arc::clone(&sessions);
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
async fn test_concurrent_chunk_uploads_mutex_contention() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();
    let (app, session) = create_test_app(temp_dir.path().to_path_buf(), key.clone());

    // Single file, 50 chunks
    let num_chunks = 50;
    let file_size = (num_chunks * CHUNK_SIZE) as u64;

    let manifest = serde_json::json!({
        "files": [{
            "relative_path": "large.bin",
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

    // Upload all 50 chunks concurrently
    let mut tasks = vec![];
    for chunk_idx in 0..num_chunks {
        let app = app.clone();
        let session_token = session.token().to_string();
        let key = key.clone();

        tasks.push(tokio::spawn(async move {
            let pattern = chunk_idx as u8;
            let chunk_data = create_test_data(pattern, CHUNK_SIZE);
            let nonce = Nonce::new();

            let cipher = create_cipher(&key);
            let encrypted = archdrop::crypto::encrypt_chunk_at_position(
                &cipher,
                &nonce,
                &chunk_data,
                chunk_idx as u32,
            )
            .expect("Failed to encrypt chunk");

            let chunk_uri = format!("/receive/{}/chunk", session_token);
            let request = build_multipart_request(
                &chunk_uri,
                "large.bin",
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

    // Wait for all
    for task in tasks {
        let response = task.await.expect("Task panicked");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Finalize and verify
    let finalize_uri = format!(
        "/receive/{}/finalize?clientId={}",
        session.token(),
        CLIENT_ID
    );
    let request = build_finalize_request(&finalize_uri, "large.bin");
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

#[tokio::test]
async fn test_concurrent_session_claim_attempts() {
    let temp_dir = setup_temp_dir();
    let key = EncryptionKey::new();

    // Create send session (unclaimed)
    let test_file = temp_dir.path().join("test.txt");
    tokio::fs::write(&test_file, b"test content")
        .await
        .expect("Failed to write test file");

    let manifest = Manifest::new(vec![test_file], None)
        .await
        .expect("Failed to create manifest");
    let total_chunks = manifest.total_chunks();
    let session = Session::new_send(manifest, key, total_chunks);
    let token = session.token().to_string();

    // 5 clients try to claim simultaneously
    let mut tasks = vec![];
    for i in 0..5 {
        let session = session.clone();
        let token = token.clone();
        let client_id = format!("client_{}", i);

        tasks.push(tokio::spawn(async move {
            // Small random delay to simulate network jitter
            let delay_ms = (i * 2) as u64;
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

            session.claim(&token, &client_id)
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
