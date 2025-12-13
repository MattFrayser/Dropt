use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto;
use crate::crypto::types::Nonce;
use crate::errors::AppError;
use crate::server::auth::{self, ClientIdParam};
use crate::server::state::AppState;
use crate::transfer::manifest::Manifest;
use anyhow::{Context, Result};
use axum::extract::Query;
use axum::{
    body::Body,
    extract::{Path, State},
    http::Response,
    Json,
};
use reqwest::header;
use tokio::time::sleep;

#[derive(serde::Deserialize)]
pub struct ChunkParams {
    #[serde(rename = "clientId")]
    client_id: String,
}

// Client will use manifest to know what it is downloading
pub async fn manifest_handler(
    Path(token): Path<String>,
    Query(params): Query<ClientIdParam>,
    State(state): State<AppState>,
) -> Result<Json<Manifest>, AppError> {
    // Session claimed when fetching manifest
    // Manifests holds info about files (sizes, names) only client should see
    tracing::info!(
        "Manifest request: token={}, client={}",
        token,
        params.client_id
    );
    auth::claim_or_validate_session(&state.session, &token, &params.client_id)?;

    // Get manifest from session
    let manifest = state
        .session
        .manifest()
        .ok_or_else(|| anyhow::anyhow!("Not a send session"))?;

    Ok(Json(manifest.clone()))
}

pub async fn send_handler(
    Path((token, file_index, chunk_index)): Path<(String, usize, usize)>,
    Query(params): Query<ChunkParams>,
    State(state): State<AppState>,
) -> Result<Response<Body>, AppError> {
    // Sessions are claimed by manifest, so just check client
    let client_id = &params.client_id;
    auth::require_active_session(&state.session, &token, client_id)?;
    tracing::debug!(
        "Chunk request START: file={}, chunk={}, client={}",
        file_index,
        chunk_index,
        client_id
    );

    // Some browser send multiple retries (safari) retries should,
    // Be noted to not count towards total
    let is_retry = state.session.has_chunk_been_sent(file_index, chunk_index);

    // Only mark non retries as sent, keeps count accurate
    if !is_retry {
        state.session.mark_chunk_sent(file_index, chunk_index);
    }

    let file_entry = state
        .session
        .get_file(file_index)
        .ok_or_else(|| anyhow::anyhow!("Invalid file index"))?;

    let chunk_size = state.config.chunk_size;

    let encrypted_chunk =
        process_chunk(file_entry, chunk_index, state.session.cipher(), chunk_size).await?;

    // Update Progress (Only first time serving this chunk)
    if !is_retry {
        let (new_total, session_total) = state.session.increment_sent_chunk();
        let raw_progress = (new_total as f64 / session_total as f64) * 100.0;

        // Cap at 99% until explicit completion
        let _ = state.progress_sender.send(raw_progress.min(99.0));
    } else {
        tracing::debug!("Served duplicate chunk {}/{}", file_index, chunk_index);
    }

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(encrypted_chunk))?)
}

async fn process_chunk(
    file_entry: &crate::transfer::manifest::FileEntry,
    chunk_index: usize,
    cipher: &Arc<aes_gcm::Aes256Gcm>,
    chunk_size: u64,
) -> Result<Vec<u8>> {
    let start = chunk_index as u64 * chunk_size;

    // Validate bounds
    if start >= file_entry.size {
        return Err(anyhow::anyhow!(
            "Chunk start {} exceeds file size {}",
            start,
            file_entry.size
        ));
    }

    let end = std::cmp::min(start + chunk_size, file_entry.size);
    let chunk_len = (end - start) as usize;

    // Read from disk
    let buffer = read_chunk_blocking(file_entry.full_path.clone(), start, chunk_len).await?;

    // Prepare data to move into the closure
    let cipher = cipher.clone();
    let nonce_str = file_entry.nonce.clone();

    // Offload encryption to a blocking thread
    // This prevents AES-GCM from stalling the async runtime
    tokio::task::spawn_blocking(move || {
        let file_nonce = Nonce::from_base64(&nonce_str)?;
        crypto::encrypt_chunk_at_position(&cipher, &file_nonce, &buffer, chunk_index as u32)
            .context("Encryption failed")
    })
    .await?
}

pub async fn complete_download(
    Path(token): Path<String>,
    Query(params): Query<ChunkParams>,
    State(state): State<AppState>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    use std::sync::atomic::Ordering;

    // Session must be active and owned to complete
    let client_id = &params.client_id;

    // If the session is ALREADY completed, resend the success signal
    // and return 200 OK. Handles the client retrying on network failure.
    if state.session.complete(&token, client_id) {
        tracing::info!("Duplicate complete request for client: {}", client_id);
        let _ = state.progress_sender.send(100.0);
        return Ok(axum::Json(serde_json::json!({
           "success": true,
           "message": "Already completed"
        })));
    }

    let chunks_sent = state.session.chunks_sent.load(Ordering::SeqCst);
    let total_chunks = state.session.total_chunks.load(Ordering::SeqCst);

    tracing::info!(
        "Complete download request: token={}, client={}, chunks_sent={}/{}",
        token,
        client_id,
        chunks_sent,
        total_chunks
    );

    auth::require_active_session(&state.session, &token, client_id)?;

    // Verify all chunks were actually sent
    if chunks_sent < total_chunks {
        tracing::warn!(
            "Complete called prematurely: {}/{} chunks sent ({}% complete)",
            chunks_sent,
            total_chunks,
            (chunks_sent as f64 / total_chunks as f64 * 100.0)
        );
    }

    state.session.complete(&token, client_id);
    tracing::info!(
        "Transfer marked complete in session state by client: {}",
        client_id
    );

    // preprepare body
    let response_body = axum::Json(serde_json::json!({
        "success": true,
        "message": "Download successful. Initiating server shutdown."
    }));

    // Wait until Axum response leaves to signal shutdown on 100%
    // 50ms should be enough to ensure proper HTTP res
    // clone progress_sender so task can run independantly of func
    let progress_sender_clone = state.progress_sender.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(50)).await;
        eprintln!("TUI shutdown signal (100.0) sent successfully. Exiting now.");
        let _ = progress_sender_clone.send(100.0);
    });

    Ok(response_body)
}

pub async fn get_file_hash(
    Path((token, file_index)): Path<(String, usize)>,
    Query(params): Query<ChunkParams>,
    State(state): State<AppState>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let client_id = &params.client_id;
    auth::require_active_session(&state.session, &token, client_id)?;

    let file_entry = state
        .session
        .get_file(file_index)
        .ok_or_else(|| anyhow::anyhow!("Invalid file index"))?;

    let hash = compute_file_hash(&file_entry.full_path).await?;

    Ok(axum::Json(serde_json::json!({
        "sha256": hash
    })))
}

async fn compute_file_hash(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    // Use spawn_blocking for disk I/O
    let path = path.to_owned();

    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut file = std::fs::File::open(&path).context(format!(
            "Failed to open file for hashing: {}",
            path.display()
        ))?;

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 65536]; // 64 KB chunks

        loop {
            let n = file
                .read(&mut buffer)
                .context("Failed to read file for hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok::<String, anyhow::Error>(hex::encode(hasher.finalize()))
    })
    .await
    .context("Hash computation task panicked")?
}

/// Opens, reads a chunk, and closes the file handle using a blocking task.
async fn read_chunk_blocking(path: PathBuf, start: u64, chunk_len: usize) -> Result<Vec<u8>> {
    // File reading is sync
    tokio::task::spawn_blocking(move || {
        tracing::debug!(
            "Blocking task START: path={:?}, start={}, len={}",
            path,
            start,
            chunk_len
        );

        // Catch panics to prevent lock poisoning
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut file = std::fs::File::open(&path).context(format!(
                "Failed to open file for sending: {}",
                path.display()
            ))?;

            let mut buffer = vec![0u8; chunk_len];

            // Seek to the starting position and read the chunk
            file.seek(SeekFrom::Start(start))
                .context("Failed to seek file")?;

            tracing::debug!(
                "Reading {} bytes from position {} in {:?}",
                chunk_len,
                start,
                path
            );

            file.read_exact(&mut buffer)
                .context("Failed to read chunk")?;

            tracing::debug!("Read complete, buffer size={}", buffer.len());

            Ok::<Vec<u8>, anyhow::Error>(buffer)
        }));

        match result {
            Ok(r) => r,
            Err(panic) => {
                tracing::error!(
                    "PANIC in read_chunk_blocking: {:?}, path={:?}, start={}, len={}",
                    panic,
                    path,
                    start,
                    chunk_len
                );
                Err(anyhow::anyhow!("Panic during file read"))
            }
        }
    })
    .await
    .context("File read task panicked")?
}
