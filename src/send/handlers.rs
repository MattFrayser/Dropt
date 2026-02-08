use std::sync::Arc;

use crate::common::{AppError, Manifest};
use crate::crypto::{self, Nonce};
use crate::send::buffer_pool::BufferPool;
use crate::send::file_handle::SendFileHandle;
use crate::server::auth::{self, ClientIdParam};
use anyhow::{Context, Result};
use axum::extract::Query;
use axum::{
    body::Body,
    extract::{Path, State},
    http::Response,
    Json,
};
use bytes::Bytes;
use reqwest::header;

use super::SendAppState;

#[derive(serde::Deserialize)]
pub struct ChunkParams {
    #[serde(rename = "clientId")]
    client_id: String,
}

// Client will use manifest to know what it is downloading
pub async fn manifest_handler(
    Path(token): Path<String>,
    Query(params): Query<ClientIdParam>,
    State(state): State<SendAppState>,
) -> Result<Json<Manifest>, AppError> {
    // Session claimed when fetching manifest
    // Manifests holds info about files (sizes, names) only client should see
    auth::claim_or_validate_session(&state.session, &token, &params.client_id)?;

    // Get manifest from session
    let manifest = state.manifest();

    // Initialize file tracking for TUI
    let names: Vec<String> = manifest.files.iter().map(|f| f.name.clone()).collect();
    let totals: Vec<u64> = manifest
        .files
        .iter()
        .map(|f| f.size.div_ceil(state.config.chunk_size))
        .collect();
    state.progress.init_files(names, totals);

    Ok(Json(manifest.clone()))
}

pub async fn send_handler(
    Path((token, file_index, chunk_index)): Path<(String, usize, usize)>,
    Query(params): Query<ChunkParams>,
    State(state): State<SendAppState>,
) -> Result<Response<Body>, AppError> {
    // Sessions are claimed by manifest, so just check client
    let client_id = &params.client_id;
    auth::require_active_session(&state.session, &token, client_id)?;

    let file_entry = state
        .get_file(file_index)
        .ok_or_else(|| AppError::BadRequest(format!("file_index out of bounds: {}", file_index)))?;
    let chunk_size = state.config.chunk_size;

    // Some browser send multiple retries (safari)
    // Be noted to not count towards total
    let is_retry = state.has_chunk_been_sent(file_index, chunk_index);
    if !is_retry {
        state.mark_chunk_sent(file_index, chunk_index);
        state.progress.increment_file(file_index);
    }

    // Get or create file handle (lazy initialization)
    let file_handle = state
        .file_handles
        .entry(file_index)
        .or_try_insert_with(|| -> Result<Arc<SendFileHandle>> {
            Ok(Arc::new(SendFileHandle::open(
                file_entry.full_path.clone(),
                file_entry.size,
            )?))
        })?
        .value()
        .clone();

    let encrypted_bytes = process_chunk(
        &file_handle,
        chunk_index,
        state.session.cipher(),
        chunk_size,
        file_entry.size,
        &file_entry.nonce,
        &state.buffer_pool,
    )
    .await?;

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(encrypted_bytes))
        .context("build response")?)
}

async fn process_chunk(
    file_handle: &Arc<SendFileHandle>,
    chunk_index: usize,
    cipher: &Arc<aws_lc_rs::aead::LessSafeKey>,
    chunk_size: u64,
    file_size: u64,
    nonce_str: &str,
    pool: &Arc<BufferPool>,
) -> Result<Bytes> {
    let start = chunk_index as u64 * chunk_size;

    // Validate bounds
    if start >= file_size {
        return Err(anyhow::anyhow!(
            "Chunk start {} exceeds file size {}",
            start,
            file_size
        ));
    }

    let end = std::cmp::min(start + chunk_size, file_size);
    let chunk_len = (end - start) as usize;

    let file_handle = file_handle.clone();
    let cipher = cipher.clone();
    let nonce_str = nonce_str.to_string();
    let pool = pool.clone();

    // Read + encrypt in a single blocking task to avoid double thread-pool scheduling
    tokio::task::spawn_blocking(move || {
        let mut buffer = pool.take();
        file_handle.read_chunk(start, chunk_len, &mut buffer)?;
        let file_nonce = Nonce::from_base64(&nonce_str)?;
        crypto::encrypt_chunk_in_place(&cipher, &file_nonce, &mut buffer, chunk_index as u32)
            .context("Encryption failed")?;
        // Wrap in Bytes that returns the buffer to the pool on drop
        Ok(pool.wrap(buffer))
    })
    .await?
}

pub async fn complete_download(
    Path(token): Path<String>,
    Query(params): Query<ChunkParams>,
    State(state): State<SendAppState>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let client_id = &params.client_id;

    // If the session is ALREADY completed, return 200 OK.
    // Handles the client retrying on network failure.
    // file_complete is idempotent so no need to re-signal progress.
    if state.session.is_completed() {
        return Ok(axum::Json(serde_json::json!({
           "success": true,
           "message": "Already completed"
        })));
    }

    // Session must be active and owned to complete
    auth::require_active_session(&state.session, &token, client_id)?;

    let chunks_sent = state.get_chunks_sent();
    let total_chunks = state.get_total_chunks();

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
    mark_all_files_complete(&state);

    Ok(axum::Json(serde_json::json!({
        "success": true,
        "message": "Download successful. Initiating server shutdown."
    })))
}

fn mark_all_files_complete(state: &SendAppState) {
    let manifest = state.manifest();
    for i in 0..manifest.files.len() {
        state.progress.file_complete(i);
    }
}
