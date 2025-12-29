use std::sync::Arc;

use crate::common::{AppError, Session};
use crate::crypto::types::Nonce;
use crate::receive::state::{FileReceiveState, ReceiveAppState};
use crate::receive::storage::{self, ChunkStorage};
use crate::server::auth::{self, ClientIdParam};
use crate::utils::security;
use anyhow::{Context, Result};
use axum::extract::{Multipart, Path, Query, State};
use axum::Json;
use axum_typed_multipart::{TryFromMultipart, TypedMultipart};
use bytes::Bytes;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio_util::bytes;

#[derive(serde::Deserialize)]
pub struct ClientManifestEntry {
    pub relative_path: String,
    pub size: u64,
}

#[derive(serde::Deserialize)]
pub struct ClientManifest {
    pub files: Vec<ClientManifestEntry>,
}

#[derive(TryFromMultipart)]
pub struct ChunkUploadRequest {
    #[form_data(limit = "12MB")]
    pub chunk: Bytes,
    #[form_data(field_name = "relativePath")]
    pub relative_path: String,
    #[form_data(field_name = "chunkIndex")]
    pub chunk_index: usize,
    pub nonce: Option<String>,
    #[form_data(field_name = "clientId")]
    pub client_id: String,
}

pub async fn receive_manifest(
    Path(token): Path<String>,
    Query(params): Query<ClientIdParam>,
    State(state): State<ReceiveAppState>,
    Json(manifest): Json<ClientManifest>,
) -> Result<axum::Json<Value>, AppError> {
    let client_id = &params.client_id;

    tracing::debug!(
        "Manifest request - token: '{}', client_id: '{}', files: {}",
        token,
        client_id,
        manifest.files.len()
    );

    // Claim session with manifest
    auth::claim_or_validate_session(&state.session, &token, client_id)?;

    let receive_session = &state.receive_sessions;

    let destination = state.session.destination().clone();

    let chunk_size = state.config.chunk_size;

    // Validate manifest before allocating disk space
    let mut total_size: u64 = 0;
    for file in &manifest.files {
        total_size = total_size
            .checked_add(file.size)
            .ok_or_else(|| AppError::BadRequest("manifest size overflow".to_string()))?;
    }
    storage::check_disk_space(&destination, total_size)
        .map_err(|e| AppError::InsufficientStorage(e.to_string()))?;

    let mut session_total_chunks = 0;

    // Precreate file sessions to prevent race conditions during parallel upload
    for file in manifest.files {
        let file_chunks = file.size.div_ceil(chunk_size);
        session_total_chunks += file_chunks;

        let file_id = security::hash_path(&file.relative_path);

        // If session already exists (on retry), skip creation to avoid truncating data
        if receive_session.contains_key(&file_id) {
            continue;
        }

        // Validate & create path
        security::validate_path(&file.relative_path)
            .map_err(|e| AppError::BadRequest(format!("bad path: {}", e)))?;
        let dest_path = destination.join(&file.relative_path);

        // Initialize storage (creates/truncates file) safely here in serial order
        let storage = ChunkStorage::new(dest_path, file.size, chunk_size)
            .await
            .context("create storage")?;

        let new_state = FileReceiveState {
            storage,
            total_chunks: file_chunks as usize,
            nonce: String::new(), // Will be populated by the first arriving chunk
            relative_path: file.relative_path,
            file_size: file.size,
        };

        receive_session.insert(file_id, Arc::new(Mutex::new(new_state)));
    }

    // Update session with total chunks
    state.session.set_total_chunks(session_total_chunks);

    Ok(Json(json!({
        "success": true,
        "total_chunks": session_total_chunks,
        "config": state.config
    })))
}

pub async fn receive_handler(
    Path(token): Path<String>,
    State(state): State<ReceiveAppState>,
    TypedMultipart(payload): TypedMultipart<ChunkUploadRequest>,
) -> Result<axum::Json<Value>, AppError> {
    let start = std::time::Instant::now();
    let receive_sessions = &state.receive_sessions;

    let file_id = security::hash_path(&payload.relative_path);
    let client_id = &payload.client_id;

    auth::require_active_session(&state.session, &token, client_id)?;

    tracing::debug!(
        "Chunk {} of {} - auth: {:?}",
        payload.chunk_index,
        payload.relative_path,
        start.elapsed()
    );

    // Sessions are made in manifest, so well just get
    let file_session_mutex = receive_sessions
        .get(&file_id)
        .ok_or_else(|| AppError::BadRequest("session not found".to_string()))?
        .clone();

    // Decrypt outside of mutex lock
    let nonce_string = payload.nonce.clone().ok_or_else(|| {
        AppError::BadRequest("missing nonce".to_string())
    })?;
    if nonce_string.is_empty() {
        return Err(AppError::BadRequest("nonce empty".to_string()));
    }
    let nonce = Nonce::from_base64(&nonce_string)?;

    // Clone what is needed for the thread
    let cipher = state.session.cipher().clone();
    let chunk_data = payload.chunk.clone();
    let chunk_index = payload.chunk_index;
    let nonce_val = nonce.clone();

    // Offload CPU work
    let decrypt_start = std::time::Instant::now();
    let decrypted_data = tokio::task::spawn_blocking(move || {
        crate::crypto::decrypt_chunk_at_position(
            &cipher,
            &nonce_val,
            &chunk_data,
            chunk_index as u32,
        )
    })
    .await
    .context("decrypt task panicked")?
    .context("decrypt failed")?;

    tracing::debug!(
        "Chunk {} - decrypt: {:?}",
        payload.chunk_index,
        decrypt_start.elapsed()
    );

    // File should be locked when writing
    let lock_start = std::time::Instant::now();
    let mut session = file_session_mutex.lock().await;
    tracing::debug!(
        "Chunk {} - lock wait: {:?}",
        payload.chunk_index,
        lock_start.elapsed()
    );

    // Update nonce in state if this was first chunk
    if session.nonce.is_empty() {
        session.nonce = nonce_string;
    }

    // Check duplicates
    if session.storage.has_chunk(payload.chunk_index) {
        return Ok(axum::Json(json!({
            "success": true,
            "duplicate": true,
        })));
    }

    let write_start = std::time::Instant::now();
    session
        .storage
        .store_chunk(payload.chunk_index, &decrypted_data)
        .await?;

    tracing::debug!(
        "Chunk {} - disk write: {:?}, total: {:?}",
        payload.chunk_index,
        write_start.elapsed(),
        start.elapsed()
    );

    // Track progress
    let (_chunks_processed, _total_chunks) = state.session.increment_received_chunk();
    state.progress.increment();

    Ok(Json(json!({
        "success": true,
    })))
}
pub async fn finalize_upload(
    Path(token): Path<String>,
    Query(params): Query<ClientIdParam>,
    State(state): State<ReceiveAppState>,
    mut multipart: Multipart,
) -> Result<axum::Json<Value>, AppError> {
    let receive_sessions = &state.receive_sessions;

    // Validate session
    let client_id = &params.client_id;
    auth::require_active_session(&state.session, &token, client_id)?;

    let mut relative_path = None;
    while let Some(field) = multipart.next_field().await.context("read multipart field")? {
        if field.name() == Some("relativePath") {
            relative_path = Some(field.text().await.context("read relativePath")?);
            break;
        }
    }
    let relative_path = relative_path.ok_or_else(|| AppError::BadRequest("missing relative_path".to_string()))?;

    // Generate file ID and remove from sessions map
    let file_id = security::hash_path(&relative_path);

    let (_key, session_mutex) = receive_sessions
        .remove(&file_id)
        .ok_or_else(|| AppError::NotFound(format!("session not found: {}", relative_path)))?;

    // Lock to finalize
    let mut session = session_mutex.lock().await;

    if session.storage.chunk_count() != session.total_chunks {
        return Err(AppError::BadRequest(format!(
            "incomplete: {}/{} chunks",
            session.storage.chunk_count(),
            session.total_chunks
        )));
    }

    // Finalize storage
    let computed_hash = session.storage.finalize().await?;

    Ok(axum::Json(json!({
        "success": true,
        "sha256": computed_hash,
    })))
}

pub async fn complete_transfer(
    Path(token): Path<String>,
    Query(params): Query<ClientIdParam>,
    State(state): State<ReceiveAppState>,
) -> Result<axum::Json<Value>, AppError> {
    let client_id = &params.client_id;
    auth::require_active_session(&state.session, &token, client_id)?;
    state.session.complete(&token, &params.client_id);

    state.progress.complete();

    Ok(Json(
        json!({"success": true, "message": "Transfer complete"}),
    ))
}
