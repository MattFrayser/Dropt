use std::sync::Arc;

use crate::config;
use crate::crypto::types::Nonce;
use crate::errors::AppError;
use crate::server::auth::{self, ClientIdParam};
use crate::server::state::{AppState, FileReceiveState};
use crate::transfer::security;
use crate::transfer::storage::ChunkStorage;
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
    #[form_data(limit = "5MB")]
    pub chunk: Bytes,
    #[form_data(field_name = "relativePath")]
    pub relative_path: String,
    #[form_data(field_name = "chunkIndex")]
    pub chunk_index: usize,
    #[form_data(field_name = "totalChunks")]
    pub total_chunks: usize,
    #[form_data(field_name = "fileSize")]
    pub file_size: u64,
    pub nonce: Option<String>,
    #[form_data(field_name = "clientId")]
    pub client_id: String,
}

pub async fn receive_manifest(
    Path(token): Path<String>,
    Query(params): Query<ClientIdParam>,
    State(state): State<AppState>,
    Json(manifest): Json<ClientManifest>,
) -> Result<axum::Json<Value>, AppError> {
    let client_id = &params.client_id;

    // Claim session with manifest
    auth::claim_or_validate_session(&state.session, &token, client_id)?;

    let receive_session = state
        .receive_sessions()
        .ok_or_else(|| anyhow::anyhow!("Invalid Server Mode"))?;

    let destination = state
        .session
        .destination()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

    let mut session_total_chunks = 0;
    // Precreate file sessions to prevent race conditions during parallel upload
    for file in manifest.files {
        let file_chunks = (file.size + config::CHUNK_SIZE - 1) / config::CHUNK_SIZE;
        session_total_chunks += file_chunks;

        let file_id = security::hash_path(&file.relative_path);

        // If session already exists (on retry), skip creation to avoid truncating data
        if receive_session.contains_key(&file_id) {
            continue;
        }

        // Validate & create path
        security::validate_path(&file.relative_path).context("Invalid file path")?;
        let dest_path = destination.join(&file.relative_path);

        // Initialize storage (creates/truncates file) safely here in serial order
        let storage = ChunkStorage::new(dest_path, file.size)
            .await
            .context("Failed to create storage")?;

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
        "total_chunks": session_total_chunks
    })))
}

pub async fn receive_handler(
    Path(token): Path<String>,
    State(state): State<AppState>,
    TypedMultipart(payload): TypedMultipart<ChunkUploadRequest>,
) -> Result<axum::Json<Value>, AppError> {
    tracing::debug!(
        "Receiving chunk {} of {} for file: {} (chunk size: {} bytes)",
        payload.chunk_index,
        payload.total_chunks,
        payload.relative_path,
        payload.chunk.len()
    );
    let receive_sessions = state
        .receive_sessions()
        .ok_or_else(|| anyhow::anyhow!("Invalid server mode: not a receive server"))?;

    let file_id = security::hash_path(&payload.relative_path);
    let client_id = &payload.client_id;

    auth::require_active_session(&state.session, &token, client_id)?;

    // Sessions are made in manifest, so well just get
    let file_session_mutex = receive_sessions
        .get(&file_id)
        .ok_or_else(|| anyhow::anyhow!("Upload session not found. Did you send the manifest?"))?
        .clone();

    // Decrypt outside of mutex lock
    let nonce_string = payload.nonce.clone().ok_or_else(|| {
        anyhow::anyhow!("Missing nonce. Client must provide nonce with every chunk.")
    })?;
    if nonce_string.is_empty() {
        return Err(anyhow::anyhow!("Nonce missing.").into());
    }
    let nonce = Nonce::from_base64(&nonce_string)?;

    // Clone what is needed for the thread
    let cipher = state.session.cipher().clone();
    let chunk_data = payload.chunk.clone();
    let chunk_index = payload.chunk_index;
    let nonce_val = nonce.clone();

    // Offload CPU work
    let decrypted_data = tokio::task::spawn_blocking(move || {
        crate::crypto::decrypt_chunk_at_position(
            &cipher,
            &nonce_val,
            &chunk_data,
            chunk_index as u32,
        )
    })
    .await??;

    // File should be locked when writing
    let mut session = file_session_mutex.lock().await;

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

    session
        .storage
        .store_chunk(payload.chunk_index, &decrypted_data)
        .await?;

    // Track progress
    let (chunks_processed, total_chunks) = state.session.increment_received_chunk();
    if total_chunks > 0 {
        let progress = (chunks_processed as f64 / total_chunks as f64) * 100.0;
        let _ = state.progress_sender.send(progress);
    }

    Ok(Json(json!({
        "success": true,
    })))
}
pub async fn finalize_upload(
    Path(token): Path<String>,
    Query(params): Query<ClientIdParam>,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<axum::Json<Value>, AppError> {
    let receive_sessions = state
        .receive_sessions()
        .ok_or_else(|| anyhow::anyhow!("Invalid server mode: not a receive server"))?;

    // Validate session
    let client_id = &params.client_id;
    auth::require_active_session(&state.session, &token, client_id)?;

    let mut relative_path = None;
    while let Some(field) = multipart.next_field().await? {
        if field.name() == Some("relativePath") {
            relative_path = Some(field.text().await?);
            break;
        }
    }
    let relative_path = relative_path.ok_or_else(|| anyhow::anyhow!("Missing relativePath"))?;

    // Generate file ID and remove from sessions map
    let file_id = security::hash_path(&relative_path);

    let (_key, session_mutex) = receive_sessions
        .remove(&file_id)
        .ok_or_else(|| anyhow::anyhow!("No upload session found for file: {}", relative_path))?;

    // Lock to finalize
    let mut session = session_mutex.lock().await;

    if session.storage.chunk_count() != session.total_chunks {
        return Err(anyhow::anyhow!(
            "Incomplete upload: received {}/{} chunks",
            session.storage.chunk_count(),
            session.total_chunks
        )
        .into());
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
    State(state): State<AppState>,
) -> Result<axum::Json<Value>, AppError> {
    let client_id = &params.client_id;
    auth::require_active_session(&state.session, &token, client_id)?;
    state.session.complete(&token, &params.client_id);

    let _ = state.progress_sender.send(100.0);

    Ok(Json(
        json!({"success": true, "message": "Transfer complete"}),
    ))
}
