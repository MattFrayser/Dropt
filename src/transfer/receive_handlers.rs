use std::sync::Arc;

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

    // Calculate total chunks from manifest
    let total_chunks: u64 = manifest
        .files
        .iter()
        .map(|f| (f.size + crate::config::CHUNK_SIZE - 1) / crate::config::CHUNK_SIZE)
        .sum();

    // Update session with total chunks
    state.session.set_total_chunks(total_chunks);

    Ok(Json(json!({
        "success": true,
        "total_chunks": total_chunks
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

    // Sessions are claimed on first file and verified on rest
    let is_new_file = !receive_sessions.contains_key(&file_id);

    if is_new_file && payload.chunk_index == 0 {
        auth::claim_or_validate_session(&state.session, &token, client_id)?;
    } else {
        auth::require_active_session(&state.session, &token, client_id)?;
    }

    // Clone the Arc<Mutex>, dropping the DashMap lock immediately
    // Frees dashmap up for another process.
    let file_session_mutex = if let Some(entry) = receive_sessions.get(&file_id) {
        entry.clone()
    } else {
        // Create new session logic
        let destination = state
            .session
            .destination()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

        security::validate_path(&payload.relative_path).context("Invalid file path")?;
        let dest_path = destination.join(&payload.relative_path);

        let storage = ChunkStorage::new(dest_path)
            .await
            .context("Failed to create storage")?;

        let new_state = FileReceiveState {
            storage,
            total_chunks: payload.total_chunks,
            nonce: payload.nonce.clone().unwrap_or_default(),
            relative_path: payload.relative_path.clone(),
            file_size: payload.file_size,
        };

        // Wrap in Arc<Mutex>
        let new_entry = Arc::new(Mutex::new(new_state));
        receive_sessions.insert(file_id.clone(), new_entry.clone());
        new_entry
    };

    // Decrypt outside of mutex lock,

    // If chunk is 0, payload will have nonce
    // (chunk 0 will always contain nonce form network)
    let nonce_string = if let Some(n) = &payload.nonce {
        n.clone()
    } else {
        // Not chunk 0, grab mutex for nonce and drop immediately
        let guard = file_session_mutex.lock().await;
        let n = guard.nonce.clone();
        drop(guard);
        n
    };

    if nonce_string.is_empty() {
        return Err(anyhow::anyhow!(
            "Nonce missing. Chunk 0 must be uploaded first or nonce provided."
        )
        .into());
    }

    let nonce = Nonce::from_base64(&nonce_string)?;
    let cipher = state.session.cipher();

    let decrypted_data = crate::crypto::decrypt_chunk_at_position(
        cipher,
        &nonce,
        &payload.chunk,
        payload.chunk_index as u32,
    )?;

    // File should be locked when writing
    let mut session = file_session_mutex.lock().await;

    // Update nonce in state if this was chunk 0
    if session.nonce.is_empty() && payload.chunk_index == 0 {
        session.nonce = nonce_string;
    }

    // Check duplicates
    if session.storage.has_chunk(payload.chunk_index) {
        return Ok(axum::Json(json!({
            "success": true,
            "duplicate": true,
            "chunk": payload.chunk_index,
            "received": session.storage.chunk_count(),
            "total": session.total_chunks,
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
        "chunk": payload.chunk_index,
        "total": session.total_chunks,
        "received": session.storage.chunk_count()
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
