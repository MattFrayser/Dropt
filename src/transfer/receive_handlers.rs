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
    let receive_sessions = state
        .receive_sessions()
        .ok_or_else(|| anyhow::anyhow!("Invalid server mode: not a receive server"))?;

    // Get or create session
    let file_id = security::hash_path(&payload.relative_path);

    // Sessions are claimed on first file and verified on rest
    let client_id = &payload.client_id;
    let is_new_file = !receive_sessions.contains_key(&file_id);

    if is_new_file && payload.chunk_index == 0 {
        auth::claim_or_validate_session(&state.session, &token, client_id)?;
    } else {
        auth::require_active_session(&state.session, &token, client_id)?;
    }

    // Lock receive session
    let session_exits = receive_sessions.contains_key(&file_id);

    if !session_exits {
        let destination = state
            .session
            .destination()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

        // Validate provided path and join to base
        security::validate_path(&payload.relative_path).context("Invalid file path")?;
        let dest_path = destination.join(&payload.relative_path);

        let storage = ChunkStorage::new(dest_path)
            .await
            .context("Failed to create storage")?;

        receive_sessions.insert(
            file_id.clone(),
            FileReceiveState {
                storage,
                total_chunks: payload.total_chunks,
                nonce: payload.nonce.clone().unwrap_or_default(),
                relative_path: payload.relative_path.clone(),
                file_size: payload.file_size,
            },
        );
    }

    let mut session = receive_sessions
        .get_mut(&file_id)
        .ok_or_else(|| anyhow::anyhow!("Invalid session"))?;

    // Update nonce if provided (chunk 0 contains the nonce)
    if let Some(ref nonce_str) = payload.nonce {
        if session.nonce.is_empty() {
            eprintln!("[receive] Setting nonce from chunk {}", payload.chunk_index);
            session.nonce = nonce_str.clone();
        }
    }

    // Check for duplicates
    if session.storage.has_chunk(payload.chunk_index) {
        return Ok(axum::Json(json!({
            "success": true,
            "duplicate": true,
            "chunk": payload.chunk_index,
            "received": session.storage.chunk_count(),
            "total": session.total_chunks,
        })));
    }

    // store chunk
    let nonce = Nonce::from_base64(&session.nonce)?;

    let cipher = state.session.cipher();

    session
        .storage
        .store_chunk(payload.chunk_index, payload.chunk, cipher, &nonce)
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

    // Parse relativePath
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

    let (_key, session) = receive_sessions
        .remove(&file_id)
        .ok_or_else(|| anyhow::anyhow!("No upload session found for file: {}", relative_path))?;

    // Verify all chunks received
    if session.storage.chunk_count() != session.total_chunks {
        return Err(anyhow::anyhow!(
            "Incomplete upload: received {}/{} chunks for {}",
            session.storage.chunk_count(),
            session.total_chunks,
            relative_path
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
