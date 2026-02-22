//! HTTP handlers for manifest intake, chunk upload, and completion.

use std::collections::HashSet;
use std::sync::Arc;

use crate::common::manifest::validate_nonce_counter_chunks;
use crate::common::{AppError, CollisionOutcome};
use crate::crypto::types::Nonce;
use crate::receive::state::{FileReceiveState, ReceiveAppState};
use crate::receive::storage::{
    self, ChunkStorage, CollisionResolution, find_available_path, resolve_collision,
};
use crate::server::auth::{self, BearerToken, LockToken};
use crate::utils::security;
use anyhow::{Context, Result};
use axum::Json;
use axum::extract::{Multipart, State};
use axum_typed_multipart::{TryFromMultipart, TypedMultipart};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio_util::bytes::Bytes;

/// Client-declared file entry for receive manifest setup.
#[derive(serde::Deserialize)]
pub struct ClientManifestEntry {
    pub relative_path: String,
    pub size: u64,
}

/// Client manifest used to pre-create receive sessions.
#[derive(serde::Deserialize)]
pub struct ClientManifest {
    pub files: Vec<ClientManifestEntry>,
}

/// Multipart payload for one encrypted chunk upload.
#[derive(TryFromMultipart)]
pub struct ChunkUploadRequest {
    #[form_data(limit = "12MB")]
    pub chunk: Bytes,
    #[form_data(field_name = "relativePath")]
    pub relative_path: String,
    #[form_data(field_name = "chunkIndex")]
    pub chunk_index: usize,
    pub nonce: Option<String>,
}

/// Claim session, validate manifest, and initialize receive state.
pub async fn receive_manifest(
    BearerToken(token): BearerToken,
    State(state): State<ReceiveAppState>,
    Json(manifest): Json<ClientManifest>,
) -> Result<axum::Json<Value>, AppError> {
    tracing::debug!(file_count = manifest.files.len(), "receive_manifest");

    // Claim session with manifest
    let lock_token = auth::claim_session(&state.session, &token)?;

    let receive_session = &state.receive_sessions;

    let destination = state.destination();

    let chunk_size = state.config.chunk_size;

    // Validate manifest before allocating disk space
    let mut total_size: u64 = 0;
    let mut seen_relative_paths: HashSet<&str> = HashSet::new();
    for file in &manifest.files {
        if !seen_relative_paths.insert(&file.relative_path) {
            return Err(AppError::BadRequest(format!(
                "duplicate relative_path in manifest: {}",
                file.relative_path
            )));
        }

        validate_nonce_counter_chunks(file.size, chunk_size, &file.relative_path)
            .map_err(|e| AppError::BadRequest(e.to_string()))?;

        total_size = total_size
            .checked_add(file.size)
            .ok_or_else(|| AppError::BadRequest("manifest size overflow".to_string()))?;
    }
    let mut session_total_chunks = 0u64;
    let mut skipped_files: Vec<String> = Vec::new();

    // Pass 1: resolve collision for every file
    let mut resolved: Vec<(ClientManifestEntry, String, CollisionResolution)> = Vec::new();
    for file in manifest.files.into_iter() {
        let filename = std::path::Path::new(&file.relative_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&file.relative_path)
            .to_string();

        let dest_path = security::confine_receive_path(destination, &file.relative_path)
            .map_err(|e| AppError::BadRequest(format!("bad path: {e}")))?;

        let resolution = resolve_collision(state.collision_policy, dest_path)
            .await
            .context("collision resolution")?;

        resolved.push((file, filename, resolution));
    }

    // Disk space: only count files that will actually be written (exclude Skip)
    let transfer_size: u64 = resolved
        .iter()
        .filter(|(_, _, r)| !matches!(r, CollisionResolution::Skip))
        .map(|(file, _, _)| file.size)
        .sum();
    storage::check_disk_space(destination, transfer_size)
        .map_err(|e| AppError::InsufficientStorage(e.to_string()))?;

    // Init progress tracker with ALL files so skipped ones appear in the TUI
    let progress_names: Vec<String> = resolved.iter().map(|(_, name, _)| name.clone()).collect();
    let progress_totals: Vec<u64> = resolved
        .iter()
        .map(|(file, _, _)| file.size.div_ceil(chunk_size))
        .collect();
    state.progress.init_files(progress_names, progress_totals);

    // Pass 2: create sessions for kept files, record collision outcomes
    for (progress_index, (file, _, resolution)) in resolved.into_iter().enumerate() {
        let file_chunks = file.size.div_ceil(chunk_size);
        let file_id = security::hash_path(&file.relative_path);

        let Some(final_path) = (match resolution {
            CollisionResolution::Skip => {
                skipped_files.push(file.relative_path.clone());
                state
                    .progress
                    .file_collision_outcome(progress_index, CollisionOutcome::Skipped);
                None
            }
            CollisionResolution::Overwrote(path) => {
                state
                    .progress
                    .file_collision_outcome(progress_index, CollisionOutcome::Overwrote);
                Some(path)
            }
            CollisionResolution::Use(path) => {
                // find_available_path handles Suffix rename if file exists.
                // For Skip/Overwrite, Use means no collision — returns path unchanged.
                let final_path = find_available_path(path.clone()).await;
                if final_path != path {
                    let new_name = final_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    state.progress.file_collision_outcome(
                        progress_index,
                        CollisionOutcome::Renamed(new_name),
                    );
                }
                Some(final_path)
            }
        }) else {
            continue;
        };

        session_total_chunks += file_chunks;
        let storage = ChunkStorage::new(final_path, file.size, chunk_size)
            .await
            .context("create storage")?;
        let new_state = FileReceiveState {
            storage,
            total_chunks: file_chunks as usize,
            nonce: None,
            file_index: progress_index,
        };
        receive_session.insert(file_id, Arc::new(Mutex::new(new_state)));
    }

    // Update session with total non-skipped chunks
    state.set_total_chunks(session_total_chunks);

    if !skipped_files.is_empty() {
        tracing::info!(
            count = skipped_files.len(),
            files = ?skipped_files,
            "files skipped due to collision policy"
        );
    }

    Ok(Json(json!({
        "success": true,
        "total_chunks": session_total_chunks,
        "skipped_files": skipped_files,
        "config": state.config,
        "lockToken": lock_token
    })))
}

/// Accept, decrypt, and persist one uploaded chunk.
pub async fn receive_handler(
    BearerToken(token): BearerToken,
    LockToken(lock_token): LockToken,
    State(state): State<ReceiveAppState>,
    TypedMultipart(payload): TypedMultipart<ChunkUploadRequest>,
) -> Result<axum::Json<Value>, AppError> {
    let receive_sessions = &state.receive_sessions;

    let ChunkUploadRequest {
        chunk,
        relative_path,
        chunk_index,
        nonce,
    } = payload;

    let file_id = security::hash_path(&relative_path);
    auth::require_active_session(&state.session, &token, &lock_token)?;

    // Sessions are made in manifest, so well just get
    let file_session_mutex = receive_sessions
        .get(&file_id)
        .ok_or_else(|| AppError::BadRequest("session not found".to_string()))?
        .clone();

    // Decrypt outside of mutex lock
    let nonce_string = nonce.ok_or_else(|| AppError::BadRequest("missing nonce".to_string()))?;
    if nonce_string.is_empty() {
        return Err(AppError::BadRequest("nonce empty".to_string()));
    }
    let nonce = Nonce::from_base64(&nonce_string)?;
    let nonce_for_lock = nonce.clone();

    let cipher = state.session.cipher().clone();
    let mut chunk_data = chunk.to_vec();
    let nonce_val = nonce;

    let decrypt_bytes = chunk_data.len();
    let decrypt_start = std::time::Instant::now();
    let decrypted_data = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        crate::crypto::decrypt_chunk_in_place(
            &cipher,
            &nonce_val,
            &mut chunk_data,
            chunk_index as u32,
        )?;
        Ok(chunk_data)
    })
    .await
    .context("decrypt task panicked")?
    .context("decrypt failed")?;
    tracing::debug!(
        chunk_index,
        bytes = decrypt_bytes,
        elapsed_us = decrypt_start.elapsed().as_micros() as u64,
        "chunk_decrypt"
    );

    // File should be locked when writing
    let lock_start = std::time::Instant::now();
    let mut session = file_session_mutex.lock().await;
    tracing::debug!(
        chunk_index,
        elapsed_us = lock_start.elapsed().as_micros() as u64,
        "lock_wait"
    );

    // Validate nonce consistency — all chunks for a file must share the same base nonce
    match &session.nonce {
        None => session.nonce = Some(nonce_for_lock),
        Some(stored) => {
            if stored != &nonce_for_lock {
                return Err(AppError::BadRequest(
                    "nonce mismatch: chunk from different stream".to_string(),
                ));
            }
        }
    }

    // Check duplicates
    if session.storage.has_chunk(chunk_index) {
        return Ok(axum::Json(json!({
            "success": true,
            "duplicate": true,
        })));
    }

    let write_start = std::time::Instant::now();
    session
        .storage
        .store_chunk(chunk_index, &decrypted_data)
        .await?;
    tracing::debug!(
        chunk_index,
        bytes = decrypted_data.len(),
        elapsed_us = write_start.elapsed().as_micros() as u64,
        "chunk_write"
    );

    // Track progress
    let (_chunks_processed, _total_chunks) = state.increment_received_chunk();
    state.progress.increment_file(session.file_index);

    Ok(Json(json!({
        "success": true,
    })))
}

/// Finalize one file upload and return its SHA-256 hash.
pub async fn finalize_upload(
    BearerToken(token): BearerToken,
    LockToken(lock_token): LockToken,
    State(state): State<ReceiveAppState>,
    mut multipart: Multipart,
) -> Result<axum::Json<Value>, AppError> {
    tracing::debug!("finalize_upload");
    let receive_sessions = &state.receive_sessions;

    // Validate session
    auth::require_active_session(&state.session, &token, &lock_token)?;

    let mut relative_path = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .context("read multipart field")?
    {
        if field.name() == Some("relativePath") {
            relative_path = Some(field.text().await.context("read relativePath")?);
            break;
        }
    }
    let relative_path =
        relative_path.ok_or_else(|| AppError::BadRequest("missing relative_path".to_string()))?;

    // Generate file ID and read session from map
    let file_id = security::hash_path(&relative_path);

    let session_mutex = receive_sessions
        .get(&file_id)
        .map(|entry| entry.value().clone())
        .ok_or_else(|| AppError::NotFound(format!("session not found: {relative_path}")))?;

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

    // Remove only after successful finalize so retries remain possible on incomplete files.
    receive_sessions.remove(&file_id);

    // Mark file as complete for TUI
    state.progress.file_complete(session.file_index);

    Ok(axum::Json(json!({
        "success": true,
        "sha256": computed_hash,
    })))
}

/// Mark the transfer complete for this receive session.
pub async fn complete_transfer(
    BearerToken(token): BearerToken,
    LockToken(lock_token): LockToken,
    State(state): State<ReceiveAppState>,
) -> Result<axum::Json<Value>, AppError> {
    auth::require_active_session(&state.session, &token, &lock_token)?;

    let pending_files = state.receive_sessions.len();
    if pending_files > 0 {
        return Err(AppError::BadRequest(format!(
            "transfer incomplete: {pending_files} file(s) not finalized"
        )));
    }

    state.session.complete(&token, &lock_token);

    Ok(Json(
        json!({"success": true, "message": "Transfer complete"}),
    ))
}
