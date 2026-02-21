//! HTTP handlers for manifest, chunk, and completion endpoints.

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::Response,
    Json,
};
use bytes::Bytes;
use reqwest::header;
use std::collections::HashSet;
use std::sync::Arc;

use crate::common::{AppError, CollisionOutcome};
use crate::crypto::{self, Nonce};
use crate::send::buffer_pool::BufferPool;
use crate::send::file_handle::SendFileHandle;
use crate::server::auth::{self, BearerToken, LockToken};

use super::SendAppState;

/// Manifest payload plus lock token for authenticated chunk requests.
#[derive(serde::Serialize)]
pub struct SendManifestResponse {
    #[serde(flatten)]
    manifest: crate::common::Manifest,
    #[serde(rename = "lockToken")]
    lock_token: String,
}

#[derive(serde::Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct SendCompleteRequest {
    skipped_files: Vec<SkippedFileReport>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedFileReport {
    file_index: usize,
    reason: String,
}

struct CompletionAccounting {
    accounted_chunks: u64,
    is_premature: bool,
}

/// Claim the session and return the transfer manifest.
pub async fn manifest_handler(
    BearerToken(token): BearerToken,
    State(state): State<SendAppState>,
) -> Result<Json<SendManifestResponse>, AppError> {
    // Session claimed when fetching manifest
    // Manifests holds info about files (sizes, names) only client should see
    let lock_token = auth::claim_session(&state.session, &token)?;

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

    Ok(Json(SendManifestResponse {
        manifest: manifest.clone(),
        lock_token,
    }))
}

/// Serve one encrypted chunk for a file index/chunk index pair.
pub async fn send_handler(
    BearerToken(token): BearerToken,
    LockToken(lock_token): LockToken,
    Path((file_index, chunk_index)): Path<(usize, usize)>,
    State(state): State<SendAppState>,
) -> Result<Response<Body>, AppError> {
    auth::require_active_session(&state.session, &token, &lock_token)?;

    let file_entry = state
        .get_file(file_index)
        .ok_or_else(|| AppError::BadRequest(format!("file_index out of bounds: {}", file_index)))?;
    let chunk_size = state.config.chunk_size;

    // Get or create file handle (lazy initialization)
    let file_handle = state
        .file_handles
        .entry(file_index)
        .or_try_insert_with(|| -> Result<Arc<SendFileHandle>> {
            Ok(Arc::new(SendFileHandle::open(
                &file_entry.full_path,
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

    // Mark chunk sent only after successful processing.
    // Some browsers send multiple retries (safari); don't count duplicates.
    if state.mark_chunk_sent(file_index, chunk_index) {
        state.progress.increment_file(file_index);
    }

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(encrypted_bytes))
        .context("build response")?)
}

/// Read, encrypt, and return a single chunk payload.
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

        let read_start = std::time::Instant::now();
        file_handle.read_chunk(start, chunk_len, &mut buffer)?;
        tracing::debug!(
            chunk_index,
            bytes = chunk_len,
            elapsed_us = read_start.elapsed().as_micros() as u64,
            "chunk_read"
        );

        let file_nonce = Nonce::from_base64(&nonce_str)?;

        let encrypt_start = std::time::Instant::now();
        crypto::encrypt_chunk_in_place(&cipher, &file_nonce, &mut buffer, chunk_index as u32)
            .context("Encryption failed")?;
        tracing::debug!(
            chunk_index,
            bytes = buffer.len(),
            elapsed_us = encrypt_start.elapsed().as_micros() as u64,
            "chunk_encrypt"
        );

        // Wrap in Bytes that returns the buffer to the pool on drop
        Ok(pool.wrap(buffer))
    })
    .await?
}

/// Mark the transfer complete (idempotent for client retries).
pub async fn complete_download(
    BearerToken(token): BearerToken,
    LockToken(lock_token): LockToken,
    State(state): State<SendAppState>,
    payload: Option<Json<SendCompleteRequest>>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
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
    auth::require_active_session(&state.session, &token, &lock_token)?;

    let payload = payload.map_or_else(SendCompleteRequest::default, |Json(value)| value);
    let (skipped_files, skipped_chunks) = apply_skipped_reports(&state, payload.skipped_files);

    let chunks_sent = state.get_chunks_sent();
    let total_chunks = state.get_total_chunks();
    let accounting = build_completion_accounting(chunks_sent, total_chunks, skipped_chunks);

    // Verify all chunks were actually sent
    if accounting.is_premature {
        tracing::warn!(
            "Complete called with unaccounted chunks: served={} skipped={} accounted={}/{}",
            chunks_sent,
            skipped_chunks,
            accounting.accounted_chunks,
            total_chunks,
        );
        return Err(AppError::BadRequest(format!(
            "Transfer incomplete: {}/{} chunks accounted for",
            accounting.accounted_chunks, total_chunks
        )));
    }

    tracing::info!(
        "Send complete: served={} skipped_files={} skipped_chunks={} total={}",
        chunks_sent,
        skipped_files,
        skipped_chunks,
        total_chunks
    );

    state.session.complete(&token, &lock_token);
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

fn normalize_skip_reason(reason: &str) -> Option<&'static str> {
    match reason {
        "browser_limit" => Some("browser_limit"),
        "user_skipped" => Some("user_skipped"),
        _ => None,
    }
}

fn build_completion_accounting(
    chunks_sent: u64,
    total_chunks: u64,
    skipped_chunks: u64,
) -> CompletionAccounting {
    let accounted_chunks = chunks_sent.saturating_add(skipped_chunks).min(total_chunks);
    CompletionAccounting {
        accounted_chunks,
        is_premature: accounted_chunks < total_chunks,
    }
}

fn apply_skipped_reports(state: &SendAppState, reports: Vec<SkippedFileReport>) -> (usize, u64) {
    let mut seen = HashSet::new();
    let mut skipped_files = 0usize;
    let mut skipped_chunks = 0u64;

    for report in reports {
        if !seen.insert(report.file_index) {
            continue;
        }

        let Some(reason) = normalize_skip_reason(report.reason.as_str()) else {
            tracing::warn!(
                file_index = report.file_index,
                reason = report.reason,
                "Ignoring skipped file report with unsupported reason"
            );
            continue;
        };

        let Some(file) = state.get_file(report.file_index) else {
            tracing::warn!(
                file_index = report.file_index,
                "Ignoring skipped file report with out-of-range file index"
            );
            continue;
        };

        let file_chunks = file.size.div_ceil(state.config.chunk_size);
        skipped_chunks = skipped_chunks.saturating_add(file_chunks);
        skipped_files += 1;
        state.progress.file_collision_outcome(report.file_index, CollisionOutcome::Skipped);
    }

    (skipped_files, skipped_chunks)
}

#[cfg(test)]
mod tests {
    use super::{build_completion_accounting, normalize_skip_reason};

    #[test]
    fn normalize_skip_reason_accepts_known_codes_only() {
        assert_eq!(normalize_skip_reason("browser_limit"), Some("browser_limit"));
        assert_eq!(normalize_skip_reason("user_skipped"), Some("user_skipped"));
        assert_eq!(normalize_skip_reason("disk_full"), None);
    }

    #[test]
    fn completion_accounting_adds_skipped_chunks_to_served_chunks() {
        let accounting = build_completion_accounting(7, 10, 3);
        assert_eq!(accounting.accounted_chunks, 10);
        assert!(!accounting.is_premature);
    }
}
