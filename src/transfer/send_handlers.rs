use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::crypto::types::Nonce;
use crate::errors::AppError;
use crate::server::auth::{self, ClientIdParam};
use crate::server::state::AppState;
use crate::transfer::manifest::Manifest;
use crate::{config, crypto};
use anyhow::{Context, Result};
use axum::extract::Query;
use axum::{
    body::Body,
    extract::{Path, State},
    http::Response,
    Json,
};
use reqwest::header;

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

    let file_entry = state
        .session
        .get_file(file_index)
        .ok_or_else(|| anyhow::anyhow!("Invalid file index"))?;

    // Calc chunk boundries for size of curr chunk
    let start = chunk_index as u64 * config::CHUNK_SIZE;
    let end = std::cmp::min(start + config::CHUNK_SIZE, file_entry.size);

    if start >= file_entry.size {
        return Err(anyhow::anyhow!("Chunk index out of bounds").into());
    }

    let chunk_len = (end - start) as usize;

    // read chunk
    let buffer = read_chunk_blocking(file_entry.full_path.clone(), start, chunk_len)
        .await
        .context("Failed reading chunkdata")?;

    // TUI progress updates
    let (new_total_chunks, session_total_chunks) = state.session.increment_sent_chunk();
    let progress = (new_total_chunks as f64 / session_total_chunks as f64) * 100.0;
    let _ = state.progress_sender.send(progress);

    // encrypt and return
    let file_nonce = Nonce::from_base64(&file_entry.nonce)
        .context(format!("Invalid nonce for file: {}", file_entry.name))?;

    let cipher = state.session.cipher();

    let encrypted =
        crypto::encrypt_chunk_at_position(cipher, &file_nonce, &buffer, chunk_index as u32)
            .context(format!(
                "Failed to encrypt chunk {} of file {}",
                chunk_index, file_entry.name
            ))?;

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(encrypted))?)
}

pub async fn complete_download(
    Path(token): Path<String>,
    Query(params): Query<ChunkParams>,
    State(state): State<AppState>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    // Session must be active and owned to complete
    let client_id = &params.client_id;
    auth::require_active_session(&state.session, &token, client_id)?;

    state.session.complete(&token, client_id);

    // Set progress to 100% to signal completion and close TUI
    let _ = state.progress_sender.send(100.0);

    Ok(axum::Json(serde_json::json!({
        "success": true,
        "message": "Download complete"
    })))
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
        let mut file = std::fs::File::open(&path).context(format!(
            "Failed to open file for sending: {}",
            path.display()
        ))?;

        let mut buffer = vec![0u8; chunk_len];

        // Seek to the starting position and read the chunk
        file.seek(SeekFrom::Start(start))
            .context("Failed to seek file")?;
        file.read_exact(&mut buffer)
            .context("Failed to read chunk")?;

        Ok(buffer)
    })
    .await
    .context("File read task panicked")?
}
