use super::runtime;
use crate::common::config::{AppConfig, Transport};
use crate::common::Manifest;
use crate::crypto::types::{EncryptionKey, Nonce};
use crate::receive::ReceiveAppState;
use crate::send::SendAppState;
use crate::server::progress::ProgressTracker;
use crate::server::routes;
use anyhow::Result;
use axum::Router;
use std::path::PathBuf;
use std::sync::Arc;

// Server configuration
pub struct ServerInstance {
    pub app: axum::Router,
    pub display_name: String,
}

impl ServerInstance {
    pub fn new(app: Router, display_name: String) -> Self {
        Self { app, display_name }
    }
}

//----------------
// SEND SERVER
//---------------
pub async fn start_send_server(
    manifest: Manifest,
    transport: Transport,
    config: &AppConfig,
) -> Result<u16> {
    let session_key = EncryptionKey::new();
    let nonce = Nonce::new();
    let transfer_settings = config.transfer_settings(transport);

    // TUI display
    let display_name = if manifest.files.len() == 1 {
        manifest.files[0].name.clone()
    } else {
        format!("{} files", manifest.files.len())
    };

    // Send specific session
    let total_chunks = manifest.total_chunks(transfer_settings.chunk_size);
    let progress_tracker = Arc::new(ProgressTracker::new());

    // Create typed state for router
    let send_state =
        SendAppState::new(session_key, manifest, total_chunks, progress_tracker.clone(), transfer_settings);
    let app = routes::create_send_router(&send_state);

    let server = ServerInstance::new(app, display_name);

    // Call runtime functions directly with typed state
    match transport {
        Transport::Local => {
            runtime::start_https(
                server,
                send_state,
                nonce,
                transport,
                config,
                progress_tracker,
            )
            .await
        }
        Transport::Cloudflare | Transport::Tailscale => {
            runtime::start_tunnel(
                server,
                send_state,
                nonce,
                transport,
                config,
                progress_tracker,
            )
            .await
        }
    }
}

//----------------
// RECEIVE SERVER
//----------------
pub async fn start_receive_server(
    destination: PathBuf,
    transport: Transport,
    config: &AppConfig,
) -> Result<u16> {
    let session_key = EncryptionKey::new();
    let nonce = Nonce::new();
    let transfer_settings = config.transfer_settings(transport);

    // TUI display name
    let display_name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(".")
        .to_string();

    // Receive specific session
    // Start with 0, will be updated when manifest arrives from client
    let progress_tracker = Arc::new(ProgressTracker::new());

    // Create typed state for router
    let receive_state = ReceiveAppState::new(
        session_key,
        destination,
        progress_tracker.clone(),
        transfer_settings,
    );
    let app = routes::create_receive_router(&receive_state);

    let server = ServerInstance::new(app, display_name);

    // Call runtime functions directly with typed state
    match transport {
        Transport::Local => {
            runtime::start_https(
                server,
                receive_state,
                nonce,
                transport,
                config,
                progress_tracker,
            )
            .await
        }
        Transport::Cloudflare | Transport::Tailscale => {
            runtime::start_tunnel(
                server,
                receive_state,
                nonce,
                transport,
                config,
                progress_tracker,
            )
            .await
        }
    }
}
