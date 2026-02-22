//! High-level server builders for send and receive modes.

use super::runtime;
use crate::common::Manifest;
use crate::common::config::{AppConfig, CollisionPolicy, Transport};
use crate::crypto::types::{EncryptionKey, Nonce};
use crate::receive::ReceiveAppState;
use crate::send::SendAppState;
use crate::server::progress::ProgressTracker;
use crate::server::routes;
use anyhow::Result;
use axum::Router;
use std::path::PathBuf;
use std::sync::Arc;

/// Router and display metadata for a running transfer server.
pub struct ServerInstance {
    pub app: axum::Router,
    pub display_name: String,
    pub display_files: Vec<String>,
    pub display_overflow_count: Option<usize>,
}

impl ServerInstance {
    pub fn new(
        app: Router,
        display_name: String,
        display_files: Vec<String>,
        display_overflow_count: Option<usize>,
    ) -> Self {
        Self {
            app,
            display_name,
            display_files,
            display_overflow_count,
        }
    }
}

fn build_send_display_label(manifest: &Manifest) -> (String, Option<usize>) {
    let visible_limit = 5;
    let visible_names: Vec<&str> = manifest
        .files
        .iter()
        .take(visible_limit)
        .map(|file| file.name.as_str())
        .collect();
    let label = visible_names.join(", ");
    let overflow = manifest.files.len().checked_sub(visible_limit);
    match overflow {
        Some(0) | None => (label, None),
        Some(count) => (label, Some(count)),
    }
}

/// Build and run a send server for the selected transport.
pub async fn start_send_server(
    manifest: Manifest,
    transport: Transport,
    config: &AppConfig,
) -> Result<u16> {
    let session_key = EncryptionKey::new();
    let nonce = Nonce::new();
    let transfer_settings = config.transfer_settings(transport);

    // TUI display
    let (display_name, display_overflow_count) = build_send_display_label(&manifest);
    let display_files = manifest
        .files
        .iter()
        .take(5)
        .map(|f| f.name.clone())
        .collect::<Vec<_>>();

    // Send specific session
    let total_chunks = manifest.total_chunks(transfer_settings.chunk_size);
    let progress_tracker = Arc::new(ProgressTracker::new());

    // Create typed state for router
    let send_state = SendAppState::new(
        session_key,
        manifest,
        total_chunks,
        progress_tracker.clone(),
        transfer_settings,
    );
    let app = routes::create_send_router(&send_state);

    let server = ServerInstance::new(app, display_name, display_files, display_overflow_count);

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

/// Build and run a receive server for the selected transport.
pub async fn start_receive_server(
    destination: PathBuf,
    transport: Transport,
    collision_policy: CollisionPolicy,
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
        collision_policy,
    );
    let app = routes::create_receive_router(&receive_state);

    let server = ServerInstance::new(app, display_name, Vec::new(), None);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::TransferSettings;

    fn manifest_with_names(names: &[&str]) -> Manifest {
        Manifest {
            files: names
                .iter()
                .enumerate()
                .map(|(index, name)| crate::common::FileEntry {
                    index,
                    name: (*name).to_string(),
                    full_path: PathBuf::from(name),
                    relative_path: (*name).to_string(),
                    size: 1,
                    nonce: "nonce".to_string(),
                })
                .collect(),
            config: TransferSettings {
                chunk_size: 1024,
                concurrency: 1,
            },
        }
    }

    #[test]
    fn display_label_uses_single_filename_without_overflow() {
        let manifest = manifest_with_names(&["one.txt"]);
        let (label, overflow) = build_send_display_label(&manifest);
        assert_eq!(label, "one.txt");
        assert_eq!(overflow, None);
    }

    #[test]
    fn display_label_joins_up_to_five_filenames() {
        let manifest = manifest_with_names(&["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"]);
        let (label, overflow) = build_send_display_label(&manifest);
        assert_eq!(label, "a.txt, b.txt, c.txt, d.txt, e.txt");
        assert_eq!(overflow, None);
    }

    #[test]
    fn display_label_adds_overflow_after_five_filenames() {
        let manifest = manifest_with_names(&[
            "a.txt", "b.txt", "c.txt", "d.txt", "e.txt", "f.txt", "g.txt",
        ]);
        let (label, overflow) = build_send_display_label(&manifest);
        assert_eq!(label, "a.txt, b.txt, c.txt, d.txt, e.txt");
        assert_eq!(overflow, Some(2));
    }
}
