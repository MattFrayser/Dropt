use super::{runtime, session};
use crate::crypto::types::{EncryptionKey, Nonce};
use crate::{
    server::{routes, AppState, Session},
    transfer::manifest::Manifest,
};
use anyhow::Result;
use axum::Router;
use std::fmt;
use std::path::PathBuf;
use tokio::sync::watch;

// Based off cli flags
pub enum ServerMode {
    Local,
    Tunnel,
}

pub enum ServerDirection {
    Send,
    Receive,
}

// used for formatting url ".../send/..."
impl fmt::Display for ServerDirection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServerDirection::Send => write!(f, "send"),
            ServerDirection::Receive => write!(f, "receive"),
        }
    }
}

// Server configuration
pub struct ServerInstance {
    pub app: axum::Router,
    pub session: session::Session,
    pub display_name: String, // shown in tui
    pub progress_sender: watch::Sender<f64>,
}

impl ServerInstance {
    pub fn new(
        app: Router,
        session: Session,
        display_name: String,
        progress_sender: watch::Sender<f64>,
    ) -> Self {
        Self {
            app,
            session,
            display_name,
            progress_sender,
        }
    }

    // Tui status bar
    pub fn progress_receiver(&self) -> watch::Receiver<f64> {
        self.progress_sender.subscribe()
    }
}

// Generic server helper function
async fn start_server(
    server: ServerInstance,
    app_state: AppState,
    mode: ServerMode,
    direction: ServerDirection,
    nonce: Nonce,
) -> Result<u16> {
    match mode {
        ServerMode::Local => runtime::start_https(server, app_state, direction, nonce).await,
        ServerMode::Tunnel => runtime::start_tunnel(server, app_state, direction, nonce).await,
    }
}

//----------------
// SEND SERVER
//---------------
pub async fn start_send_server(manifest: Manifest, mode: ServerMode) -> Result<u16> {
    let session_key = EncryptionKey::new();
    let nonce = Nonce::new();

    // TUI display
    let display_name = if manifest.files.len() == 1 {
        manifest.files[0].name.clone()
    } else {
        format!("{} files", manifest.files.len())
    };

    // Send specific session
    let total_chunks = manifest.total_chunks();
    let session = session::Session::new_send(manifest.clone(), session_key, total_chunks);
    let (progress_sender, _) = tokio::sync::watch::channel(0.0);

    // App and router
    let state = AppState::new_send(session.clone(), progress_sender.clone());
    let app = routes::create_send_router(&state);
    let server = ServerInstance::new(app, session, display_name, progress_sender);

    start_server(server, state, mode, ServerDirection::Send, nonce).await
}

//----------------
// RECEIVE SERVER
//----------------
pub async fn start_receive_server(destination: PathBuf, mode: ServerMode) -> Result<u16> {
    let session_key = EncryptionKey::new();
    let nonce = Nonce::new();

    // TUI display name
    let display_name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(".")
        .to_string();

    // Receive specific session
    // Start with 0, will be updated when manifest arrives from client
    let session = session::Session::new_receive(destination.clone(), session_key, 0);
    let (progress_sender, _) = tokio::sync::watch::channel(0.0);

    let state = AppState::new_receive(session.clone(), progress_sender.clone());
    let app = routes::create_receive_router(&state);
    let server = ServerInstance::new(app, session, display_name, progress_sender);

    start_server(server, state, mode, ServerDirection::Receive, nonce).await
}

//----------------
// TEST HELPERS
//----------------
// Note: These functions are intended for testing only. They allow tests to:
// 1. Provide their own encryption keys (for deterministic testing)
// 2. Access the session token and key (needed by test clients)

// Test helper: starts send server with provided key and returns session
pub async fn start_send_server_for_test(
    manifest: Manifest,
    session_key: EncryptionKey,
    mode: ServerMode,
) -> Result<(u16, Session)> {
    let nonce = Nonce::new();

    // Create session with provided key
    let total_chunks = manifest.total_chunks();
    let session = session::Session::new_send(manifest.clone(), session_key, total_chunks);

    let display_name = if manifest.files.len() == 1 {
        manifest.files[0].name.clone()
    } else {
        format!("{} files", manifest.files.len())
    };

    let (progress_sender, _) = tokio::sync::watch::channel(0.0);
    let state = AppState::new_send(session.clone(), progress_sender.clone());
    let app = routes::create_send_router(&state);
    let server = ServerInstance::new(app, session.clone(), display_name, progress_sender);

    let port = start_server(server, state, mode, ServerDirection::Send, nonce).await?;
    Ok((port, session))
}

/// Test helper: starts receive server with provided key and returns session
pub async fn start_receive_server_for_test(
    destination: PathBuf,
    session_key: EncryptionKey,
    mode: ServerMode,
) -> Result<(u16, Session)> {
    let nonce = Nonce::new();

    // Create session with provided key
    // Start with 0, will be updated when manifest arrives
    let session = session::Session::new_receive(destination.clone(), session_key, 0);

    let display_name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(".")
        .to_string();

    let (progress_sender, _) = tokio::sync::watch::channel(0.0);
    let state = AppState::new_receive(session.clone(), progress_sender.clone());
    let app = routes::create_receive_router(&state);
    let server = ServerInstance::new(app, session.clone(), display_name, progress_sender);

    let port = start_server(server, state, mode, ServerDirection::Receive, nonce).await?;
    Ok((port, session))
}
