pub mod handlers;
pub mod modes;
pub mod utils;
use crate::crypto::Encryptor;
use crate::server::handlers::AppState;
use crate::session::SessionStore;
use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;

pub enum ServerMode {
    Local,
    Http,
    Tunnel,
}
#[derive(Debug)]
pub enum ServerDirection {
    Send,
    Receive,
}

pub async fn start_server(
    file_path: PathBuf,
    mode: ServerMode,
    direction: ServerDirection,
) -> Result<u16> {
    let sessions = SessionStore::new();
    let encryptor = Encryptor::new();

    // encrypion values
    let key = encryptor.get_key_base64();
    let nonce = encryptor.get_nonce_base64();
    let token = sessions.create_session(file_path.clone()).await;

    // Progress channel
    let (progress_sender, progress_consumer) = watch::channel(0.0); // make progress channel
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    let state = AppState {
        sessions,
        encryptor: Arc::new(encryptor),
        progress_sender,
    };

    let app = match direction {
        // Create axium router
        ServerDirection::Send => Router::new()
            .route("/health", get(|| async { "OK" }))
            .route("/download/:token", get(handlers::serve_download_page))
            .route("/download/:token/data", get(handlers::download_handler))
            .route("/download.js", get(handlers::serve_download_js))
            .route("/crypto.js", get(handlers::serve_crypto_js))
            .with_state(state),

        ServerDirection::Receive => Router::new()
            .route("/health", get(|| async { "OK" }))
            .route("/upload/:token", get(handlers::serve_upload_page))
            .route("/upload/:token/data", post(handlers::upload))
            .route("/upload.js", get(handlers::serve_upload_js))
            .route("/crypto.js", get(handlers::serve_crypto_js))
            .with_state(state),
    };

    let server = modes::Server {
        app,
        token,
        key,
        nonce,
        progress_consumer,
        file_name,
    };

    match mode {
        ServerMode::Local => modes::start_https(server, direction).await,
        ServerMode::Tunnel => modes::start_tunnel(server, direction).await,
        ServerMode::Http => modes::start_http(server, direction).await,
    }
}
