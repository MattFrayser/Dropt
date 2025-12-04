//! Router definitions for send and receive modes

use crate::{
    server::{state::AppState, static_files},
    transfer,
};
use axum::{routing::*, Router};

/// Create router for send mode
pub fn create_send_router(state: &AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/send/:token/manifest",
            get(transfer::send_handlers::manifest_handler),
        )
        .route(
            "/send/:token/:file_index/chunk/:chunk_index",
            get(transfer::send_handlers::send_handler),
        )
        .route(
            "/send/:token/:file_index/hash",
            get(transfer::send_handlers::get_file_hash),
        )
        .route(
            "/send/:token/complete",
            post(transfer::send_handlers::complete_download),
        )
        .route("/send/:token", get(static_files::serve_download_page))
        .route("/download.js", get(static_files::serve_download_js))
        .route("/styles.css", get(static_files::serve_shared_css))
        .route("/shared.js", get(static_files::serve_shared_js))
        .with_state(state.clone())
}

/// Create router for receive mode
pub fn create_receive_router(state: &AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/receive/:token/manifest",
            post(transfer::receive_handlers::receive_manifest),
        )
        .route(
            "/receive/:token/chunk",
            post(transfer::receive_handlers::receive_handler),
        )
        .route(
            "/receive/:token/finalize",
            post(transfer::receive_handlers::finalize_upload),
        )
        .route("/receive/:token", get(static_files::serve_upload_page))
        .route(
            "/receive/:token/complete",
            post(transfer::receive_handlers::complete_transfer),
        )
        .route("/upload.js", get(static_files::serve_upload_js))
        .route("/styles.css", get(static_files::serve_shared_css))
        .route("/shared.js", get(static_files::serve_shared_js))
        .with_state(state.clone())
}
