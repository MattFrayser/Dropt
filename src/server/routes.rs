//! Router definitions for send and receive modes

use crate::{
    receive::{self, ReceiveAppState},
    send::{self, SendAppState},
    ui::web,
};
use axum::{extract::DefaultBodyLimit, routing::*, Router};

/// Build the router for send endpoints and web assets.
pub fn create_send_router(state: &SendAppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/send/manifest", get(send::handlers::manifest_handler))
        .route(
            "/send/:file_index/chunk/:chunk_index",
            get(send::handlers::send_handler),
        )
        .route("/send/complete", post(send::handlers::complete_download))
        .route("/send", get(|| async { web::serve_download_page() }))
        .route("/download.js", get(|| async { web::serve_download_js() }))
        .route("/styles.css", get(|| async { web::serve_shared_css() }))
        .route("/shared.js", get(|| async { web::serve_shared_js() }))
        .with_state(state.clone())
}

/// Start a loopback HTTP server plus tunnel and run one session.
pub fn create_receive_router(state: &ReceiveAppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/receive/manifest",
            post(receive::handlers::receive_manifest),
        )
        .route("/receive/chunk", post(receive::handlers::receive_handler))
        .route(
            "/receive/finalize",
            post(receive::handlers::finalize_upload),
        )
        .route("/receive", get(|| async { web::serve_upload_page() }))
        .route(
            "/receive/complete",
            post(receive::handlers::complete_transfer),
        )
        .route("/upload.js", get(|| async { web::serve_upload_js() }))
        .route("/styles.css", get(|| async { web::serve_shared_css() }))
        .route("/shared.js", get(|| async { web::serve_shared_js() }))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(25 * 1024 * 1024))
}
