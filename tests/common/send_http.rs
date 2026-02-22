use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;

use dropt::common::Manifest;
use dropt::crypto::types::EncryptionKey;
use dropt::send::SendAppState;
use dropt::server::auth::LOCK_HEADER_NAME;
use dropt::server::progress::ProgressTracker;
use dropt::server::routes;

use super::{default_config, CHUNK_SIZE};

//===========
// App Factory
//===========
pub async fn create_send_test_app(
    file_paths: Vec<std::path::PathBuf>,
    key: EncryptionKey,
) -> (Router, SendAppState, u64) {
    let config = default_config();
    let manifest = Manifest::new(file_paths, None, config)
        .await
        .expect("Failed to create manifest");

    let total_chunks = manifest
        .files
        .iter()
        .map(|f| f.size.div_ceil(CHUNK_SIZE as u64))
        .sum();

    let progress = Arc::new(ProgressTracker::new());
    let state = SendAppState::new(key, manifest, total_chunks, progress, config);
    let app = routes::create_send_router(&state);

    (app, state, total_chunks)
}

//=================
// Request Builders
//=================
pub fn build_request(
    method: Method,
    uri: &str,
    auth: Option<&str>,
    lock_token: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(auth_header) = auth {
        builder = builder.header("Authorization", auth_header);
    }
    if let Some(lock) = lock_token {
        builder = builder.header(LOCK_HEADER_NAME, lock);
    }
    builder
        .body(Body::empty())
        .expect("Failed to build request")
}

pub fn build_bearer_request(
    method: Method,
    uri: &str,
    token: &str,
    lock_token: Option<&str>,
) -> Request<Body> {
    let auth = format!("Bearer {}", token);
    build_request(method, uri, Some(&auth), lock_token)
}

//================
// Response Helpers
//================
pub async fn extract_json(response: axum::response::Response) -> serde_json::Value {
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();
    serde_json::from_slice(&body_bytes).expect("Failed to parse JSON")
}

pub async fn extract_bytes(response: axum::response::Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes()
        .to_vec()
}

pub async fn assert_error_response(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_type: &str,
    expected_message_contains: &str,
) {
    assert_eq!(response.status(), expected_status);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], expected_type);
    let message = json["error"]["message"]
        .as_str()
        .expect("error.message should be a string")
        .to_lowercase();
    assert!(
        message.contains(&expected_message_contains.to_lowercase()),
        "error message should contain '{expected_message_contains}', got '{message}'"
    );
}
