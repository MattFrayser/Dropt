use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Method, Request},
};
use http_body_util::BodyExt;

use super::default_config;
use dropt::common::CollisionPolicy;
use dropt::crypto::types::EncryptionKey;
use dropt::receive::ReceiveAppState;
use dropt::server::progress::ProgressTracker;
use dropt::server::routes;

//===========
// App Factory
//===========
pub fn create_receive_test_app(
    output_dir: PathBuf,
    key: EncryptionKey,
) -> (Router, ReceiveAppState) {
    create_receive_test_app_with_policy(output_dir, key, CollisionPolicy::default())
}

pub fn create_receive_test_app_with_policy(
    output_dir: PathBuf,
    key: EncryptionKey,
    policy: CollisionPolicy,
) -> (Router, ReceiveAppState) {
    let progress = Arc::new(ProgressTracker::new());
    let config = default_config();
    let state = ReceiveAppState::new(key, output_dir, progress, config, policy);
    let app = routes::create_receive_router(&state);
    (app, state)
}

//=================
// Request Builders
//=================
pub fn build_json_request(uri: &str, json: serde_json::Value, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json).expect("Failed to serialize JSON"),
        ))
        .expect("Failed to build request")
}

#[allow(clippy::too_many_arguments)]
pub fn build_multipart_request(
    uri: &str,
    relative_path: &str,
    chunk_index: usize,
    total_chunks: usize,
    file_size: u64,
    nonce: &str,
    chunk_data: Vec<u8>,
    token: &str,
) -> Request<Body> {
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    let write_field = |body: &mut Vec<u8>, name: &str, value: &str| {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    };

    write_field(&mut body, "relativePath", relative_path);
    write_field(&mut body, "chunkIndex", &chunk_index.to_string());
    write_field(&mut body, "totalChunks", &total_chunks.to_string());
    write_field(&mut body, "fileSize", &file_size.to_string());
    write_field(&mut body, "nonce", nonce);

    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chunk\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&chunk_data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .expect("Failed to build multipart request")
}

pub fn build_finalize_request(uri: &str, relative_path: &str, token: &str) -> Request<Body> {
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"relativePath\"\r\n\r\n");
    body.extend_from_slice(relative_path.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .expect("Failed to build finalize request")
}

pub fn build_complete_request(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("Failed to build complete request")
}

//==============
// Header Helpers
//==============
pub fn with_lock_token(mut request: Request<Body>, lock_token: &str) -> Request<Body> {
    request.headers_mut().insert(
        "X-Transfer-Lock",
        lock_token.parse().expect("valid lock token header"),
    );
    request
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
