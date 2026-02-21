mod common;

use dropt::server::auth::{BearerToken, LockToken};
use axum::{
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use common::send_http::{build_request, extract_json};
use tower::ServiceExt;

fn create_app() -> Router {
    async fn protected(
        BearerToken(_token): BearerToken,
        LockToken(_lock): LockToken,
    ) -> impl IntoResponse {
        StatusCode::OK
    }

    Router::new().route("/protected", get(protected))
}

#[tokio::test]
async fn rejects_empty_bearer_token_header() {
    let app = create_app();
    let request = build_request(Method::GET, "/protected", Some("Bearer "), Some("lock-token"));
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "invalid authorization header");
}

#[tokio::test]
async fn rejects_missing_authorization_header() {
    let app = create_app();
    let request = build_request(Method::GET, "/protected", None, Some("lock-token"));
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "missing authorization header");
}

#[tokio::test]
async fn rejects_malformed_authorization_header() {
    let app = create_app();
    let request = build_request(
        Method::GET,
        "/protected",
        Some("Token abc123"),
        Some("lock-token"),
    );
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "invalid authorization header");
}

#[tokio::test]
async fn rejects_missing_transfer_lock_header() {
    let app = create_app();
    let request = build_request(Method::GET, "/protected", Some("Bearer token123"), None);
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "missing transfer lock header");
}

#[tokio::test]
async fn rejects_empty_transfer_lock_header() {
    let app = create_app();
    let request = build_request(Method::GET, "/protected", Some("Bearer token123"), Some("   "));
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "invalid transfer lock header");
}

#[tokio::test]
async fn accepts_valid_authorization_and_lock_headers() {
    let app = create_app();
    let request = build_request(
        Method::GET,
        "/protected",
        Some("Bearer token123"),
        Some("lock-token"),
    );
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
}
