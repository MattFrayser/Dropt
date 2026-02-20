use dropt::server::auth::{BearerToken, LockToken, LOCK_HEADER_NAME};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use http_body_util::BodyExt;
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

fn build_request(auth: Option<&str>, lock: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(Method::GET).uri("/protected");

    if let Some(auth_header) = auth {
        builder = builder.header("Authorization", auth_header);
    }
    if let Some(lock_header) = lock {
        builder = builder.header(LOCK_HEADER_NAME, lock_header);
    }

    builder.body(Body::empty()).expect("valid request")
}

async fn extract_json(response: axum::response::Response) -> serde_json::Value {
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    serde_json::from_slice(&body_bytes).expect("parse json body")
}

#[tokio::test]
async fn rejects_empty_bearer_token_header() {
    let app = create_app();
    let request = build_request(Some("Bearer "), Some("lock-token"));
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "invalid authorization header");
}

#[tokio::test]
async fn rejects_missing_authorization_header() {
    let app = create_app();
    let request = build_request(None, Some("lock-token"));
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "missing authorization header");
}

#[tokio::test]
async fn rejects_malformed_authorization_header() {
    let app = create_app();
    let request = build_request(Some("Token abc123"), Some("lock-token"));
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "invalid authorization header");
}

#[tokio::test]
async fn rejects_missing_transfer_lock_header() {
    let app = create_app();
    let request = build_request(Some("Bearer token123"), None);
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "missing transfer lock header");
}

#[tokio::test]
async fn rejects_empty_transfer_lock_header() {
    let app = create_app();
    let request = build_request(Some("Bearer token123"), Some("   "));
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = extract_json(response).await;
    assert_eq!(json["error"]["type"], "unauthorized");
    assert_eq!(json["error"]["message"], "invalid transfer lock header");
}

#[tokio::test]
async fn accepts_valid_authorization_and_lock_headers() {
    let app = create_app();
    let request = build_request(Some("Bearer token123"), Some("lock-token"));
    let response = app.oneshot(request).await.expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
}
