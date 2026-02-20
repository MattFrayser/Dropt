use dropt::ui::web;
use axum::{
    body::to_bytes,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

const UPLOAD_HTML: &str = include_str!("../src/ui/web/upload.html");
const DOWNLOAD_HTML: &str = include_str!("../src/ui/web/download.html");
const UPLOAD_JS: &str = include_str!("../src/ui/web/upload.js");
const DOWNLOAD_JS: &str = include_str!("../src/ui/web/download.js");
const SHARED_JS: &str = include_str!("../src/ui/web/shared.js");
const SHARED_CSS: &str = include_str!("../src/ui/web/styles.css");

fn assert_into_response<T: IntoResponse>(_: T) {}

async fn response_text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    String::from_utf8(bytes.to_vec()).expect("body should be valid UTF-8")
}

fn assert_hardening_headers(headers: &HeaderMap) {
    let csp = headers
        .get("content-security-policy")
        .expect("content-security-policy header")
        .to_str()
        .expect("content-security-policy value is valid UTF-8");

    assert!(
        csp.contains("frame-ancestors 'none'"),
        "content-security-policy should deny framing"
    );
    assert_eq!(
        headers
            .get("x-frame-options")
            .expect("x-frame-options header")
            .to_str()
            .expect("x-frame-options value is valid UTF-8"),
        "DENY"
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .expect("x-content-type-options header")
            .to_str()
            .expect("x-content-type-options value is valid UTF-8"),
        "nosniff"
    );
    assert_eq!(
        headers
            .get("referrer-policy")
            .expect("referrer-policy header")
            .to_str()
            .expect("referrer-policy value is valid UTF-8"),
        "no-referrer"
    );
}

#[tokio::test]
async fn serve_upload_page_returns_expected_html_contract() {
    let response = web::serve_upload_page().into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_hardening_headers(response.headers());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("header value is valid UTF-8"),
        "text/html; charset=utf-8"
    );
    assert_eq!(response_text(response).await, UPLOAD_HTML);
}

#[tokio::test]
async fn serve_download_page_returns_expected_html_contract() {
    let response = web::serve_download_page().into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_hardening_headers(response.headers());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("header value is valid UTF-8"),
        "text/html; charset=utf-8"
    );
    assert_eq!(response_text(response).await, DOWNLOAD_HTML);
}

#[tokio::test]
async fn serve_upload_js_returns_expected_js_contract() {
    let response = web::serve_upload_js().into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_hardening_headers(response.headers());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("header value is valid UTF-8"),
        "application/javascript;charset=utf-8"
    );
    assert_eq!(response_text(response).await, UPLOAD_JS);
}

#[tokio::test]
async fn serve_download_js_returns_expected_js_contract() {
    let response = web::serve_download_js().into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_hardening_headers(response.headers());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("header value is valid UTF-8"),
        "application/javascript;charset=utf-8"
    );
    assert_eq!(response_text(response).await, DOWNLOAD_JS);
}

#[tokio::test]
async fn serve_shared_js_returns_expected_js_contract() {
    let response = web::serve_shared_js().into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_hardening_headers(response.headers());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("header value is valid UTF-8"),
        "application/javascript;charset=utf-8"
    );
    assert_eq!(response_text(response).await, SHARED_JS);
}

#[tokio::test]
async fn serve_shared_css_returns_expected_css_contract() {
    let response = web::serve_shared_css().into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_hardening_headers(response.headers());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("header value is valid UTF-8"),
        "text/css; charset=utf-8"
    );
    assert_eq!(response_text(response).await, SHARED_CSS);
}

#[test]
fn handlers_are_sync_into_response_values() {
    assert_into_response(web::serve_upload_page());
    assert_into_response(web::serve_upload_js());
    assert_into_response(web::serve_download_page());
    assert_into_response(web::serve_download_js());
    assert_into_response(web::serve_shared_js());
    assert_into_response(web::serve_shared_css());
}
