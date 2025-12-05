use axum::{
    body::Body,
    http::{Response, StatusCode},
    response::Html,
};

use crate::config;

//-- HELPER FUNCS
fn serve_html(content: &'static str) -> Result<Html<&'static str>, StatusCode> {
    Ok(Html(content))
}
fn serve_js(content: &'static str) -> Response<Body> {
    Response::builder()
        .header("content-type", "application/javascript;charset=utf-8")
        .body(Body::from(content))
        .unwrap()
}
fn serve_css(content: &'static str) -> Response<Body> {
    Response::builder()
        .header("content-type", "text/css; charset=utf-8")
        .body(Body::from(content))
        .unwrap()
}

//-- UPLOAD PAGE
pub async fn serve_upload_page() -> Result<Html<&'static str>, StatusCode> {
    serve_html(include_str!("../../templates/upload.html"))
}

pub async fn serve_upload_js() -> Response<Body> {
    serve_js(include_str!("../../templates/upload.js"))
}

//-- DOWNLOAD_PAGE
pub async fn serve_download_page() -> Result<Html<&'static str>, StatusCode> {
    serve_html(include_str!("../../templates/download.html"))
}

pub async fn serve_download_js() -> Response<Body> {
    serve_js(include_str!("../../templates/download.js"))
}

//-- SHARED JS AND CSS
pub async fn serve_shared_js() -> Response<Body> {
    const JS: &str = include_str!("../../templates/shared.js");

    // Inject runtime config
    // Chunk size for js and rust should match
    // Best to have one source from rust
    let js_with_config = JS.replace("__CHUNK_SIZE__", &config::CHUNK_SIZE.to_string());

    Response::builder()
        .header("content-type", "application/javascript; charset=utf-8")
        .body(Body::from(js_with_config))
        .unwrap()
}

pub async fn serve_shared_css() -> impl axum::response::IntoResponse {
    serve_css(include_str!("../../templates/styles.css"))
}
