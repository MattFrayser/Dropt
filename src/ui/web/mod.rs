use axum::{
    body::Body,
    http::{Response, StatusCode},
    response::Html,
};

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
    serve_html(include_str!("upload.html"))
}

pub async fn serve_upload_js() -> Response<Body> {
    serve_js(include_str!("upload.js"))
}

//-- DOWNLOAD_PAGE
pub async fn serve_download_page() -> Result<Html<&'static str>, StatusCode> {
    serve_html(include_str!("download.html"))
}

pub async fn serve_download_js() -> Response<Body> {
    serve_js(include_str!("download.js"))
}

//-- SHARED JS AND CSS
pub async fn serve_shared_js() -> Response<Body> {
    serve_js(include_str!("shared.js"))
}

pub async fn serve_shared_css() -> impl axum::response::IntoResponse {
    serve_css(include_str!("styles.css"))
}
