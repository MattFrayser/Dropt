use axum::{
    body::Body,
    http::{Response, StatusCode},
    response::Html,
};

pub async fn serve_upload_page() -> Result<Html<&'static str>, StatusCode> {
    const HTML: &str = include_str!("../../templates/upload.html");
    Ok(Html(HTML))
}

pub async fn serve_upload_js() -> Response<Body> {
    const JS: &str = include_str!("../../templates/upload.js");
    Response::builder()
        .header("content-type", "application/javascript; charset=utf-8")
        .body(Body::from(JS))
        .unwrap()
}

pub async fn serve_download_page() -> Result<Html<&'static str>, StatusCode> {
    const HTML: &str = include_str!("../../templates/download.html");
    Ok(Html(HTML))
}

pub async fn serve_download_js() -> Response<Body> {
    const JS: &str = include_str!("../../templates/download.js");
    Response::builder()
        .header("content-type", "application/javascript; charset=utf-8")
        .body(Body::from(JS))
        .unwrap()
}

pub async fn serve_shared_js() -> Response<Body> {
    const JS: &str = include_str!("../../templates/shared.js");
    Response::builder()
        .header("content-type", "application/javascript; charset=utf-8")
        .body(Body::from(JS))
        .unwrap()
}

pub async fn serve_shared_css() -> impl axum::response::IntoResponse {
    let css = include_str!("../../templates/styles.css");
    Response::builder()
        .header("content-type", "text/css")
        .body(Body::from(css))
        .unwrap()
}
