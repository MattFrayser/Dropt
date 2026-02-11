use axum::{
    http::header,
    response::{Html, IntoResponse},
};

//-- HELPER FUNCS
fn serve_html(content: &'static str) -> Html<&'static str> {
    Html(content)
}
fn serve_js(content: &'static str) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript;charset=utf-8")],
        content,
    )
}
fn serve_css(content: &'static str) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], content)
}

//-- UPLOAD PAGE
pub fn serve_upload_page() -> impl IntoResponse {
    serve_html(include_str!("upload.html"))
}

pub fn serve_upload_js() -> impl IntoResponse {
    serve_js(include_str!("upload.js"))
}

//-- DOWNLOAD_PAGE
pub fn serve_download_page() -> impl IntoResponse {
    serve_html(include_str!("download.html"))
}

pub fn serve_download_js() -> impl IntoResponse {
    serve_js(include_str!("download.js"))
}

//-- SHARED JS AND CSS
pub fn serve_shared_js() -> impl IntoResponse {
    serve_js(include_str!("shared.js"))
}

pub fn serve_shared_css() -> impl IntoResponse {
    serve_css(include_str!("styles.css"))
}
