use axum::{
    http::header,
    response::{Html, IntoResponse},
};

//-- HELPER FUNCS
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

fn hardening_headers() -> [(header::HeaderName, &'static str); 4] {
    [
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
    ]
}

fn typed_hardening_headers(content_type: &'static str) -> [(header::HeaderName, &'static str); 5] {
    [
        (header::CONTENT_TYPE, content_type),
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
    ]
}

fn serve_html(content: &'static str) -> Html<&'static str> {
    Html(content)
}
fn serve_js(content: &'static str) -> impl IntoResponse {
    (
        typed_hardening_headers("application/javascript;charset=utf-8"),
        content,
    )
}
fn serve_css(content: &'static str) -> impl IntoResponse {
    (typed_hardening_headers("text/css; charset=utf-8"), content)
}

//-- UPLOAD PAGE
pub fn serve_upload_page() -> impl IntoResponse {
    (hardening_headers(), serve_html(include_str!("upload.html")))
}

pub fn serve_upload_js() -> impl IntoResponse {
    serve_js(include_str!("upload.js"))
}

//-- DOWNLOAD_PAGE
pub fn serve_download_page() -> impl IntoResponse {
    (
        hardening_headers(),
        serve_html(include_str!("download.html")),
    )
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
