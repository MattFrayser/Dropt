use crate::crypto::Encryptor;
use crate::session::SessionStore;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, Response};
use futures::stream;
use futures::StreamExt;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

#[derive(Clone)]
pub struct AppState {
    pub sessions: SessionStore,
    pub encryptor: Arc<Encryptor>, // Arc = thread-safe shared ownership
    pub progress_sender: watch::Sender<f64>,
}

pub async fn download_handler(
    Path(token): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    // validate token and get file path
    let file_path = state
        .sessions
        .validate_and_mark_used(&token)
        .await
        .ok_or(StatusCode::FORBIDDEN)?;

    // Extract filename
    let filename = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download"); // default to generic 'download'

    // open file asynchronously to not block thread
    let file = File::open(&file_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; // Error -> 500

    let encryptor = state.encryptor.create_stream_encryptor();

    // clone progress for stream
    let progress_sender = state.progress_sender.clone();

    // file meta data for progress
    let file_metadata = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; // Error -> 500
    let total_size = file_metadata.len() as f64;
    let bytes_sent = 0u64;

    // Async Stream
    // Create sream form state machine
    // 4KB buffer initial
    let stream = stream::unfold(
        (
            file,
            encryptor,
            [0u8; 4096],
            bytes_sent,
            total_size,
            progress_sender,
        ),
        |(mut file, mut enc, mut buf, mut bytes_sent, total_size, progress_sender)| async move {
            //consume buffer
            match file.read(&mut buf).await {
                Ok(0) => {
                    let _ = progress_sender.send(100.0);
                    None
                }
                Ok(n) => {
                    let chunk = &buf[..n]; // bytes read

                    // encrypt chunk
                    let encrypted = enc.encrypt_next(chunk).ok()?; // convert res to Option, end steam on err

                    // Frame format for browser parsing
                    let len = encrypted.len() as u32;
                    let mut framed = len.to_be_bytes().to_vec(); // prefix len
                    framed.extend_from_slice(&encrypted); // append encrypted data

                    // update progress
                    bytes_sent += n as u64;
                    let progress = (bytes_sent as f64 / total_size) * 100.0;
                    let _ = progress_sender.send(progress);

                    // return (stream item, state for next)
                    // Ok wraps body for Body::from_stream
                    Some((
                        Ok::<_, std::io::Error>(framed),
                        (file, enc, buf, bytes_sent, total_size, progress_sender),
                    ))
                }

                Err(e) => Some((
                    Err(e),
                    (file, enc, buf, bytes_sent, total_size, progress_sender),
                )),
            }
        },
    );

    println!("Starting stream");
    Response::builder()
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from_stream(stream))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn serve_download_page() -> Result<Html<&'static str>, StatusCode> {
    // return embedded html to brower
    const HTML: &str = include_str!("../../templates/download/download.html");
    Ok(Html(HTML))
}

pub async fn serve_download_js() -> Response {
    const JS: &str = include_str!("../../templates/download/download.js");
    Response::builder()
        .header("content-type", "application/javascript; charset=utf-8")
        .body(Body::from(JS))
        .unwrap()
}

pub async fn upload(
    Path(token): Path<String>,
    State(state): State<AppState>,
    _headers: HeaderMap,
    body: Body,
) -> Result<Response, StatusCode> {
    // Validate token
    let dest_dir = state
        .sessions
        .validate_and_mark_used(&token)
        .await
        .ok_or(StatusCode::FORBIDDEN)?;

    // naming
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("upload_{}.zip", timestamp);
    let dest_path = std::path::Path::new(&dest_dir).join(&filename);

    let mut file = File::create(&dest_path).await.map_err(|e| {
        eprintln!("Failed to create file: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Create decryptor
    let mut decryptor = state.encryptor.create_stream_decryptor();

    // Clone progress sender for tracking
    let progress_sender = state.progress_sender.clone();

    // Read first 8 bytes for total encrypted size
    let mut stream = body.into_data_stream();
    let mut size_buffer = Vec::with_capacity(8);

    // Accumulate exactly 8 bytes for size header
    while size_buffer.len() < 8 {
        let chunk = stream
            .next()
            .await
            .ok_or(StatusCode::BAD_REQUEST)?
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        size_buffer.extend_from_slice(&chunk);
    }

    // Parse total size from first 8 bytes (big-endian)
    let total_size = u64::from_be_bytes([
        size_buffer[0],
        size_buffer[1],
        size_buffer[2],
        size_buffer[3],
        size_buffer[4],
        size_buffer[5],
        size_buffer[6],
        size_buffer[7],
    ]) as f64;

    // Use remaining bytes after size header as initial buffer
    let mut buffer: Vec<u8> = size_buffer.drain(8..).collect();
    let mut bytes_received = buffer.len() as u64;

    // Process encrypted frames
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            eprintln!("Stream error: {}", e);
            StatusCode::BAD_REQUEST
        })?;

        buffer.extend_from_slice(&chunk);
        bytes_received += chunk.len() as u64;

        // parse framed chunks
        while buffer.len() >= 4 {
            let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

            if buffer.len() < 4 + len {
                break; // wait for more data
            }

            let encrypted_chunk = &buffer[4..4 + len];
            let plaintext = decryptor.decrypt_next(encrypted_chunk).map_err(|e| {
                eprintln!("Decryption failed: {:?}", e);
                StatusCode::BAD_REQUEST
            })?;

            file.write_all(&plaintext).await.map_err(|e| {
                eprintln!("Failed to write to file: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // remove decrypted chunk
            buffer.drain(..4 + len);

            // Update progress
            let progress = (bytes_received as f64 / total_size) * 100.0;
            let _ = progress_sender.send(progress.min(100.0));
        }
    }

    // ensure all data is written
    file.flush()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Send final 100% progress
    let _ = progress_sender.send(100.0);

    println!("Upload complete");

    let response_json = format!(r#"{{"success":true,"filename":"{}"}}"#, filename);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response_json))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn serve_upload_page() -> Result<Html<&'static str>, StatusCode> {
    // return embedded html to brower
    const HTML: &str = include_str!("../../templates/upload/upload.html");
    Ok(Html(HTML))
}

pub async fn serve_upload_js() -> Response {
    const JS: &str = include_str!("../../templates/upload/upload.js");
    Response::builder()
        .header("content-type", "application/javascript; charset=utf-8")
        .body(Body::from(JS))
        .unwrap()
}

pub async fn serve_crypto_js() -> Response {
    const JS: &str = include_str!("../../templates/shared/crypto.js");
    Response::builder()
        .header("content-type", "application/javascript; charset=utf-8")
        .body(Body::from(JS))
        .unwrap()
}
