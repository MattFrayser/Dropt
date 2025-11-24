use crate::crypto::Encryptor;
use crate::qr;
use crate::session::SessionStore;
use crate::tui::TransferUI;
use crate::tunnel::CloudflareTunnel;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::response::Response;
use axum::{routing::get, Router};
use futures::stream;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::signal;
use tokio::sync::watch;

pub enum ServerMode {
    Local,
    Http,
    Tunnel,
}

pub async fn start_server(
    file_path: PathBuf,
    mode: ServerMode,
) -> Result<u16, Box<dyn std::error::Error>> {
    let sessions = SessionStore::new();
    let encryptor = Encryptor::new();

    // encrypion values
    let key = encryptor.get_key_base64();
    let nonce = encryptor.get_nonce_base64();
    let token = sessions
        .create_session(file_path.to_string_lossy().to_string())
        .await;

    // Tui values
    let (progress_sender, progress_consumer) = watch::channel(0.0); // make progress channel
    let file_hash = "";
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();

    let state = AppState {
        sessions,
        encryptor: Arc::new(encryptor),
        progress_sender: Arc::new(tokio::sync::Mutex::new(progress_sender)),
    };

    // Create axium router
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/download/:token", get(serve_page))
        .route("/download/:token/data", get(download_handler))
        .route("/app.js", get(serve_js))
        .with_state(state);

    match mode {
        ServerMode::Local => {
            start_local(
                app,
                token,
                key,
                nonce,
                progress_consumer,
                file_name,
                file_hash,
            )
            .await
        }
        ServerMode::Tunnel => {
            start_tunnel(
                app,
                token,
                key,
                nonce,
                progress_consumer,
                file_name,
                file_hash,
            )
            .await
        }
        ServerMode::Http => {
            start_http(
                app,
                token,
                key,
                nonce,
                progress_consumer,
                file_name,
                file_hash,
            )
            .await
        }
    }
}

async fn start_local(
    app: Router,
    token: String,
    key: String,
    nonce: String,
    progress_consumer: watch::Receiver<f64>,
    file_name: String,
    file_hash: &str,
) -> Result<u16, Box<dyn std::error::Error>> {
    // local Ip and Certs
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    let addr = SocketAddr::from(([127, 0, 0, 0], 0));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();

    let tls_config = generate_cert(&local_ip).await?;

    // HTTPS for local
    let url = format!(
        "https://{}:{}/download/{}#key={}&nonce={}",
        local_ip, port, token, key, nonce
    );

    // Make TUI
    let qr_code = qr::generate_qr(&url);
    spawn_tui(
        progress_consumer,
        file_name,
        file_hash.to_owned(),
        qr_code,
        url.clone(),
    );

    // HTTPS Server
    let handle = axum_server::Handle::new();
    shutdown_handler(handle.clone());

    // Start server
    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;

    Ok(port)
}

async fn start_http(
    app: Router,
    token: String,
    key: String,
    nonce: String,
    progress_consumer: watch::Receiver<f64>,
    file_name: String,
    file_hash: &str,
) -> Result<u16, Box<dyn std::error::Error>> {
    // Start local HTTP
    let addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();

    println!("listening on port {}", port);

    // Spawn server in background
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();

    let std_listener = listener.into_std()?;

    tokio::spawn(async move {
        if let Err(e) = axum_server::from_tcp(std_listener)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
        {
            eprintln!("Server error: {}", e);
        }
    });

    // Wait for server to be ready before starting tunnel
    println!("waiting for local server");
    wait_for_server_ready(port, 5).await?;
    println!("local server ready");

    let url = format!(
        "http://127.0.0.1:{}/download/{}#key={}&nonce={}",
        port, token, key, nonce
    );

    println!("{url}");

    // Make Tui
    let qr_code = qr::generate_qr(&url);
    spawn_tui(
        progress_consumer,
        file_name,
        file_hash.to_owned(),
        qr_code,
        url,
    );

    shutdown_handler(handle);

    // Keep tunnel alive until Ctrl-C
    tokio::signal::ctrl_c().await?;

    Ok(port)
}

async fn start_tunnel(
    app: Router,
    token: String,
    key: String,
    nonce: String,
    progress_consumer: watch::Receiver<f64>,
    file_name: String,
    file_hash: &str,
) -> Result<u16, Box<dyn std::error::Error>> {
    // Start local HTTP
    let addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();

    println!("listening on port {}", port);

    // Spawn server in background
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();

    let std_listener = listener.into_std()?;

    tokio::spawn(async move {
        if let Err(e) = axum_server::from_tcp(std_listener)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
        {
            eprintln!("Server error: {}", e);
        }
    });

    // Wait for server to be ready before starting tunnel
    println!("waiting for local server");
    wait_for_server_ready(port, 5).await?;
    println!("local server ready");

    println!("Allowing server to fully initialize...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Start tunnel
    println!("starting cloudflair tunnel");
    let tunnel = CloudflareTunnel::start(port).await?;
    println!("tunnel started");

    println!("{}", tunnel.url());

    let url = format!(
        "{}/download/{}#key={}&nonce={}",
        tunnel.url(),
        token,
        key,
        nonce
    );

    println!("\nTunnel ready!");
    println!("   URL: {}\n", url);

    // Make Tui
    let qr_code = qr::generate_qr(&url);
    spawn_tui(
        progress_consumer,
        file_name,
        file_hash.to_owned(),
        qr_code,
        url,
    );

    shutdown_handler(handle);

    // Keep tunnel alive until Ctrl-C
    tokio::signal::ctrl_c().await?;

    Ok(port)
}

async fn wait_for_server_ready(
    port: u16,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("http://127.0.0.1:{}/health", port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()?;

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() > timeout {
            return Err("Server failed to start within timeout".into());
        }

        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                return Ok(());
            }
            _ => {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}
fn spawn_tui(
    progress: watch::Receiver<f64>,
    file_name: String,
    file_hash: String,
    qr_code: String,
    url: String,
) {
    tokio::spawn(async move {
        let mut ui = TransferUI::new(progress, file_name, file_hash, qr_code, url);

        if let Err(e) = ui.run().await {
            eprintln!("ui err: {}", e);
        }
    });
}

fn shutdown_handler(handle: axum_server::Handle) {
    // Spawn ctrl-c handler
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        handle.shutdown();
    });
}

fn get_local_ip() -> Option<String> {
    // Connect to external address to determine local ip
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;

async fn generate_cert(ip: &str) -> Result<RustlsConfig, Box<dyn std::error::Error>> {
    let subject_alt_names = vec![ip.to_string(), "localhost".to_string()];

    let cert = generate_simple_self_signed(subject_alt_names)?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();

    tokio::fs::write("/tmp/archdrop-cert.pem", &cert_pem).await?;
    tokio::fs::write("/tmp/archdrop-key.pem", &key_pem).await?;

    Ok(RustlsConfig::from_pem_file("/tmp/archdrop-cert.pem", "/tmp/archdrop-key.pem").await?)
}

#[derive(Clone)]
pub struct AppState {
    pub sessions: SessionStore,
    pub encryptor: Arc<Encryptor>, // Arc = thread-safe shared ownership
    pub progress_sender: Arc<tokio::sync::Mutex<watch::Sender<f64>>>,
}

async fn download_handler(
    Path(token): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    // validate token and get file path
    let file_path = state
        .sessions
        .validate_and_mark_used(&token)
        .await
        .ok_or_else(|| {
            println!("Token validation failed");
            StatusCode::FORBIDDEN
        })?; // None -> 403

    println!("Token validated and marked as used");
    println!("Original file: {}", file_path);

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
                    let _ = progress_sender.lock().await.send(100.0);
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
                    let _ = progress_sender.lock().await.send(progress);

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

async fn serve_page() -> Result<Html<&'static str>, StatusCode> {
    // return embedded html to brower
    const HTML: &str = include_str!("../templates/download.html");
    Ok(Html(HTML))
}

const JS: &str = include_str!("../templates/app.js");

async fn serve_js() -> Response {
    Response::builder()
        .header("content-type", "application/javascript; charset=utf-8")
        .body(Body::from(JS))
        .unwrap()
}
