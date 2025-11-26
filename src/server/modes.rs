use super::utils;
use crate::server::ServerDirection;
use crate::tunnel::CloudflareTunnel;
use crate::{output, qr};
use anyhow::{Context, Result};
use axum::Router;
use std::net::SocketAddr;
use tokio::sync::watch;

pub struct Server {
    pub app: Router,
    pub token: String,
    pub key: String,
    pub nonce: String,
    pub file_name: String,
    pub progress_consumer: watch::Receiver<f64>,
}

pub async fn start_https(server: Server, direction: ServerDirection) -> Result<u16> {
    let spinner = output::spinner("Starting local HTTPS server...");
    // local Ip and Certs
    let local_ip = utils::get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    let tls_config = utils::generate_cert(&local_ip)
        .await
        .context("Failed to generate TLS certificate")?;

    // Spawn HTTPS server and get port
    let (port, server_handle) = spawn_https_server(server.app, tls_config)
        .await
        .context("Failed to spawn HTTPS server")?;

    spinner.set_message(format!("Waiting for server on port {}...", port));

    // Wait for server to be ready
    utils::wait_for_server_ready(port, 5, true)
        .await
        .context("Server failed to become ready")?;

    output::finish_spinner_success(&spinner, &format!("Server ready on port {}", port));

    let service = match direction {
        ServerDirection::Send => "download",
        ServerDirection::Receive => "upload",
    };

    let url = format!(
        "https://{}:{}/{}/{}#key={}&nonce={}",
        local_ip, port, service, server.token, server.key, server.nonce
    );
    println!("{}", url);

    // Spawn TUI and get handle
    let qr_code = qr::generate_qr(&url)?;
    let tui_handle = utils::spawn_tui(
        server.progress_consumer,
        server.file_name,
        qr_code,
        service == "upload",
    );

    // Wait for TUI to exit or Ctrl+C
    tokio::select! {
        _ = tui_handle => {}
        _ = tokio::signal::ctrl_c() => {}
    }

    // Graceful shutdown
    server_handle.shutdown();

    Ok(port)
}

pub async fn start_http(server: Server, direction: ServerDirection) -> Result<u16> {
    // Start local HTTP
    let spinner = output::spinner("Starting local server...");

    // Get local IP for network access
    let local_ip = utils::get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    let (port, server_handle) = spawn_http_server(server.app)
        .await
        .context("Failed to spawn HTTP server")?;

    spinner.set_message(format!("Waiting for server on port {}...", port));

    utils::wait_for_server_ready(port, 5, false)
        .await
        .context("Server failed to become ready")?;

    output::finish_spinner_success(&spinner, &format!("Server ready on port {}", port));

    let service = match direction {
        ServerDirection::Send => "download",
        ServerDirection::Receive => "upload",
    };

    let url = format!(
        "http://{}:{}/{}/{}#key={}&nonce={}",
        local_ip, port, service, server.token, server.key, server.nonce
    );
    println!("{url}");

    // Spawn TUI and get handle
    let qr_code = qr::generate_qr(&url)?;
    let tui_handle = utils::spawn_tui(
        server.progress_consumer,
        server.file_name,
        qr_code,
        service == "upload",
    );

    // Wait for TUI to exit or Ctrl+C
    tokio::select! {
        _ = tui_handle => {}
        _ = tokio::signal::ctrl_c() => {}
    }

    // Graceful shutdown
    server_handle.shutdown();

    Ok(port)
}

pub async fn start_tunnel(server: Server, direction: ServerDirection) -> Result<u16> {
    // Start local HTTP
    let spinner = output::spinner("Starting local server...");
    let (port, server_handle) = spawn_http_server(server.app)
        .await
        .context("Failed to spawn HTTP server")?;
    spinner.set_message(format!("Waiting for server on port {}...", port));

    // Wait for server to be ready before starting tunnel
    utils::wait_for_server_ready(port, 5, false)
        .await
        .context("Server failed to become ready")?;
    output::finish_spinner_success(&spinner, &format!("Server ready on port {}", port));

    // Start tunnel
    let tunnel = CloudflareTunnel::start(port)
        .await
        .context("Failed to establish Cloudflare tunnel")?;

    let service = match direction {
        ServerDirection::Send => "download",
        ServerDirection::Receive => "upload",
    };

    let url = format!(
        "{}/{}/{}#key={}&nonce={}",
        tunnel.url(),
        service,
        server.token,
        server.key,
        server.nonce
    );
    println!("{}", url);

    // Spawn TUI and get handle
    let qr_code = qr::generate_qr(&url)?;
    let tui_handle = utils::spawn_tui(
        server.progress_consumer,
        server.file_name,
        qr_code,
        service == "upload",
    );

    // Wait for TUI to exit or Ctrl+C
    tokio::select! {
        _ = tui_handle => {}
        _ = tokio::signal::ctrl_c() => {}
    }

    // Graceful shutdown
    server_handle.shutdown();

    Ok(port)
}

async fn spawn_http_server(app: Router) -> Result<(u16, axum_server::Handle)> {
    // Get random port, bind to all interfaces for network access
    let addr = SocketAddr::from(([0, 0, 0, 0], 0));

    // bind to socket
    let std_listener = std::net::TcpListener::bind(addr)?;
    std_listener.set_nonblocking(true)
        .context("Failed to set listener to non-blocking mode")?;
    let port = std_listener.local_addr()?.port();

    // Spawn server in background
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();

    tokio::spawn(async move {
        if let Err(e) = axum_server::from_tcp(std_listener)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
        {
            eprintln!("Server error: {}", e);
        }
    });

    Ok((port, handle))
}

async fn spawn_https_server(app: Router, tls_config: axum_server::tls_rustls::RustlsConfig) -> Result<(u16, axum_server::Handle)> {
    // Get random port, bind to all interfaces
    let addr = SocketAddr::from(([0, 0, 0, 0], 0));

    // bind to socket
    let std_listener = std::net::TcpListener::bind(addr)?;
    std_listener.set_nonblocking(true)
        .context("Failed to set listener to non-blocking mode")?;
    let port = std_listener.local_addr()?.port();

    // Spawn server in background
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();

    tokio::spawn(async move {
        if let Err(e) = axum_server::from_tcp_rustls(std_listener, tls_config)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
        {
            eprintln!("Server error: {}", e);
        }
    });

    Ok((port, handle))
}
