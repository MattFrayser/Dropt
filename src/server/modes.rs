use super::utils;
use crate::server::ServerDirection;
use crate::tunnel::CloudflareTunnel;
use crate::{output, qr};
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

pub async fn start_local(
    server: Server,
    direction: ServerDirection,
) -> Result<u16, Box<dyn std::error::Error>> {
    let spinner = output::spinner("Starting local HTTPS server...");
    // local Ip and Certs
    let local_ip = utils::get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    let tls_config = utils::generate_cert(&local_ip).await?;

    // spawn server server
    let addr = SocketAddr::from(([127, 0, 0, 0], 0));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    spinner.set_message(format!("Waiting for server on port {}...", port));

    utils::wait_for_server_ready(port, 5).await?;
    output::finish_spinner_success(&spinner, &format!("Server ready on port {}", port));

    let service = match direction {
        ServerDirection::Send => "download",
        ServerDirection::Recieve => "upload",
    };

    let url = format!(
        "https://{}:{}/{}/{}#key={}&nonce={}",
        local_ip, port, service, server.token, server.key, server.nonce
    );
    println!("{}", url);

    let qr_code = qr::generate_qr(&url);
    utils::spawn_tui(
        server.progress_consumer,
        server.file_name,
        qr_code,
        service == "upload",
    );

    // HTTPS Server
    let handle = axum_server::Handle::new();
    utils::shutdown_handler(handle.clone());

    // Start server
    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(server.app.into_make_service())
        .await?;

    Ok(port)
}

pub async fn start_http(
    server: Server,
    direction: ServerDirection,
) -> Result<u16, Box<dyn std::error::Error>> {
    let Server {
        app,
        token,
        key,
        nonce,
        progress_consumer,
        file_name,
    } = server;
    // Start local HTTP
    let spinner = output::spinner("Starting local server...");
    let port = spawn_http_server(app).await?;
    spinner.set_message(format!("Waiting for server on port {}...", port));

    // Wait for server to be ready before starting tunnel
    utils::wait_for_server_ready(port, 5).await?;
    output::finish_spinner_success(&spinner, &format!("Server ready on port {}", port));

    let service = match direction {
        ServerDirection::Send => "download",
        ServerDirection::Recieve => "upload",
    };

    let url = format!(
        "http://127.0.0.1:{}/{}/{}#key={}&nonce={}",
        port, service, token, key, nonce
    );
    println!("{url}");

    // Make Tui
    let qr_code = qr::generate_qr(&url);
    utils::spawn_tui(progress_consumer, file_name, qr_code, service == "upload");

    // Keep tunnel alive until Ctrl-C
    tokio::signal::ctrl_c().await?;

    Ok(port)
}

pub async fn start_tunnel(
    server: Server,
    direction: ServerDirection,
) -> Result<u16, Box<dyn std::error::Error>> {
    let Server {
        app,
        token,
        key,
        nonce,
        progress_consumer,
        file_name,
    } = server;
    // Start local HTTP
    let spinner = output::spinner("Starting local server...");
    let port = spawn_http_server(app).await?;
    spinner.set_message(format!("Waiting for server on port {}...", port));

    // Wait for server to be ready before starting tunnel
    utils::wait_for_server_ready(port, 5).await?;
    output::finish_spinner_success(&spinner, &format!("Server ready on port {}", port));

    // Start tunnel
    let tunnel = CloudflareTunnel::start(port).await?;

    let service = match direction {
        ServerDirection::Send => "download",
        ServerDirection::Recieve => "upload",
    };

    let url = format!(
        "{}/{}/{}#key={}&nonce={}",
        tunnel.url(),
        service,
        token,
        key,
        nonce
    );
    println!("{}", url);

    let qr_code = qr::generate_qr(&url);
    utils::spawn_tui(progress_consumer, file_name, qr_code, service == "upload");

    // Keep tunnel alive until Ctrl-C
    tokio::signal::ctrl_c().await?;

    Ok(port)
}

async fn spawn_http_server(app: Router) -> Result<u16, Box<dyn std::error::Error>> {
    // Get random port
    let addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();

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

    utils::shutdown_handler(handle);
    Ok(port)
}
