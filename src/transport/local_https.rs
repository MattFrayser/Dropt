use crate::server::ServerInstance;
use crate::ui::tui::{spinner, spinner_success};
use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;
use std::net::{SocketAddr, UdpSocket};

pub enum Protocol {
    Https,
    Http,
}

/// Utility function for building base HTTP/HTTPS server
pub async fn start_local_server(
    server: ServerInstance,
    protocol: Protocol,
) -> Result<(u16, axum_server::Handle)> {
    let spinner = spinner("Starting local server...");

    // Bind to random port
    let addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let listener = std::net::TcpListener::bind(addr).context("Failed to bind socket")?;

    listener
        .set_nonblocking(true)
        .context("Failed to set listener to non-blocking mode")?;

    let port = listener.local_addr()?.port();

    // Spawn HTTP server in background
    let server_handle = axum_server::Handle::new();
    let server_handle_clone = server_handle.clone();

    // HTTPS uses self signed certs
    match protocol {
        Protocol::Https => {
            // Use local IP for certificate to allow network access
            let local_ip = get_local_ip().unwrap_or_else(|_| "127.0.0.1".to_string());
            let tls_config = generate_cert(&local_ip)
                .await
                .context("Failed to generate TLS certificate")?;
            tokio::spawn(async move {
                if let Err(e) = axum_server::from_tcp_rustls(listener, tls_config)
                    .handle(server_handle_clone)
                    .serve(server.app.into_make_service())
                    .await
                {
                    eprintln!("Server error: {}", e);
                }
            });
        }
        Protocol::Http => {
            tokio::spawn(async move {
                if let Err(e) = axum_server::from_tcp(listener)
                    .handle(server_handle_clone)
                    .serve(server.app.into_make_service())
                    .await
                {
                    eprintln!("Server error: {}", e);
                }
            });
        }
    }

    spinner_success(&spinner, &format!("Server ready on port {}", port));

    Ok((port, server_handle))
}

/// Get the local IP address (non-loopback)
pub fn get_local_ip() -> Result<String> {
    // This doesn't actually send data, just determines the local IP
    // Needed for --local flag
    let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind socket for IP detection")?;

    socket
        .connect("8.8.8.8:80")
        .context("Failed to connect socket for IP detection")?;

    let local_addr = socket.local_addr().context("Failed to get local address")?;

    Ok(local_addr.ip().to_string())
}

/// Generate certs and load directly from memory
pub async fn generate_cert(ip: &str) -> Result<RustlsConfig> {
    let subject_alt_names = vec![ip.to_string(), "localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = cert
        .serialize_pem()
        .context("Failed to serialize certificate to PEM")?
        .into_bytes();
    let key_pem = cert.serialize_private_key_pem().into_bytes();

    RustlsConfig::from_pem(cert_pem, key_pem)
        .await
        .context("Failed to create TLS configuration")
}
