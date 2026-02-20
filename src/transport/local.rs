//! Local server bootstrap utilities
//!
//! - Tunnel mode should bind loopback only.
//! - Local HTTPS mode may bind all interfaces for LAN access.

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;
use std::net::{SocketAddr, UdpSocket};

/// HTTP/TLS mode used for local server startup.
pub enum Protocol {
    Https,
    Http,
}

/// Address exposure policy for the listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindScope {
    Loopback,
    AllInterfaces,
}

fn bind_addr(scope: BindScope, port: u16) -> SocketAddr {
    match scope {
        BindScope::Loopback => SocketAddr::from(([127, 0, 0, 1], port)),
        BindScope::AllInterfaces => SocketAddr::from(([0, 0, 0, 0], port)),
    }
}

/// Starts a local Axum server and returns `(bound_port, handle)`.
pub async fn start_local_server(
    app: axum::Router,
    protocol: Protocol,
    bind_scope: BindScope,
    port: u16,
) -> Result<(u16, axum_server::Handle)> {
    let addr = bind_addr(bind_scope, port);
    let listener = std::net::TcpListener::bind(addr).context(
        "Failed to bind to port - port already in use.\n\n\
         Is another dropt instance running?\n\
         Or is another service using this port?",
    )?;

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
            let local_ip = get_local_ip().unwrap_or_else(|_| "127.0.0.1".to_string());
            let tls_config = generate_cert(&local_ip)
                .await
                .context("Failed to generate TLS certificate")?;
            tokio::spawn(async move {
                if let Err(e) = axum_server::from_tcp_rustls(listener, tls_config)
                    .handle(server_handle_clone)
                    .serve(app.into_make_service())
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
                    .serve(app.into_make_service())
                    .await
                {
                    eprintln!("Server error: {}", e);
                }
            });
        }
    }

    Ok((port, server_handle))
}

/// Best-effort local non-loopback IP discovery for URL/certificate use.
pub fn get_local_ip() -> Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind socket for IP detection")?;

    socket
        .connect("8.8.8.8:80")
        .context("Failed to connect socket for IP detection")?;

    let local_addr = socket.local_addr().context("Failed to get local address")?;

    Ok(local_addr.ip().to_string())
}

/// Builds an in-memory self-signed TLS config for local HTTPS serving.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_scope_binds_only_loopback() {
        let addr = bind_addr(BindScope::Loopback, 8080);
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn all_interfaces_scope_binds_lan_capable() {
        let addr = bind_addr(BindScope::AllInterfaces, 8080);
        assert_eq!(addr.ip().to_string(), "0.0.0.0");
    }
}
