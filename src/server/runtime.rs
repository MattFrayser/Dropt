use crate::crypto::types::Nonce;
use crate::server::state::{AppState, TransferStorage};
use crate::server::{helpers, ServerDirection, ServerInstance};
use crate::tunnel::CloudflareTunnel;
use crate::ui::{output, qr};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

enum Protocol {
    Https,
    Http,
}
pub async fn start_https(
    server: ServerInstance,
    app_state: AppState,
    direction: ServerDirection,
    nonce: Nonce,
) -> Result<u16> {
    let service = direction.to_string();

    // Clone needed before consuming server
    let session = server.session.clone();
    let display_name = server.display_name.clone();
    let progress_receiver = server.progress_receiver();

    let (port, server_handle) = start_local_server(server, Protocol::Https).await?;

    let base_url = format!("https://127.0.0.1:{}", port);
    let url = format!(
        "{}/{}/{}#key={}&nonce={}",
        base_url,
        service,
        session.token(),
        session.session_key_b64(),
        nonce.to_base64()
    );

    println!("{}", url);

    run_session(
        server_handle,
        app_state,
        None,
        display_name,
        progress_receiver,
        url,
        service,
    )
    .await?;
    Ok(port)
}

pub async fn start_tunnel(
    server: ServerInstance,
    app_state: AppState,
    direction: ServerDirection,
    nonce: Nonce,
) -> Result<u16> {
    let service = direction.to_string();

    // Clone what we need before consuming server
    let session = server.session.clone();
    let display_name = server.display_name.clone();
    let progress_receiver = server.progress_receiver();

    let (port, server_handle) = start_local_server(server, Protocol::Http).await?;

    // Start tunnel
    let tunnel = CloudflareTunnel::start(port)
        .await
        .context("Failed to establish Cloudflare tunnel")?;

    // Ensure tunnel URL doesn't have trailing slash
    let tunnel_url = tunnel.url().trim_end_matches('/');
    let url = format!(
        "{}/{}/{}#key={}&nonce={}",
        tunnel_url,
        service,
        session.token(),
        session.session_key_b64(),
        nonce.to_base64()
    );
    println!("{}", url);

    run_session(
        server_handle,
        app_state,
        Some(tunnel),
        display_name,
        progress_receiver,
        url,
        service,
    )
    .await?;

    Ok(port)
}

/// Utility function for building base HTTP/HTTPS sever
async fn start_local_server(
    server: ServerInstance,
    protocol: Protocol,
) -> Result<(u16, axum_server::Handle)> {
    let spinner = output::spinner("Starting local server...");

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
            let tls_config = helpers::generate_cert("127.0.0.1")
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

    let use_https = matches!(protocol, Protocol::Https);
    helpers::wait_for_server_ready(port, 5, use_https)
        .await
        .context("Server failed to become ready")?;
    output::spinner_success(&spinner, &format!("Server ready on port {}", port));

    Ok((port, server_handle))
}

async fn run_session(
    server_handle: axum_server::Handle,
    state: AppState,
    mut tunnel: Option<CloudflareTunnel>,
    display_name: String,
    progress_receiver: tokio::sync::watch::Receiver<f64>,
    url: String,
    service: String,
) -> Result<()> {
    // CancellationTokens
    let root_token = CancellationToken::new();
    let tui_token = root_token.child_token();
    let shutdown_token = root_token.child_token();

    // TUI msgs
    let (status_sender, status_receiver) = tokio::sync::watch::channel(None);

    // Spawn TUI
    let qr_code = qr::generate_qr(&url)?;
    let tui_handle = helpers::spawn_tui(
        progress_receiver,
        display_name,
        qr_code,
        service == "upload",
        status_receiver,
        tui_token.clone(),
    );

    // Spawn Ctrl+C handler with two-stage loop
    let signal_token = root_token.clone();
    let signal_status_sender = status_sender.clone();
    let signal_state = state.clone();

    let ctrl_c_task = tokio::spawn(async move {
        // Wait for first Ctrl+C
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("Failed to listen for Ctrl+C");
            return;
        }

        tracing::info!("Ctrl+C received - initiating graceful shutdown");

        // Check if there are active transfers
        let active_count = signal_state.transfer_count();

        if active_count > 0 {
            let _ = signal_status_sender.send(Some(format!(
                "Shutting down... {} transfer(s) in progress - Press Ctrl+C again to force quit",
                active_count
            )));
        }
        // Cancel all tasks gracefully
        signal_token.cancel();

        // second Ctrl+C for immediate shutdown
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("Second Ctrl+C - forcing immediate shutdown");
            // Token already cancelled
            // let runtime clean up
        }
    });

    //  wait for complete or cancel
    tokio::select! {
        result = tui_handle => {
            tracing::info!("Transfer completed successfully");
            result.context("TUI task failed")?;
            ShutdownResult::Completed
        }
        _ = shutdown_token.cancelled() => {
            tracing::info!("Shutdown requested via Ctrl+C");
            ShutdownResult::Forced
        }
    };

    // cleanup

    // Ensure all tokens are cancelled
    root_token.cancel();

    // Shutdown tunnel if it exists
    if let Some(ref mut t) = tunnel {
        tracing::debug!("Shutting down cloudflared tunnel...");
        if let Err(e) = t.shutdown().await {
            tracing::warn!("Error during tunnel shutdown: {}", e);
        }
    }

    // Wait for signal handler to finish (should be quick)
    ctrl_c_task.abort(); // It's ok to abort this one - it's just listening
    let _ = ctrl_c_task.await;

    // Shutdown server and wait for transfers
    shutdown(server_handle, state, shutdown_token, status_sender).await?;

    Ok(())
}

//==========
// SHUTDOWN
//==========

enum ShutdownResult {
    Completed,
    Forced,
}

async fn shutdown(
    server_handle: axum_server::Handle,
    state: AppState,
    cancel_token: CancellationToken,
    status_sender: tokio::sync::watch::Sender<Option<String>>,
) -> Result<()> {
    // Stop accepting new connections
    server_handle.shutdown();
    tracing::info!("Server stopped accepting new connections");

    // Wait for active transfers to complete
    let result = wait_for_transfers(&state, cancel_token, status_sender.clone()).await;

    // Clear status message before final cleanup
    let _ = status_sender.send(None);

    match result {
        ShutdownResult::Completed => {
            tracing::info!("All transfers completed successfully");
        }
        ShutdownResult::Forced => {
            let remaining = state.transfer_count();
            tracing::warn!("Forced shutdown with {} pending transfers", remaining);
        }
    }

    // Clean up sessions
    cleanup_sessions(&state).await;
    tracing::info!("Server shutdown complete");

    Ok(())
}

async fn wait_for_transfers(
    state: &AppState,
    cancel_token: CancellationToken,
    status_sender: tokio::sync::watch::Sender<Option<String>>,
) -> ShutdownResult {
    let mut last_count = state.transfer_count();

    loop {
        // Wait for cancellation OR timeout
        tokio::select! {
            // Cancellation requested (second Ctrl+C)
            _ = cancel_token.cancelled() => {
                tracing::info!("Force shutdown requested");
                return ShutdownResult::Forced;
            }

            // Check transfer status periodically
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                let current_count = state.transfer_count();

                // All transfers complete
                if current_count == 0 {
                    return ShutdownResult::Completed;
                }

                // Show progress if count changed
                if current_count != last_count {
                    tracing::info!("{} transfer(s) remaining...", current_count);
                    let _ = status_sender.send(Some(format!(
                        "{} transfer(s) remaining - Press Ctrl+C to force quit",
                        current_count
                    )));
                    last_count = current_count;
                }
            }
        }
    }
}

/// Clean up all active sessions, triggering Drop cleanup for incomplete transfers
async fn cleanup_sessions(state: &AppState) {
    match &state.transfers {
        TransferStorage::Send(sessions) => {
            let count = sessions.len();
            if count > 0 {
                tracing::info!("Cleaning up {} send session(s)", count);
            }
            sessions.clear();
        }
        TransferStorage::Receive(sessions) => {
            let count = sessions.len();
            if count == 0 {
                return;
            }
            tracing::info!("Cleaning up {} receive session(s)", count);

            // Collect keys first. allows safe iteration and removal.
            let keys: Vec<String> = sessions.iter().map(|entry| entry.key().clone()).collect();

            // Drain sessions by taking ownership
            let cleanup_tasks: Vec<_> = keys
                .into_iter()
                // take ownership FileReceiveState value
                .filter_map(|key| sessions.remove(&key))
                .map(|(_key, file_receive_state)| {
                    // Spawn async cleanup operation task for each
                    tokio::spawn(async move {
                        if let Err(e) = file_receive_state.storage.cleanup().await {
                            tracing::error!("Error during async cleanup: {}", e);
                        }
                    })
                })
                .collect();

            futures::future::join_all(cleanup_tasks).await;
        }
    }
    tracing::debug!("Session cleanup complete");
}
