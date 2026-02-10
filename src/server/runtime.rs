use crate::common::config::{AppConfig, Transport};
use crate::common::TransferState;
use crate::crypto::types::Nonce;
use crate::server::ServerInstance;
use crate::transport::local::{get_local_ip, start_local_server, BindScope, Protocol};
use crate::transport::tunnel::Tunnel;
use crate::ui::tui::{generate_qr, spawn_tui, spinner, spinner_error, spinner_success, TuiConfig};
use anyhow::{Context, Result};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub async fn start_https<S: TransferState>(
    server: ServerInstance,
    app_state: S,
    nonce: Nonce,
) -> Result<u16> {
    let service = app_state.service_path();

    // Clone needed before consuming server
    let display_name = server.display_name.clone();
    let progress_receiver = server.progress_receiver();

    let (port, server_handle) = start_local_server(server, Protocol::Https).await?;

    // Use local IP instead of localhost for network access
    let local_ip = get_local_ip().unwrap_or_else(|_| "127.0.0.1".to_string());
    let base_url = format!("https://{}:{}", local_ip, port);
    let url = format!(
        "{}/{}/{}#key={}&nonce={}",
        base_url,
        service,
        app_state.session().token(),
        app_state.session().session_key_b64(),
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
    )
    .await?;
    Ok(port)
}

pub async fn start_tunnel<S: TransferState>(
    server: ServerInstance,
    app_state: S,
    nonce: Nonce,
) -> Result<u16> {
    let service = app_state.service_path();

    // Clone what we need before consuming server
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
        app_state.session().token(),
        app_state.session().session_key_b64(),
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
    )
    .await?;

    Ok(port)
}

async fn run_session<S: TransferState>(
    server_handle: axum_server::Handle,
    state: S,
    mut tunnel: Option<CloudflareTunnel>,
    display_name: String,
    progress_receiver: tokio::sync::watch::Receiver<f64>,
    url: String,
) -> Result<()> {
    // CancellationTokens
    let root_token = CancellationToken::new();
    let tui_token = root_token.child_token();
    let shutdown_token = root_token.child_token();

    // TUI msgs
    let (status_sender, status_receiver) = tokio::sync::watch::channel(None);

    // Spawn TUI (can be disabled with NO_TUI=1 for debugging)
    let tui_handle = if std::env::var("NO_TUI").is_ok() {
        // No TUI mode - just print URL and wait
        println!("TUI disabled. Press Ctrl+C to stop.");
        tokio::spawn(async move {
            // Wait indefinitely until cancelled
            tui_token.cancelled().await;
        })
    } else {
        let qr_code = generate_qr(&url)?;
        spawn_tui(
            progress_receiver,
            display_name,
            qr_code,
            state.is_receiving(),
            status_receiver,
            tui_token.clone(),
        )
    };

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

async fn shutdown<S: TransferState>(
    server_handle: axum_server::Handle,
    state: S,
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

async fn wait_for_transfers<S: TransferState>(
    state: &S,
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
async fn cleanup_sessions<S: TransferState>(state: &S) {
    state.cleanup().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Session;
    use crate::crypto::types::EncryptionKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct FakeState {
        session: Session,
        active_transfers: Arc<AtomicUsize>,
        cleanup_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl TransferState for FakeState {
        fn transfer_count(&self) -> usize {
            self.active_transfers.load(Ordering::SeqCst)
        }

        async fn cleanup(&self) {
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            self.active_transfers.store(0, Ordering::SeqCst);
        }

        fn session(&self) -> &Session {
            &self.session
        }

        fn service_path(&self) -> &'static str {
            "send"
        }

        fn is_receiving(&self) -> bool {
            false
        }
    }

    fn make_state(active_transfers: usize) -> FakeState {
        FakeState {
            session: Session::new(EncryptionKey::new()),
            active_transfers: Arc::new(AtomicUsize::new(active_transfers)),
            cleanup_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn mark_session_completed(session: &Session) {
        let token = session.token().to_string();
        let lock = session.claim(&token).expect("claim session");
        assert!(session.complete(&token, &lock));
    }

    #[tokio::test]
    async fn shutdown_skips_drain_when_session_already_completed() {
        let state = make_state(3);
        mark_session_completed(state.session());
        let (status_sender, _status_receiver) = tokio::sync::watch::channel(None);
        let handle = axum_server::Handle::new();

        tokio::time::timeout(
            Duration::from_millis(100),
            shutdown(handle, state.clone(), status_sender),
        )
        .await
        .expect("shutdown should not wait for drain")
        .expect("shutdown should succeed");

        assert_eq!(
            state.cleanup_calls.load(Ordering::SeqCst),
            1,
            "cleanup should run once"
        );
        assert_eq!(state.transfer_count(), 0);
    }

    #[tokio::test]
    async fn shutdown_cleans_up_when_no_active_transfers_remain() {
        let state = make_state(0);
        let (status_sender, _status_receiver) = tokio::sync::watch::channel(None);
        let handle = axum_server::Handle::new();

        shutdown(handle, state.clone(), status_sender)
            .await
            .expect("shutdown should succeed");

        assert_eq!(
            state.cleanup_calls.load(Ordering::SeqCst),
            1,
            "cleanup should run once"
        );
        assert_eq!(state.transfer_count(), 0);
    }
}
