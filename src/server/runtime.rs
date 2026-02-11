//! Runtime lifecycle: start servers, run session UI loop, and shutdown.

use crate::common::config::{AppConfig, Transport};
use crate::common::TransferState;
use crate::crypto::types::Nonce;
use crate::server::progress::ProgressTracker;
use crate::server::ServerInstance;
use crate::transport::local::{get_local_ip, start_local_server, BindScope, Protocol};
use crate::transport::tunnel::Tunnel;
use crate::ui::tui::{generate_qr, spawn_tui, spinner, spinner_error, spinner_success, TuiConfig};
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn no_tui_enabled() -> bool {
    std::env::var("NO_TUI").is_ok()
}

/// Start a direct HTTPS server and run one transfer session.
pub async fn start_https<S: TransferState>(
    server: ServerInstance,
    app_state: S,
    nonce: Nonce,
    transport: Transport,
    config: &AppConfig,
    tracker: Arc<ProgressTracker>,
) -> Result<u16> {
    let service = app_state.service_path();
    let ServerInstance {
        app,
        display_name,
        display_files,
        display_overflow_count,
    } = server;

    let (port, server_handle) = match start_local_server(
        app,
        Protocol::Https,
        BindScope::AllInterfaces,
        config.port(transport),
    )
    .await
    {
        Ok(result) => result,
        Err(err) => return Err(err),
    };

    // Use local IP instead of localhost for network access
    let local_ip = get_local_ip().unwrap_or_else(|_| "127.0.0.1".to_string());
    let base_url = format!("https://{}:{}", local_ip, port);
    let url = format!(
        "{}/{}#token={}&key={}&nonce={}",
        base_url,
        service,
        app_state.session().token(),
        app_state.session().session_key_b64(),
        nonce.to_base64()
    );

    if no_tui_enabled() {
        println!("{}", url);
    }

    run_session(
        server_handle,
        app_state,
        None,
        display_name,
        display_files,
        display_overflow_count,
        tracker,
        url,
        transport,
        config,
    )
    .await?;
    Ok(port)
}

/// Start a loopback HTTP server plus tunnel and run one session.
pub async fn start_tunnel<S: TransferState>(
    server: ServerInstance,
    app_state: S,
    nonce: Nonce,
    transport: Transport,
    config: &AppConfig,
    tracker: Arc<ProgressTracker>,
) -> Result<u16> {
    let service = app_state.service_path();
    let ServerInstance {
        app,
        display_name,
        display_files,
        display_overflow_count,
    } = server;

    let (port, server_handle) = match start_local_server(
        app,
        Protocol::Http,
        BindScope::Loopback,
        config.port(transport),
    )
    .await
    {
        Ok(result) => result,
        Err(err) => return Err(err),
    };

    let tunnel_spinner = spinner(match transport {
        Transport::Cloudflare => "Starting Cloudflare tunnel...",
        Transport::Tailscale => "Starting Tailscale tunnel...",
        Transport::Local => "Starting tunnel...",
    });

    let tunnel = match Tunnel::start(transport, port).await {
        Ok(tunnel) => {
            spinner_success(&tunnel_spinner, "Tunnel established");
            tunnel
        }
        Err(err) => {
            spinner_error(&tunnel_spinner, "Failed to establish tunnel");
            return Err(err);
        }
    };

    // Ensure tunnel URL doesn't have trailing slash
    let tunnel_url = tunnel.url().trim_end_matches('/');
    let url = format!(
        "{}/{}#token={}&key={}&nonce={}",
        tunnel_url,
        service,
        app_state.session().token(),
        app_state.session().session_key_b64(),
        nonce.to_base64()
    );
    if no_tui_enabled() {
        println!("{}", url);
    }

    run_session(
        server_handle,
        app_state,
        Some(tunnel),
        display_name,
        display_files,
        display_overflow_count,
        tracker,
        url,
        transport,
        config,
    )
    .await?;

    Ok(port)
}

/// Run transfer session loop, TUI, signal handling, and cleanup.
#[allow(clippy::too_many_arguments)]
async fn run_session<S: TransferState>(
    server_handle: axum_server::Handle,
    state: S,
    mut tunnel: Option<Tunnel>,
    display_name: String,
    display_files: Vec<String>,
    display_overflow_count: Option<usize>,
    tracker: Arc<ProgressTracker>,
    url: String,
    transport: Transport,
    config: &AppConfig,
) -> Result<()> {
    // CancellationToken for TUI / main loop
    let root_token = CancellationToken::new();
    let tui_token = root_token.child_token();

    // TUI msgs
    let (status_sender, status_receiver) = tokio::sync::watch::channel(None);

    // Spawn TUI (can be disabled with NO_TUI=1 for debugging)
    let tui_handle = if no_tui_enabled() {
        // No TUI mode - poll tracker for completion
        println!("TUI disabled. Press Ctrl+C to stop.");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tui_token.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {
                        if tracker.snapshot().is_complete() {
                            break;
                        }
                    }
                }
            }
            Ok(())
        })
    } else {
        let qr_code = generate_qr(&url)?;
        let tui_config = TuiConfig {
            is_receiving: state.is_receiving(),
            transport,
            url,
            qr_code,
            display_name,
            display_files,
            display_overflow_count,
            show_qr: config.tui.show_qr,
            show_url: config.tui.show_url,
        };
        spawn_tui(tui_config, tracker, status_receiver, tui_token)
    };

    // Spawn Ctrl+C handler — cancels root_token on first Ctrl+C
    let signal_token = root_token.clone();
    let ctrl_c_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("Failed to listen for Ctrl+C");
            return;
        }
        tracing::info!("Ctrl+C received - initiating graceful shutdown");
        signal_token.cancel();
    });

    // Wait for transfer completion or Ctrl+C
    tokio::select! {
        result = tui_handle => {
            tracing::info!("Transfer completed successfully");
            let _ = result.context("TUI task failed")?;
        }
        _ = root_token.cancelled() => {}
    };

    // Cleanup

    // Ensure TUI stops
    root_token.cancel();

    // Shutdown tunnel if it exists
    if let Some(ref mut t) = tunnel {
        tracing::debug!("Shutting down tunnel...");
        if let Err(e) = t.shutdown().await {
            tracing::warn!("Error during tunnel shutdown: {}", e);
        }
    }

    // Stop the first-stage signal handler before shutdown installs its own
    ctrl_c_task.abort();
    let _ = ctrl_c_task.await;

    // Shutdown server and drain active transfers
    shutdown(server_handle, state, status_sender).await?;

    Ok(())
}

//==========
// SHUTDOWN
//==========

enum ShutdownResult {
    Completed,
    Forced,
}

/// Stop accepting new connections, drain/force transfers, and cleanup state.
async fn shutdown<S: TransferState>(
    server_handle: axum_server::Handle,
    state: S,
    status_sender: tokio::sync::watch::Sender<Option<String>>,
) -> Result<()> {
    // Stop accepting new connections
    server_handle.shutdown();
    tracing::info!("Server stopped accepting new connections");

    // Wait for in-flight transfers to finish (Ctrl+C to force quit)
    let result = if state.session().is_completed() {
        ShutdownResult::Completed
    } else {
        wait_for_transfers(&state, &status_sender).await
    };

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

/// Wait for active transfers to finish, or force quit on Ctrl+C.
async fn wait_for_transfers<S: TransferState>(
    state: &S,
    status_sender: &tokio::sync::watch::Sender<Option<String>>,
) -> ShutdownResult {
    // Already done — no need to wait
    if state.transfer_count() == 0 {
        return ShutdownResult::Completed;
    }

    let mut last_count = state.transfer_count();

    loop {
        tokio::select! {
            // Ctrl+C during drain = force quit
            result = tokio::signal::ctrl_c() => {
                if result.is_ok() {
                    tracing::info!("Force shutdown requested");
                    return ShutdownResult::Forced;
                }
            }

            // Poll transfer status
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                let current_count = state.transfer_count();

                if current_count == 0 {
                    return ShutdownResult::Completed;
                }

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
