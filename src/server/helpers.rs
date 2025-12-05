use crate::ui::tui::TransferUI;
use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

// Poll for server ready
pub async fn wait_for_server_ready(port: u16, timeout_secs: u64, use_https: bool) -> Result<()> {
    let protocol = if use_https { "https" } else { "http" };
    let url = format!("{}://127.0.0.1:{}/health", protocol, port);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .danger_accept_invalid_certs(true) // Accept self-signed certificates
        .build()
        .context("Failed to create HTTP client")?;

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!(
                "Server failed to start within {} seconds",
                timeout_secs
            ));
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

pub fn spawn_tui(
    progress: watch::Receiver<f64>,
    file_name: String,
    qr_code: String,
    is_recieving: bool,
    status_message: watch::Receiver<Option<String>>,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ui = TransferUI::new(progress, file_name, qr_code, is_recieving, status_message);

        // Run TUI w/ cancellation support
        tokio::select! {
            result = ui.run() => {
                if let Err(e) = result {
                    eprintln!("ui err: {}", e);
                }
            }
            _ = cancel_token.cancelled() => {
                tracing::debug!("TUI task cancelled gracefully");
                // TUI will drop and restore terminal automatically
            }
        }
    })
}

// Generate certs and load directly from memory
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
