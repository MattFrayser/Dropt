//! Cloudflare quick tunnel process management.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStderr, Command};
use tracing::{info, warn};

use crate::transport::with_startup_timeout;

const TUNNEL_POLL_INTERVAL: Duration = Duration::from_millis(200);
const START_MAX_ATTEMPTS: u8 = 3;
const START_RETRY_BACKOFF: Duration = Duration::from_millis(300);

#[derive(Deserialize)]
struct QuickTunnelResponse {
    hostname: String,
}

/// Active Cloudflare tunnel process and resolved public URL.
pub struct CloudflareTunnel {
    process: Child,
    url: String,
}

#[derive(Debug, Error)]
enum CloudflareError {
    #[error("cloudflared binary not found")]
    BinaryMissing,
    #[error("no free local port available for cloudflared metrics")]
    MetricsPortUnavailable,
    #[error("cloudflared exited before URL became available (status: {0})")]
    ProcessExited(String),
    #[error("timed out waiting for Cloudflare tunnel URL")]
    UrlTimeout,
    #[error("cloudflared startup failed: {0}")]
    StartupFailed(String),
}

/// Cloudflare startup errors
fn map_start_error(err: CloudflareError) -> anyhow::Error {
    match err {
        CloudflareError::BinaryMissing => anyhow::anyhow!(
            "Failed to start Cloudflare tunnel.\n\n\
             Install cloudflared:\n\
             https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/\n\n\
             Or use a different tunnel provider."
        ),
        CloudflareError::MetricsPortUnavailable => anyhow::anyhow!(
            "No free ports available for Cloudflare tunnel metrics.\n\n\
             This usually means too many local services are running.\n\
             Try closing some applications or use a different tunnel provider."
        ),
        CloudflareError::UrlTimeout => anyhow::anyhow!(
            "Timed out waiting for Cloudflare tunnel URL.\n\n\
             This may indicate a network issue or cloudflared startup failure.\n\
             Check your internet connection and firewall settings, then try again.\n\n\
             Or use a different tunnel provider."
        ),
        CloudflareError::ProcessExited(status) => anyhow::anyhow!(
            "cloudflared exited before tunnel URL became available (status: {status}).\n\n\
             Try again, or use a different tunnel provider."
        ),
        CloudflareError::StartupFailed(msg) => anyhow::anyhow!(
            "Failed to start Cloudflare tunnel: {msg}\n\n\
             Or use a different tunnel provider."
        ),
    }
}

impl CloudflareTunnel {
    #[tracing::instrument(fields(local_port))]
    pub async fn start(local_port: u16) -> Result<Self> {
        Self::start_with_retry(local_port)
            .await
            .map_err(map_start_error)
    }

    async fn start_with_retry(local_port: u16) -> std::result::Result<Self, CloudflareError> {
        let mut last_error = None;

        for attempt in 1..=START_MAX_ATTEMPTS {
            match Self::start_once(local_port).await {
                Ok(tunnel) => return Ok(tunnel),
                Err(err) => {
                    if attempt < START_MAX_ATTEMPTS && is_retryable_start_error(&err) {
                        warn!(
                            "Cloudflare tunnel startup attempt {}/{} failed: {}. Retrying...",
                            attempt, START_MAX_ATTEMPTS, err
                        );
                        last_error = Some(err);
                        tokio::time::sleep(START_RETRY_BACKOFF * u32::from(attempt)).await;
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        if let Some(err) = last_error {
            return Err(err);
        }

        Err(CloudflareError::StartupFailed(
            "unknown startup failure".to_string(),
        ))
    }

    async fn start_once(local_port: u16) -> std::result::Result<Self, CloudflareError> {
        let metrics_port = get_available_port().ok_or(CloudflareError::MetricsPortUnavailable)?;

        // spawn cloudflared process on port & capture output
        let mut child = Command::new("cloudflared")
            .args([
                "tunnel",
                "--url",
                &format!("http://localhost:{local_port}"),
                "--metrics",
                &format!("localhost:{metrics_port}"),
                "--no-autoupdate",
                "--protocol",
                "http2",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::NotFound {
                    CloudflareError::BinaryMissing
                } else {
                    CloudflareError::StartupFailed(err.to_string())
                }
            })?;

        // log stderr for debugging
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(log_stderr(stderr));
        }

        // Parse stream with timeout
        // reader keeps stream alive after url
        let url = match with_startup_timeout(wait_for_url(metrics_port, &mut child)).await {
            Ok(Ok(u)) => u,
            Ok(Err(e)) => {
                if let Err(kill_err) = child.kill().await {
                    warn!(
                        "Failed to kill tunnel process after startup failure: {}",
                        kill_err
                    );
                }
                return Err(e);
            }
            Err(_) => {
                if let Err(kill_err) = child.kill().await {
                    warn!(
                        "Failed to kill tunnel process after startup timeout: {}",
                        kill_err
                    );
                }
                return Err(CloudflareError::UrlTimeout);
            }
        };

        Ok(Self {
            process: child,
            url,
        })
    }

    /// Gracefully shuts down the managed `cloudflared` process.
    pub async fn shutdown(&mut self) -> Result<()> {
        if let Err(e) = self.process.kill().await {
            // failed kill often means the process is already dead
            warn!("Failed to send graceful signal to tunnel process: {}", e);
            return Ok(());
        }

        match tokio::time::timeout(Duration::from_secs(5), self.process.wait()).await {
            Ok(Ok(status)) => {
                info!("Tunnel process exited with status: {}", status);
                Ok(())
            }
            Ok(Err(e)) => Err(e).context("Failed to wait for tunnel process"),
            Err(_) => {
                warn!("Tunnel process did not exit after 5 seconds, may be stuck");
                // exhausted attempts, just log
                Ok(())
            }
        }
    }

    /// Return cloudflare quicktunnel url
    pub fn url(&self) -> &str {
        &self.url
    }
}

async fn wait_for_url(
    metrics_port: u16,
    child: &mut Child,
) -> std::result::Result<String, CloudflareError> {
    let client = reqwest::Client::new();
    let api_url = format!("http://localhost:{metrics_port}/quicktunnel");

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| CloudflareError::StartupFailed(err.to_string()))?
        {
            return Err(CloudflareError::ProcessExited(status.to_string()));
        }

        // silence errors here because we expect them while initializing
        match with_startup_timeout(client.get(&api_url).send()).await {
            Ok(Ok(res)) => match with_startup_timeout(res.json::<QuickTunnelResponse>()).await {
                Ok(Ok(json)) => {
                    if !json.hostname.is_empty() {
                        return Ok(format!("https://{}", json.hostname));
                    }
                }
                Ok(Err(_)) => {}
                Err(_) => return Err(CloudflareError::UrlTimeout),
            },
            Ok(Err(_)) => {}
            Err(_) => return Err(CloudflareError::UrlTimeout),
        }

        tokio::time::sleep(TUNNEL_POLL_INTERVAL).await;
    }
}

fn is_retryable_start_error(error: &CloudflareError) -> bool {
    match error {
        CloudflareError::UrlTimeout | CloudflareError::ProcessExited(_) => true,
        CloudflareError::StartupFailed(msg) => {
            let text = msg.to_lowercase();
            text.contains("failed to bind")
                || text.contains("address already in use")
                || text.contains("connection refused")
        }
        CloudflareError::BinaryMissing | CloudflareError::MetricsPortUnavailable => false,
    }
}

fn get_available_port() -> Option<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

// Cloudflare only uses stderr for logging
async fn log_stderr(stderr: ChildStderr) {
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();

    // Cloudflare uses stderr for both logs and errors
    // errors will contain error/fatal
    while let Some(line) = lines.next_line().await.ok().flatten() {
        let lowercase_line = line.to_lowercase();
        if lowercase_line.contains("error") || lowercase_line.contains("fatal") {
            tracing::error!("cloudflared stderr: {}", line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_errors_include_metrics_bind_conflicts() {
        assert!(is_retryable_start_error(&CloudflareError::StartupFailed(
            "failed to bind metrics listener".to_string()
        )));
    }

    #[test]
    fn retryable_errors_include_url_timeout() {
        assert!(is_retryable_start_error(&CloudflareError::UrlTimeout));
    }

    #[test]
    fn non_retryable_errors_are_not_retried() {
        assert!(!is_retryable_start_error(&CloudflareError::BinaryMissing));
    }
}
