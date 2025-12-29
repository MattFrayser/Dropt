use crate::ui::tui::{spinner, spinner_success};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStderr, Command};
use tracing::{info, warn};

const TUNNEL_URL_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Deserialize)]
struct QuickTunnelResponse {
    hostname: String,
}

pub struct CloudflareTunnel {
    process: Child,
    url: String,
}

impl CloudflareTunnel {
    pub async fn start(local_port: u16) -> Result<Self> {
        let spinner = spinner("Starting Cloudflare tunnel...");
        spinner.enable_steady_tick(Duration::from_millis(80));

        let metrics_port = get_available_port()
            .ok_or_else(|| anyhow::anyhow!("No free ports for tunnel metrics"))?;

        // spawn cloudflared process on port & capture output
        let mut child = Command::new("cloudflared")
            .args([
                "tunnel",
                "--url",
                &format!("http://localhost:{}", local_port),
                "--metrics",
                &format!("localhost:{}", metrics_port),
                "--no-autoupdate",
                "--protocol",
                "http2",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn cloudflared process")?;

        // log stderr for debugging
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(log_stderr(stderr));
        }

        // Parse stream with timeout
        // reader keeps stream alive after url
        let url = match wait_for_url(metrics_port).await {
            Ok(u) => u,
            Err(e) => {
                if let Err(kill_err) = child.kill().await {
                    eprintln!("Failed to kill tunnel process: {}", kill_err);
                }
                return Err(e).context("Failed to obtain tunnel URL"); // kill
            }
        };

        spinner_success(&spinner, "Tunnel established");

        Ok(Self {
            process: child,
            url,
        })
    }

    // Graceful shutdown of tunnel
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

    // used for graceful clean up of sessions
    pub fn child_process(&mut self) -> &mut Child {
        &mut self.process
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

async fn wait_for_url(metrics_port: u16) -> Result<String> {
    let client = reqwest::Client::new();
    let api_url = format!("http://localhost:{}/quicktunnel", metrics_port);

    let deadline = tokio::time::Instant::now() + TUNNEL_URL_TIMEOUT;

    while tokio::time::Instant::now() < deadline {
        // silence errors here because we expect them while initializing
        if let Ok(res) = client.get(&api_url).send().await {
            if let Ok(json) = res.json::<QuickTunnelResponse>().await {
                if !json.hostname.is_empty() {
                    return Ok(format!("https://{}", json.hostname));
                }
            }
        }

        tokio::time::sleep(TUNNEL_POLL_INTERVAL).await;
    }

    anyhow::bail!("Timed out waiting for tunnel URL")
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
