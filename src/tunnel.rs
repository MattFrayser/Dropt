use anyhow::{bail, ensure, Context, Result};
use regex::Regex;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use crate::output;

pub struct CloudflareTunnel {
    process: Child,
    url: String,
}

impl CloudflareTunnel {
    pub async fn start(local_port: u16) -> Result<Self> {
        // ui spinner
        let spinner = output::spinner("Starting tunnel...");

        spinner.set_message("Starting cloudflare tunnel...");
        spinner.enable_steady_tick(Duration::from_millis(80));

        // check cloudflared installed
        ensure!(
            Self::is_installed().await,
            "cloudflared is not installed\n\
             \n\
             Install: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/\n\
             Or use --local flag for HTTPS without tunnel"
        );

        // spawn cloudflared process & capture output
        let mut child = Command::new("cloudflared")
            .args(&[
                "tunnel",
                "--url",
                &format!("http://localhost:{}", local_port),
                "--no-autoupdate",
                "--protocol",
                "http2",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn cloudflared process")?;

        let stderr = child
            .stderr
            .take()
            .context("Failed to capture cloudflared output")?;

        // Parse stream with timeout
        // reader keeps stream alive after url
        let (url, reader) = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            Self::parse_stream(stderr),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Tunnel startup timed out after 30 seconds"))??;

        tokio::spawn(async move {
            Self::monitor_stderr(reader).await;
        });

        spinner.finish_with_message("Tunnel established");

        Ok(Self {
            process: child,
            url,
        })
    }

    async fn parse_stream(
        stream: impl tokio::io::AsyncRead + Unpin,
    ) -> Result<(String, BufReader<impl tokio::io::AsyncRead + Unpin>)> {
        let reader = BufReader::new(stream);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            //println!("[cloudflared] {}", line); // Log all output
            if line.contains("trycloudflare.com") {
                if let Some(url) = Self::extract_url(&line) {
                    // Return URL and the reader to continue monitoring
                    return Ok((url, lines.into_inner()));
                }
            }
        }
        bail!("Tunnel started but no URL was found in cloudflared output");
    }

    async fn monitor_stderr(stream: BufReader<impl tokio::io::AsyncRead + Unpin>) {
        let mut lines = stream.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // Only log errors - keep the stream alive without spam
            if line.contains("ERR") || line.contains("error") || line.contains("failed") {
                output::error(&format!("[cloudflared] {}", line));
            }
            // Silently consume all other output to keep tunnel alive
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    async fn is_installed() -> bool {
        Command::new("which")
            .arg("cloudflared")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await // ← Add this
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn extract_url(line: &str) -> Option<String> {
        let re = Regex::new(r"https://[a-z0-9-]+\.trycloudflare\.com").ok()?;
        re.find(line).map(|m| m.as_str().to_string())
    }
}

impl Drop for CloudflareTunnel {
    fn drop(&mut self) {
        let _ = self.process.start_kill();
    }
}
