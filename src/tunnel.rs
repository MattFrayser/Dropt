use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub struct CloudflareTunnel {
    process: Child,
    url: String,
}

impl CloudflareTunnel {
    pub async fn start(local_port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        // check cloudflared installed
        if !Self::is_installed().await {
            return Err("cloudflared not installed.\n 
                Install cloudflared or use --local."
                .into());
        }

        println!("cloudflared installed");

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
            .spawn()?;

        let stderr = child.stderr.take().ok_or("No stderr")?;

        // Parse stream with timeout
        // reader keeps stream alive after url
        let (url, reader) = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            Self::parse_stream(stderr),
        )
        .await
        .map_err(|_| "Tunnel startup timed out.")??;

        println!("{:?}", url);

        tokio::spawn(async move {
            Self::monitor_stderr(reader).await;
        });

        Ok(Self {
            process: child,
            url,
        })
    }

    async fn parse_stream(
        stream: impl tokio::io::AsyncRead + Unpin,
    ) -> Result<(String, BufReader<impl tokio::io::AsyncRead + Unpin>), Box<dyn std::error::Error>>
    {
        let reader = BufReader::new(stream);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            println!("[cloudflared] {}", line); // Log all output
            if line.contains("trycloudflare.com") {
                if let Some(url) = Self::extract_url(&line) {
                    // Return URL and the reader to continue monitoring
                    return Ok((url, lines.into_inner()));
                }
            }
        }

        Err("No tunnel URL found".into())
    }

    async fn monitor_stderr(stream: BufReader<impl tokio::io::AsyncRead + Unpin>) {
        let mut lines = stream.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // Only log errors - keep the stream alive without spam
            if line.contains("ERR") || line.contains("error") || line.contains("failed") {
                eprintln!("[cloudflared] {}", line);
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
        if line.contains("trycloudflare.com") {
            // Find where https:// starts
            if let Some(start) = line.find("https://") {
                let rest = &line[start..];

                // Extract until whitespace or box characters
                let url = rest
                    .split_whitespace()
                    .next()?
                    .trim_end_matches(&[',', '.', ';', '|', '+', '-', ' ', '"', ')', ']'][..]);

                // Verify it's a valid URL
                // Looking for https://random.trycloudflare.com
                if url.starts_with("https://")
                    && url.contains("trycloudflare.com")
                    && !url.contains("api.trycloudflare.com")
                    && !url.contains("/tunnel")
                {
                    // ensure proper ending
                    if let Some(end_idx) = url.find(".trycloudflare.com") {
                        let url_part = &url[..end_idx + ".trycloudflare.com".len()];

                        return Some(url_part.to_string());
                    }
                }
            }
        }

        None
    }
}

impl Drop for CloudflareTunnel {
    fn drop(&mut self) {
        let _ = self.process.start_kill();
    }
}
