//! Tailscale funnel lifecycle management.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tailscale_localapi::LocalApi;
use thiserror::Error;
use tokio::process::Command;

/// Active Tailscale tunnel context.
pub struct TailscaleTunnel {
    url: String,
    port: u16,
    owns_funnel: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
enum TailscaleError {
    #[error("permission denied")]
    PermissionDenied,
    #[error("funnel already in use")]
    AlreadyInUse,
    #[error("tailscale binary not found")]
    BinaryMissing,
    #[error("tailscale daemon not available")]
    DaemonUnavailable,
    #[error("unknown tailscale error: {0}")]
    Unknown(String),
}

struct CommandOutput {
    success: bool,
    stderr: String,
}

#[async_trait]
trait TailscaleBackend {
    async fn hostname(&self) -> Result<String, TailscaleError>;
    async fn run(&self, args: &[&str]) -> Result<CommandOutput, TailscaleError>;
}

struct SystemTailscaleBackend;

#[async_trait]
impl TailscaleBackend for SystemTailscaleBackend {
    async fn hostname(&self) -> Result<String, TailscaleError> {
        let client = LocalApi::new_with_socket_path("/var/run/tailscale/tailscaled.sock");
        let status = client
            .status()
            .await
            .map_err(|_| TailscaleError::DaemonUnavailable)?;
        Ok(status.self_status.dnsname.trim_end_matches('.').to_string())
    }

    async fn run(&self, args: &[&str]) -> Result<CommandOutput, TailscaleError> {
        let output = Command::new("tailscale")
            .args(args)
            .output()
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    TailscaleError::BinaryMissing
                } else {
                    TailscaleError::Unknown(e.to_string())
                }
            })?;

        Ok(CommandOutput {
            success: output.status.success(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

fn classify_start_failure(stderr: &str) -> TailscaleError {
    let normalized = stderr.to_lowercase();

    if normalized.contains("access denied")
        || normalized.contains("serve config denied")
        || normalized.contains("operator")
    {
        return TailscaleError::PermissionDenied;
    }

    if normalized.contains("already listening")
        || normalized.contains("address already in use")
        || normalized.contains("already in use")
    {
        return TailscaleError::AlreadyInUse;
    }

    TailscaleError::Unknown(stderr.trim().to_string())
}

fn is_benign_off_failure(stderr: &str) -> bool {
    let normalized = stderr.to_lowercase();
    normalized.contains("not found")
        || normalized.contains("nothing")
        || normalized.contains("already")
        || normalized.contains("no serve config")
        || normalized.contains("handler does not exist")
}

fn map_start_error(err: TailscaleError) -> anyhow::Error {
    match err {
        TailscaleError::PermissionDenied => anyhow!(
            "Tailscale funnel requires operator permissions.\n\n\
             One-time setup - Run this command:\n\
             sudo tailscale set --operator=$USER\n\n\
             Then try again.\n\n\
             Or use a different tunnel provider."
        ),
        TailscaleError::AlreadyInUse => anyhow!(
            "Tailscale funnel is already in use on this port.\n\n\
             Reusing existing funnel for this transfer session."
        ),
        TailscaleError::BinaryMissing => anyhow!(
            "Failed to start Tailscale funnel.\n\n\
             Make sure Tailscale is installed and running.\n\
             Install: https://tailscale.com/download\n\n\
             Or use a different tunnel provider."
        ),
        TailscaleError::DaemonUnavailable => anyhow!(
            "Failed to connect to Tailscale.\n\n\
             Make sure Tailscale is installed and running:\n\
             Install: https://tailscale.com/download\n\
             Then run: sudo tailscale up\n\n\
             Or use a different tunnel provider."
        ),
        TailscaleError::Unknown(msg) => anyhow!(
            "Failed to start Tailscale funnel: {}\n\n\
             Or use a different tunnel provider.",
            msg
        ),
    }
}

/// Start tailscale tunnel
/// Tailscale status is checked via tailscale_localapi crate
/// Tailscale funnel is started as background task since crate does not yet support funnels
impl TailscaleTunnel {
    #[tracing::instrument(fields(port))]
    pub async fn start(port: u16) -> Result<Self> {
        let backend = SystemTailscaleBackend;
        Self::start_with_backend(&backend, port)
            .await
            .map_err(map_start_error)
    }

    async fn start_with_backend<B: TailscaleBackend + Sync>(
        backend: &B,
        port: u16,
    ) -> std::result::Result<Self, TailscaleError> {
        let hostname = backend.hostname().await?;

        let port_arg = port.to_string();
        let output = backend.run(&["funnel", "--bg", &port_arg]).await?;

        let owns_funnel = if output.success {
            true
        } else {
            match classify_start_failure(&output.stderr) {
                TailscaleError::AlreadyInUse => {
                    tracing::warn!(
                        "Port {} already has a Tailscale funnel. Using existing funnel.",
                        port
                    );
                    false
                }
                err => return Err(err),
            }
        };

        Ok(Self {
            url: format!("https://{}", hostname),
            port,
            owns_funnel,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Shutdown funnel only if we started it
    /// If another service was already using the port, we don't clean it up
    pub async fn shutdown(&mut self) -> Result<()> {
        let backend = SystemTailscaleBackend;
        self.shutdown_with_backend(&backend).await
    }

    async fn shutdown_with_backend<B: TailscaleBackend + Sync>(
        &mut self,
        backend: &B,
    ) -> Result<()> {
        if self.owns_funnel {
            self.off_funnel(backend).await?;
        } else {
            tracing::debug!(
                "Skipping funnel cleanup - port {} owned by another service",
                self.port
            );
        }
        Ok(())
    }

    /// Disable only this process-owned funnel mapping.
    async fn off_funnel<B: TailscaleBackend + Sync>(&self, backend: &B) -> Result<()> {
        let port_arg = self.port.to_string();
        let output = backend
            .run(&["funnel", &format!("--https={}", port_arg), "off"])
            .await
            .context("Failed to disable Tailscale funnel")?;

        if !output.success {
            if is_benign_off_failure(&output.stderr) {
                tracing::warn!(
                    "Scoped funnel cleanup returned non-fatal response: {}",
                    output.stderr.trim()
                );
                return Ok(());
            }
            return Err(anyhow!(
                "Failed to disable scoped Tailscale funnel: {}",
                output.stderr.trim()
            ));
        } else {
            tracing::debug!("Tailscale funnel cleaned up successfully");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockBackend {
        hostname: String,
        responses: Arc<Mutex<VecDeque<Result<CommandOutput, TailscaleError>>>>,
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl MockBackend {
        fn new(hostname: &str, responses: Vec<Result<CommandOutput, TailscaleError>>) -> Self {
            Self {
                hostname: hostname.to_string(),
                responses: Arc::new(Mutex::new(VecDeque::from(responses))),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TailscaleBackend for MockBackend {
        async fn hostname(&self) -> Result<String, TailscaleError> {
            Ok(self.hostname.clone())
        }

        async fn run(&self, args: &[&str]) -> Result<CommandOutput, TailscaleError> {
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|a| a.to_string()).collect());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock response missing")
        }
    }

    #[tokio::test]
    async fn permission_denied_is_typed() {
        let backend = MockBackend::new(
            "host.test.ts.net",
            vec![Ok(CommandOutput {
                success: false,
                stderr: "Access denied: serve config denied".to_string(),
            })],
        );
        let result = TailscaleTunnel::start_with_backend(&backend, 8443).await;
        assert!(matches!(result, Err(TailscaleError::PermissionDenied)));
    }

    #[tokio::test]
    async fn existing_funnel_reuse_does_not_own_resource() {
        let backend = MockBackend::new(
            "host.test.ts.net",
            vec![Ok(CommandOutput {
                success: false,
                stderr: "already listening on 8443".to_string(),
            })],
        );

        let tunnel = TailscaleTunnel::start_with_backend(&backend, 8443)
            .await
            .expect("reusing existing funnel should succeed");

        assert!(!tunnel.owns_funnel);
    }

    #[tokio::test]
    async fn owned_cleanup_uses_scoped_off() {
        let backend = MockBackend::new(
            "host.test.ts.net",
            vec![
                Ok(CommandOutput {
                    success: true,
                    stderr: String::new(),
                }),
                Ok(CommandOutput {
                    success: true,
                    stderr: String::new(),
                }),
            ],
        );

        let mut tunnel = TailscaleTunnel::start_with_backend(&backend, 443)
            .await
            .expect("start should succeed");

        tunnel
            .shutdown_with_backend(&backend)
            .await
            .expect("cleanup should succeed");

        let calls = backend.calls();
        assert_eq!(calls[0], vec!["funnel", "--bg", "443"]);
        assert_eq!(calls[1], vec!["funnel", "--https=443", "off"]);
    }

    #[tokio::test]
    async fn reuse_path_skips_cleanup_command() {
        let backend = MockBackend::new(
            "host.test.ts.net",
            vec![Ok(CommandOutput {
                success: false,
                stderr: "address already in use".to_string(),
            })],
        );

        let mut tunnel = TailscaleTunnel::start_with_backend(&backend, 8443)
            .await
            .expect("reusing existing funnel should succeed");

        tunnel
            .shutdown_with_backend(&backend)
            .await
            .expect("cleanup should be skipped");

        let calls = backend.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], vec!["funnel", "--bg", "8443"]);
    }

    #[test]
    fn binary_missing_is_typed() {
        let err = TailscaleError::BinaryMissing;
        assert!(matches!(err, TailscaleError::BinaryMissing));
    }

    #[test]
    fn handler_does_not_exist_is_benign_off_failure() {
        assert!(is_benign_off_failure(
            "error: failed to remove web serve: handler does not exist"
        ));
    }
}
