//! Provider agnostic tunnel behavior

use super::cloudflare::CloudflareTunnel;
use super::tailscale::TailscaleTunnel;
use crate::common::config::Transport;

use anyhow::Result;

pub enum Tunnel {
    Cloudflare(CloudflareTunnel),
    Tailscale(TailscaleTunnel),
}

impl Tunnel {
    #[tracing::instrument(fields(transport = ?transport, port))]
    pub async fn start(transport: Transport, port: u16) -> Result<Self> {
        match transport {
            Transport::Local => anyhow::bail!("Local transport does not use tunneling"),
            Transport::Cloudflare => Ok(Self::Cloudflare(CloudflareTunnel::start(port).await?)),
            Transport::Tailscale => Ok(Self::Tailscale(TailscaleTunnel::start(port).await?)),
        }
    }

    pub fn url(&self) -> &str {
        match self {
            Self::Cloudflare(t) => t.url(),
            Self::Tailscale(t) => t.url(),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn shutdown(&mut self) -> Result<()> {
        match self {
            Self::Cloudflare(t) => t.shutdown().await,
            Self::Tailscale(t) => t.shutdown().await,
        }
    }
}
