//! Configuration schema, defaults, and layered loading.
//!
//! Precedence: defaults < config < enviroment < CLI
use anyhow::{ensure, Context, Result};
use clap::{Args, ValueEnum};
use directories::ProjectDirs;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_CHUNK_SIZE: u64 = 64 * 1024 * 1024;
const MAX_CONCURRENCY: usize = 256;

const LOCAL_TRANSFER: TransferSettings = TransferSettings {
    chunk_size: 10 * 1024 * 1024,
    concurrency: 8,
};

const CLOUDFLARE_TRANSFER: TransferSettings = TransferSettings {
    chunk_size: 1024 * 1024,
    concurrency: 2,
};

const TAILSCALE_TRANSFER: TransferSettings = TransferSettings {
    chunk_size: 2 * 1024 * 1024,
    concurrency: 4,
};

pub fn config_path() -> PathBuf {
    ProjectDirs::from("", "", "archdrop")
        .map(|p| p.config_dir().join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("archdrop.toml"))
}

/// Transfer tuning parameters shared by all transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Local,
    Cloudflare,
    Tailscale,
}

/// Transfer tuning parameters shared by all transports.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TransferSettings {
    /// Chunk size in bytes
    pub chunk_size: u64,
    /// Max concurrent chunks per transfer
    pub concurrency: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSettings {
    pub port: u16,
    #[serde(flatten)]
    pub transfer: TransferSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareSettings {
    pub port: u16,
    #[serde(flatten)]
    pub transfer: TransferSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleSettings {
    pub port: u16,
    #[serde(flatten)]
    pub transfer: TransferSettings,
}

impl Default for LocalSettings {
    fn default() -> Self {
        Self {
            port: 0,
            transfer: LOCAL_TRANSFER,
        }
    }
}

impl Default for CloudflareSettings {
    fn default() -> Self {
        Self {
            port: 0,
            transfer: CLOUDFLARE_TRANSFER,
        }
    }
}

impl Default for TailscaleSettings {
    fn default() -> Self {
        Self {
            port: 0,
            transfer: TAILSCALE_TRANSFER,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TuiSettings {
    pub show_qr: bool,
    pub show_url: bool,
}

impl Default for TuiSettings {
    fn default() -> Self {
        Self {
            show_qr: true,
            show_url: true,
        }
    }
}

/// Fully resolved application configuration after all layers merge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub default_transport: Transport,
    pub local: LocalSettings,
    pub cloudflare: CloudflareSettings,
    pub tailscale: TailscaleSettings,
    pub tui: TuiSettings,
}

impl AppConfig {
    /// Returns transfer settings for the selected transport.
    pub fn transfer_settings(&self, transport: Transport) -> TransferSettings {
        match transport {
            Transport::Local => self.local.transfer,
            Transport::Cloudflare => self.cloudflare.transfer,
            Transport::Tailscale => self.tailscale.transfer,
        }
    }

    /// Returns configured listen port for the selected transport.
    pub fn port(&self, transport: Transport) -> u16 {
        match transport {
            Transport::Local => self.local.port,
            Transport::Cloudflare => self.cloudflare.port,
            Transport::Tailscale => self.tailscale.port,
        }
    }

    /// Validates transport transfer bounds and rejects unsafe values.
    pub fn validate(&self) -> Result<()> {
        Self::validate_transfer("local", self.local.transfer)?;
        Self::validate_transfer("cloudflare", self.cloudflare.transfer)?;
        Self::validate_transfer("tailscale", self.tailscale.transfer)?;
        Ok(())
    }

    fn set_port(&mut self, transport: Transport, port: u16) {
        match transport {
            Transport::Local => self.local.port = port,
            Transport::Cloudflare => self.cloudflare.port = port,
            Transport::Tailscale => self.tailscale.port = port,
        }
    }

    fn validate_transfer(name: &str, transfer: TransferSettings) -> Result<()> {
        ensure!(
            transfer.chunk_size > 0,
            "Invalid config: {name}.chunk_size must be > 0"
        );
        ensure!(
            transfer.chunk_size <= MAX_CHUNK_SIZE,
            "Invalid config: {name}.chunk_size must be <= {MAX_CHUNK_SIZE}"
        );
        ensure!(
            transfer.concurrency >= 1,
            "Invalid config: {name}.concurrency must be >= 1"
        );
        ensure!(
            transfer.concurrency <= MAX_CONCURRENCY,
            "Invalid config: {name}.concurrency must be <= {MAX_CONCURRENCY}"
        );
        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_transport: Transport::Local,
            local: LocalSettings::default(),
            cloudflare: CloudflareSettings::default(),
            tailscale: TailscaleSettings::default(),
            tui: TuiSettings::default(),
        }
    }
}

#[derive(Args, Debug, Clone, Default, Serialize)]
pub struct CliArgs {
    /// Transport method (overrides config default)
    #[arg(long, value_enum)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<Transport>,

    /// Port override for the selected/default transport (0 = auto-assign)
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Loads config from defaults/file/env, then applies overrides.
pub fn load_config(cli_args: &CliArgs) -> Result<AppConfig> {
    let path = config_path();

    let mut config: AppConfig = Figment::new()
        .merge(Serialized::defaults(AppConfig::default()))
        .merge(Toml::file(&path))
        .merge(Env::prefixed("ARCHDROP_").split("_"))
        .extract()
        .context("Failed to load configuration")?;

    // CLI overrides apply only to selected transport.
    if let Some(port) = cli_args.port {
        let transport = cli_args.via.unwrap_or(config.default_transport);
        config.set_port(transport, port);
    }

    config.validate()?;

    Ok(config)
}
