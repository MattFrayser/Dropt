//! Configuration schema, defaults, and layered loading.
//!
//! Precedence: defaults < config < enviroment < CLI
use anyhow::{Context, Result, ensure};
use directories::ProjectDirs;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_TRANSFER_CHUNK_SIZE_BYTES: u64 = 10 * 1024 * 1024;
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

/*
 *  TUNNEL SETTINGS
 */

/// Transfer tuning parameters shared by all transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
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

/*
 *  TUI SETTINGS
 */

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

/*
 * RECIEVE SPECIFIC SETTINGS
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CollisionPolicy {
    #[default]
    Suffix,
    Overwrite,
    Skip,
}

/*
 * APP CONFIG
 */

/// Fully resolved application configuration after all layers merge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub default_transport: Transport,
    pub zip: bool,
    pub local: LocalSettings,
    pub cloudflare: CloudflareSettings,
    pub tailscale: TailscaleSettings,
    pub tui: TuiSettings,
    pub on_conflict: CollisionPolicy,
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
            transfer.chunk_size <= MAX_TRANSFER_CHUNK_SIZE_BYTES,
            "Invalid config: {name}.chunk_size must be <= {MAX_TRANSFER_CHUNK_SIZE_BYTES}"
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
            zip: false,
            local: LocalSettings::default(),
            cloudflare: CloudflareSettings::default(),
            tailscale: TailscaleSettings::default(),
            tui: TuiSettings::default(),
            on_conflict: CollisionPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Get path to config
pub fn config_path() -> PathBuf {
    ProjectDirs::from("", "", "dropt")
        .map(|p| p.config_dir().join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("dropt.toml"))
}

/// Loads config from defaults/file/env.
pub fn load_config() -> Result<AppConfig> {
    let path = config_path();

    load_config_from_path_and_env_pairs(&path, std::env::vars())
}

fn load_file_and_defaults(path: &Path) -> Result<AppConfig> {
    let config: AppConfig = Figment::new()
        .merge(Serialized::defaults(AppConfig::default()))
        .merge(Toml::file(path))
        .extract()
        .context("Failed to load configuration")?;

    Ok(config)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct EnvOverrides {
    default_transport: Option<Transport>,
    zip: Option<bool>,
    local_port: Option<u16>,
    cloudflare_port: Option<u16>,
    tailscale_port: Option<u16>,
    local_chunk_size: Option<u64>,
    cloudflare_chunk_size: Option<u64>,
    tailscale_chunk_size: Option<u64>,
    local_concurrency: Option<usize>,
    cloudflare_concurrency: Option<usize>,
    tailscale_concurrency: Option<usize>,
    tui_show_qr: Option<bool>,
    tui_show_url: Option<bool>,
    on_conflict: Option<CollisionPolicy>,
}

fn parse_bool(key: &str, value: &str) -> Result<bool> {
    value
        .parse::<bool>()
        .with_context(|| format!("Invalid env value for {key}: expected true or false"))
}

fn parse_u16(key: &str, value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("Invalid env value for {key}: expected u16 integer"))
}

fn parse_u64(key: &str, value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .with_context(|| format!("Invalid env value for {key}: expected u64 integer"))
}

fn parse_usize(key: &str, value: &str) -> Result<usize> {
    value
        .parse::<usize>()
        .with_context(|| format!("Invalid env value for {key}: expected usize integer"))
}

fn parse_transport(key: &str, value: &str) -> Result<Transport> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local" => Ok(Transport::Local),
        "cloudflare" => Ok(Transport::Cloudflare),
        "tailscale" => Ok(Transport::Tailscale),
        _ => anyhow::bail!(
            "Invalid env value for {key}: expected one of local, cloudflare, tailscale"
        ),
    }
}

fn parse_collision_policy(key: &str, value: &str) -> Result<CollisionPolicy> {
    match value.trim().to_ascii_lowercase().as_str() {
        "suffix" => Ok(CollisionPolicy::Suffix),
        "overwrite" => Ok(CollisionPolicy::Overwrite),
        "skip" => Ok(CollisionPolicy::Skip),
        _ => anyhow::bail!("Invalid env value for {key}: expected one of suffix, overwrite, skip"),
    }
}

fn parse_env_overrides<I, K, V>(env_pairs: I) -> Result<EnvOverrides>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut overrides = EnvOverrides::default();

    for (raw_key, raw_value) in env_pairs {
        let key = raw_key.as_ref();
        let value = raw_value.as_ref();

        if !key.starts_with("DROPT_") {
            continue;
        }

        match key {
            "DROPT_DEFAULT_TRANSPORT" => {
                overrides.default_transport = Some(parse_transport(key, value)?);
            }
            "DROPT_ZIP" => {
                overrides.zip = Some(parse_bool(key, value)?);
            }
            "DROPT_LOCAL_PORT" => {
                overrides.local_port = Some(parse_u16(key, value)?);
            }
            "DROPT_CLOUDFLARE_PORT" => {
                overrides.cloudflare_port = Some(parse_u16(key, value)?);
            }
            "DROPT_TAILSCALE_PORT" => {
                overrides.tailscale_port = Some(parse_u16(key, value)?);
            }
            "DROPT_LOCAL_CHUNK_SIZE" => {
                overrides.local_chunk_size = Some(parse_u64(key, value)?);
            }
            "DROPT_CLOUDFLARE_CHUNK_SIZE" => {
                overrides.cloudflare_chunk_size = Some(parse_u64(key, value)?);
            }
            "DROPT_TAILSCALE_CHUNK_SIZE" => {
                overrides.tailscale_chunk_size = Some(parse_u64(key, value)?);
            }
            "DROPT_LOCAL_CONCURRENCY" => {
                overrides.local_concurrency = Some(parse_usize(key, value)?);
            }
            "DROPT_CLOUDFLARE_CONCURRENCY" => {
                overrides.cloudflare_concurrency = Some(parse_usize(key, value)?);
            }
            "DROPT_TAILSCALE_CONCURRENCY" => {
                overrides.tailscale_concurrency = Some(parse_usize(key, value)?);
            }
            "DROPT_TUI_SHOW_QR" => {
                overrides.tui_show_qr = Some(parse_bool(key, value)?);
            }
            "DROPT_TUI_SHOW_URL" => {
                overrides.tui_show_url = Some(parse_bool(key, value)?);
            }
            "DROPT_ON_CONFLICT" => {
                overrides.on_conflict = Some(parse_collision_policy(key, value)?);
            }
            _ => {}
        }
    }

    Ok(overrides)
}

fn apply_env_overrides(config: &mut AppConfig, overrides: EnvOverrides) {
    if let Some(transport) = overrides.default_transport {
        config.default_transport = transport;
    }
    if let Some(zip) = overrides.zip {
        config.zip = zip;
    }
    if let Some(port) = overrides.local_port {
        config.local.port = port;
    }
    if let Some(port) = overrides.cloudflare_port {
        config.cloudflare.port = port;
    }
    if let Some(port) = overrides.tailscale_port {
        config.tailscale.port = port;
    }
    if let Some(chunk_size) = overrides.local_chunk_size {
        config.local.transfer.chunk_size = chunk_size;
    }
    if let Some(chunk_size) = overrides.cloudflare_chunk_size {
        config.cloudflare.transfer.chunk_size = chunk_size;
    }
    if let Some(chunk_size) = overrides.tailscale_chunk_size {
        config.tailscale.transfer.chunk_size = chunk_size;
    }
    if let Some(concurrency) = overrides.local_concurrency {
        config.local.transfer.concurrency = concurrency;
    }
    if let Some(concurrency) = overrides.cloudflare_concurrency {
        config.cloudflare.transfer.concurrency = concurrency;
    }
    if let Some(concurrency) = overrides.tailscale_concurrency {
        config.tailscale.transfer.concurrency = concurrency;
    }
    if let Some(show_qr) = overrides.tui_show_qr {
        config.tui.show_qr = show_qr;
    }
    if let Some(show_url) = overrides.tui_show_url {
        config.tui.show_url = show_url;
    }
    if let Some(on_conflict) = overrides.on_conflict {
        config.on_conflict = on_conflict;
    }
}

#[doc(hidden)]
pub fn load_config_from_path_and_env_pairs<I, K, V>(path: &Path, env_pairs: I) -> Result<AppConfig>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut config = load_file_and_defaults(path)?;
    let env_overrides = parse_env_overrides(env_pairs)?;
    apply_env_overrides(&mut config, env_overrides);

    config.validate()?;

    Ok(config)
}

/// Applies runtime overrides to a loaded config.
pub fn apply_overrides(mut config: AppConfig, overrides: &ConfigOverrides) -> AppConfig {
    if let Some(port) = overrides.port {
        let transport = overrides.transport.unwrap_or(config.default_transport);
        config.set_port(transport, port);
    }

    config
}
