//! CLI handlers for config subcommands.

mod edit;
mod io;
mod reset;
mod show;

use crate::common::config::{AppConfig, config_path};
use anyhow::{Context, Result};

fn defaults_toml() -> Result<String> {
    toml::to_string_pretty(&AppConfig::default()).context("Failed to serialize default config")
}

/// Print resolved config file path.
pub fn run_config_path() -> Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    show::path_config_with_writer(&config_path(), &mut output)
}

/// Print config file contents or default-config guidance when missing.
pub fn run_config_show() -> Result<()> {
    let path = config_path();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let stderr = std::io::stderr();
    let mut err_output = stderr.lock();
    show::show_config_with_io(&path, &mut output, &mut err_output)
}

/// Open config in `$EDITOR`, validate, and save.
pub fn run_config_edit(no_retry: bool) -> Result<bool> {
    edit::edit_config(&config_path(), no_retry)
}

/// Reset config to defaults (with confirmation).
pub fn run_config_reset(yes: bool) -> Result<bool> {
    reset::reset_config(&config_path(), yes)
}
