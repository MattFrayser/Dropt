//! File I/O helpers for safe config writes.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Atomically replace a config file with new contents.
pub(super) fn atomic_write(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory {}", parent.display()))?;
    }

    let tmp_path = temp_path_for(path);
    fs::write(&tmp_path, contents)
        .with_context(|| format!("Failed to write temporary file {}", tmp_path.display()))?;

    let file = fs::OpenOptions::new()
        .write(true)
        .open(&tmp_path)
        .with_context(|| format!("Failed to reopen temporary file {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to sync temporary file {}", tmp_path.display()))?;

    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to replace config file {} from {}",
            path.display(),
            tmp_path.display()
        )
    })?;

    Ok(())
}

/// Build a unique temp path next to the target config file.
pub(super) fn temp_path_for(path: &Path) -> PathBuf {
    let base_name = path
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or("config.toml");
    let tmp_name = format!(".{base_name}.{}.tmp", Uuid::new_v4());
    path.with_file_name(tmp_name)
}
