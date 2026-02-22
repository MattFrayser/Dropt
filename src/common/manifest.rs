//! Transfer manifest model and per-file validation.

use super::TransferSettings;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{crypto::types::Nonce, utils::security};

const MAX_CHUNKS_PER_FILE: u64 = (u32::MAX as u64) + 1;

/// Validates that file chunk count fits encryption nonce/counter limits.
pub fn validate_nonce_counter_chunks(
    file_size: u64,
    chunk_size: u64,
    file_label: &str,
) -> Result<()> {
    let total_chunks = file_size.div_ceil(chunk_size);
    if total_chunks > MAX_CHUNKS_PER_FILE {
        anyhow::bail!(
            "File '{file_label}' is too large for secure chunk encryption with current settings. Max supported chunks per file is {MAX_CHUNKS_PER_FILE}. Increase chunk size or split the file."
        );
    }
    Ok(())
}

/// Metadata for a single file during transfer
#[derive(Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub index: usize,
    pub name: String,
    #[serde(skip)]
    pub full_path: PathBuf,
    pub relative_path: String,
    pub size: u64,
    pub nonce: String,
}

/// Contains all files to be transfered & config
#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub files: Vec<FileEntry>,
    pub config: TransferSettings,
}

impl Manifest {
    /// Builds a manifest from input paths and assigns one unique nonce per file.
    pub async fn new(
        file_paths: Vec<PathBuf>,
        base_path: Option<&Path>,
        config: TransferSettings,
    ) -> Result<Self> {
        let mut files = Vec::new();

        // determine common base, no base, use parent
        let base = base_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
            file_paths[0]
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf()
        });

        for (index, path) in file_paths.into_iter().enumerate() {
            let metadata = tokio::fs::metadata(&path)
                .await
                .context(format!("Failed to read metadata for: {}", path.display()))?;

            let relative = path
                .strip_prefix(&base)
                .unwrap_or(path.as_path())
                .to_string_lossy()
                .to_string();

            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unnamed")
                .to_string();

            validate_nonce_counter_chunks(metadata.len(), config.chunk_size, &name)?;

            security::validate_filename(&name).context("Invalid file name")?;

            // Unique nonce for each file
            let nonce = Nonce::new();

            files.push(FileEntry {
                index,
                name,
                size: metadata.len(),
                relative_path: relative,
                nonce: nonce.to_base64(),
                full_path: path,
            });
        }

        Ok(Manifest { files, config })
    }

    /// Calculate total chunks needed for all files in manifest
    pub fn total_chunks(&self, chunk_size: u64) -> u64 {
        self.files.iter().map(|f| f.size.div_ceil(chunk_size)).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_max_u32_counter_space() {
        let max_chunks = (u32::MAX as u64) + 1;
        let file_size = max_chunks * 1024;
        let result = validate_nonce_counter_chunks(file_size, 1024, "max.bin");
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_more_than_u32_counter_space() {
        let file_size = ((u32::MAX as u64) + 2) * 1024;
        let result = validate_nonce_counter_chunks(file_size, 1024, "too-large.bin");
        assert!(result.is_err());
    }
}
