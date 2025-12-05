use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{crypto::types::Nonce, transfer::security};

// Metadata for single file
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

// List of all files
#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub async fn new(file_paths: Vec<PathBuf>, base_path: Option<&Path>) -> Result<Self> {
        let mut files = Vec::new();

        // determine common base, no base, use parent
        let base =
            base_path.unwrap_or_else(|| file_paths[0].parent().unwrap_or_else(|| Path::new("")));

        for (index, path) in file_paths.iter().enumerate() {
            let metadata = tokio::fs::metadata(path)
                .await
                .context(format!("Failed to read metadata for: {}", path.display()))?;

            let relative = path
                .strip_prefix(base)
                .unwrap_or(path.as_path())
                .to_string_lossy()
                .to_string();

            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unnamed")
                .to_string();

            security::validate_filename(&name).context("Invalid fine name")?;

            // Unique nonce for each file
            let nonce = Nonce::new();

            files.push(FileEntry {
                index,
                name,
                size: metadata.len(),
                relative_path: relative,
                nonce: nonce.to_base64(),
                full_path: path.clone(),
            });
        }

        Ok(Manifest { files })
    }

    /// Calculate total chunks needed for all files in manifest
    pub fn total_chunks(&self) -> u64 {
        self.files
            .iter()
            .map(|f| (f.size + crate::config::CHUNK_SIZE - 1) / crate::config::CHUNK_SIZE)
            .sum()
    }
}
