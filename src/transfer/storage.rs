// Storage module
// Provides operations for chunk management
// RAII guard is used for cleanups on Error

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::SeekFrom;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::config::CHUNK_SIZE;

pub struct ChunkStorage {
    file: File,
    path: PathBuf,
    chunks_received: HashSet<usize>,
    disarmed: bool, // false -> delete files on drop
}

impl ChunkStorage {
    pub async fn new(mut dest_path: PathBuf, file_size: u64) -> Result<Self> {
        // Create parent dir
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Break apart file: name, ext, path
        // name and ext are broken apart for naming like test (1).txt if duplicates
        let stem = dest_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unnamed")
            .to_string();

        let extension = dest_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|e| format!(".{}", e))
            .unwrap_or_default();

        let parent_dir = dest_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let mut counter = 1;

        loop {
            // First try open file as new
            let result = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&dest_path)
                .await;

            match result {
                Ok(file) => {
                    file.set_len(file_size).await?;

                    return Ok(Self {
                        file,
                        path: dest_path,
                        chunks_received: HashSet::new(),
                        disarmed: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Catch collision via error
                    let new_name = format!("{} ({}){}", stem, counter, extension);
                    dest_path = parent_dir.join(new_name);
                    counter += 1;
                }
                Err(e) => {
                    // real error
                    return Err(anyhow::Error::new(e).context(format!(
                        "Failed to create storage file: {}",
                        dest_path.display()
                    )));
                }
            };
        }
    }

    //-- Accessors
    pub fn has_chunk(&self, chunk_index: usize) -> bool {
        self.chunks_received.contains(&chunk_index)
    }

    pub fn get_path(&self) -> &PathBuf {
        &self.path
    }

    pub fn chunk_count(&self) -> usize {
        self.chunks_received.len()
    }

    pub async fn store_chunk(&mut self, chunk_index: usize, decrypted_data: &[u8]) -> Result<()> {
        // Seek positon - handles out of order arival
        let offset = (chunk_index as u64) * CHUNK_SIZE;
        self.file.seek(SeekFrom::Start(offset)).await?;

        // Write & mark received
        self.file.write_all(decrypted_data).await.context(format!(
            "Failed to write chunk {} at offset {}",
            chunk_index, offset
        ))?;

        self.chunks_received.insert(chunk_index);

        Ok(())
    }

    // Clean up w/o drop, happy path
    pub async fn cleanup(&mut self) -> Result<()> {
        if !self.disarmed {
            self.disarmed = true; // prevent Drop
            tokio::fs::remove_file(&self.path)
                .await
                .context("Failed to remove incomplete file")?;
        }

        Ok(())
    }

    pub async fn finalize(&mut self) -> Result<String> {
        self.file.flush().await?;

        // Calc final hash for integrity of operation
        // Hash is done at end since chunks may not arrive in order
        self.file.seek(SeekFrom::Start(0)).await?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 16 * 1024]; // 16KB

        loop {
            let n = tokio::io::AsyncReadExt::read(&mut self.file, &mut buffer).await?;
            if n == 0 {
                break;
            }

            hasher.update(&buffer[..n]);
        }

        self.disarmed = true; // mark success

        let hash = hex::encode(hasher.finalize());
        Ok(hash)
    }
}

// auto runs on out of scope
// if disarmed is false file is deleted
impl Drop for ChunkStorage {
    fn drop(&mut self) {
        if !self.disarmed {
            // Using drop as guarnteed way to remove files
            // Drop is sync so must block when to clean up
            // File deletion is fast so will not block long
            if let Err(e) = std::fs::remove_file(&self.path) {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "Failed to clean up temporary file"
                );
            } else {
                tracing::debug!("Cleaned up incomplete transfer file");
            }
        }
    }
}
