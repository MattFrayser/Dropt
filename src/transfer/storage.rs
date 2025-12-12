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
    expected_chunks: usize, // Total expected chunks for validation
    disarmed: bool,         // false -> delete files on drop
}

impl ChunkStorage {
    pub async fn new(mut dest_path: PathBuf, file_size: u64) -> Result<Self> {
        // Create parent dir
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Break apart file: name, ext, path
        // Handle collision numbering properly:
        // - "test.txt" -> "test (1).txt" -> "test (2).txt"

        let filename = dest_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unnamed")
            .to_string();

        let parent_dir = dest_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        // Find the first '.' to split filename from all extensions
        let (base_name, all_extensions) = if let Some(dot_pos) = filename.find('.') {
            (
                filename[..dot_pos].to_string(),
                filename[dot_pos..].to_string(),
            )
        } else {
            (filename.clone(), String::new())
        };

        // Check if base_name ends with " (N)" pattern and extract N
        let (name_without_number, mut counter) = if let Some(paren_pos) = base_name.rfind(" (") {
            if base_name.ends_with(')') {
                let number_str = &base_name[paren_pos + 2..base_name.len() - 1];
                if let Ok(num) = number_str.parse::<u32>() {
                    // Found existing number, increment from there
                    (base_name[..paren_pos].to_string(), num + 1)
                } else {
                    // Has " (" but not a valid number
                    (base_name.clone(), 1)
                }
            } else {
                (base_name.clone(), 1)
            }
        } else {
            // No existing number
            (base_name.clone(), 1)
        };

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

                    // Calculate expected chunks
                    let expected_chunks = if file_size == 0 {
                        0
                    } else {
                        ((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE) as usize
                    };

                    return Ok(Self {
                        file,
                        path: dest_path,
                        chunks_received: HashSet::new(),
                        expected_chunks,
                        disarmed: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Catch collision via error
                    let new_name =
                        format!("{} ({}){}", name_without_number, counter, all_extensions);
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
        // Check for completeness before finalizing
        let received = self.chunk_count();
        if received < self.expected_chunks {
            return Err(anyhow::anyhow!(
                "Incomplete transfer: received {}/{} chunks",
                received,
                self.expected_chunks
            ));
        }

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
