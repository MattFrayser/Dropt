//! Assembles files from out-of-order chunks with collision-safe naming and RAII cleanup.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::SeekFrom;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::common::config::CollisionPolicy;

/// Finds an available path by appending ` (N)` suffix if the target already exists.
/// Returns the original path unchanged if no collision.
/// Does not create any files — pure path resolution.
///
/// Note: Small TOCTOU window exists between this call and file creation.
/// For a local file transfer tool this risk is acceptable.
pub async fn find_available_path(mut path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }

    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unnamed")
        .to_string();

    let parent_dir = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let (base_name, all_extensions) = if let Some(dot_pos) = filename.find('.') {
        if dot_pos == 0 {
            (filename, String::new())
        } else {
            (
                filename[..dot_pos].to_string(),
                filename[dot_pos..].to_string(),
            )
        }
    } else {
        (filename, String::new())
    };

    let (name_without_number, mut counter) = if let Some(paren_pos) = base_name.rfind(" (") {
        if base_name.ends_with(')') {
            let number_str = &base_name[paren_pos + 2..base_name.len() - 1];
            if let Ok(num) = number_str.parse::<u32>() {
                (base_name[..paren_pos].to_string(), num + 1)
            } else {
                (base_name, 1)
            }
        } else {
            (base_name, 1)
        }
    } else {
        (base_name, 1)
    };

    loop {
        let new_name = format!("{name_without_number} ({counter}){all_extensions}");
        path = parent_dir.join(&new_name);
        if !path.exists() {
            return path;
        }
        counter += 1;
    }
}

/// Manages file assembly from chunks arriving in any order.
///
/// RAII: `disarmed=false` → Drop deletes file. Set `true` after finalization.
pub struct ChunkStorage {
    file: File,
    path: PathBuf,
    chunks_received: HashSet<usize>,
    expected_chunks: usize,
    expected_size: u64,
    disarmed: bool,
    chunk_size: u64,
}

impl ChunkStorage {
    /// Create storage for one file, resolving name collisions safely.
    pub async fn new(dest_path: PathBuf, file_size: u64, chunk_size: u64) -> Result<Self> {
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let final_path = find_available_path(dest_path).await;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&final_path)
            .await
            .context(format!(
                "Failed to create storage file: {}",
                final_path.display()
            ))?;

        file.set_len(file_size).await?;

        let expected_chunks = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(chunk_size) as usize
        };

        Ok(Self {
            file,
            path: final_path,
            chunks_received: HashSet::new(),
            expected_chunks,
            expected_size: file_size,
            disarmed: false,
            chunk_size,
        })
    }

    /// Return whether this chunk index is already stored.
    pub fn has_chunk(&self, chunk_index: usize) -> bool {
        self.chunks_received.contains(&chunk_index)
    }

    /// Return the output path used by this storage session.
    pub fn get_path(&self) -> &PathBuf {
        &self.path
    }

    /// Return number of unique chunks written so far.
    pub fn chunk_count(&self) -> usize {
        self.chunks_received.len()
    }

    /// Writes chunk at positioned offset. Validates size to prevent overflow attacks.
    ///
    /// # Errors
    ///
    /// - `chunk_index >= expected_chunks`: Invalid chunk index
    /// - Size mismatch: Chunk too large or wrong size for position
    /// - I/O errors: Seek or write failures
    pub async fn store_chunk(&mut self, chunk_index: usize, decrypted_data: &[u8]) -> Result<()> {
        if chunk_index >= self.expected_chunks {
            return Err(anyhow::anyhow!(
                "Invalid chunk index {} (expected 0-{})",
                chunk_index,
                self.expected_chunks - 1
            ));
        }

        // Validate chunk size
        let is_last = chunk_index == self.expected_chunks - 1;
        let expected_size = if is_last {
            // Last chunk: remainder or full chunk if file_size is exact multiple
            let remainder = self.expected_size % self.chunk_size;
            if remainder == 0 {
                self.chunk_size
            } else {
                remainder
            }
        } else {
            // Non-last chunks must be exactly chunk_size
            self.chunk_size
        };

        if decrypted_data.len() as u64 != expected_size {
            return Err(anyhow::anyhow!(
                "Chunk {} size mismatch: got {} bytes, expected {} bytes",
                chunk_index,
                decrypted_data.len(),
                expected_size
            ));
        }

        // Seek positon
        let offset = (chunk_index as u64) * self.chunk_size;
        self.file.seek(SeekFrom::Start(offset)).await?;

        self.file.write_all(decrypted_data).await.context(format!(
            "Failed to write chunk {chunk_index} at offset {offset}"
        ))?;

        self.chunks_received.insert(chunk_index);

        Ok(())
    }

    /// Remove incomplete output and disarm drop cleanup.
    pub async fn cleanup(&mut self) -> Result<()> {
        if !self.disarmed {
            self.disarmed = true; // prevent Drop
            tokio::fs::remove_file(&self.path)
                .await
                .context("Failed to remove incomplete file")?;
        }

        Ok(())
    }

    /// Verify completeness, hash output, and keep finalized file.
    ///
    /// # Returns
    ///
    /// Hex-encoded SHA-256 hash of the complete file for client verification.
    ///
    /// # Errors
    ///
    /// - Missing chunks: Not all expected chunks received
    /// - I/O errors: Cannot read file for hashing
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

        // Validate actual file size matches expected
        let actual_size = self.file.metadata().await?.len();
        if actual_size != self.expected_size {
            return Err(anyhow::anyhow!(
                "File size mismatch: {} bytes on disk, expected {} bytes",
                actual_size,
                self.expected_size
            ));
        }

        // Calc final hash for integrity of operation
        self.file.seek(SeekFrom::Start(0)).await?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB

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

/// RAII cleanup guard: Deletes incomplete files unless disarmed by finalization.
/// # Drop Behavior
///
/// - `disarmed = false`: Delete file (incomplete transfer, error, or Ctrl+C)
/// - `disarmed = true`: Keep file (successful finalization)
///
/// Drop is synchronous, but cleanup must complete. Uses `block_in_place` to
/// avoid blocking the Tokio runtime's thread pool
impl Drop for ChunkStorage {
    fn drop(&mut self) {
        if !self.disarmed {
            if let Err(e) = std::fs::remove_file(&self.path) {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "Failed to clean up temporary file"
                );
            }
        }
    }
}

/// Ensure destination filesystem has enough free space.
/// Returns Ok if sufficient space available, Err otherwise
pub fn check_disk_space(destination: &std::path::Path, bytes: u64) -> Result<()> {
    use sysinfo::Disks;

    let disks = Disks::new_with_refreshed_list();

    // Convert relative paths to absolute before matching against mount points
    let abs_destination =
        std::fs::canonicalize(destination).unwrap_or_else(|_| destination.to_path_buf());
    let dest_str = abs_destination.to_string_lossy();

    let mut available: Option<u64> = None;
    let mut longest_match_len = 0;
    let required_bytes = bytes + 1024 * 1024 * 1024; // 1GB buffer

    // Find disk with longest matching mount point (most specific)
    for disk in disks.list() {
        let mount_point = disk.mount_point().to_string_lossy();
        let mount_len = mount_point.len();
        if dest_str.starts_with(mount_point.as_ref()) && mount_len > longest_match_len {
            available = Some(disk.available_space());
            longest_match_len = mount_len;
        }
    }

    match available {
        Some(avail) if avail >= required_bytes => Ok(()),
        Some(avail) => Err(anyhow::anyhow!(
            "Insufficient disk space: {} GB available, {} GB required",
            avail / (1024 * 1024 * 1024),
            required_bytes / (1024 * 1024 * 1024)
        )),
        None => Err(anyhow::anyhow!(
            "Cannot determine available disk space for {destination:?}."
        )),
    }
}

pub enum CollisionResolution {
    Use(PathBuf),
    Overwrote(PathBuf),
    Skip,
}

/// Resolves a file path against an existing file according to the collision policy.
///
/// # Errors
///
/// Returns an error if `Overwrite` fails to remove the existing file.
pub async fn resolve_collision(
    policy: CollisionPolicy,
    path: PathBuf,
) -> Result<CollisionResolution> {
    match policy {
        CollisionPolicy::Suffix => Ok(CollisionResolution::Use(path)),
        CollisionPolicy::Overwrite => {
            if path.exists() {
                tokio::fs::remove_file(&path).await?;
            }
            Ok(CollisionResolution::Overwrote(path))
        }
        CollisionPolicy::Skip => {
            if path.exists() {
                Ok(CollisionResolution::Skip)
            } else {
                Ok(CollisionResolution::Use(path))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::CollisionPolicy;
    use tempfile::TempDir;

    #[tokio::test]
    async fn find_available_path_returns_original_when_no_collision() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        let result = find_available_path(path.clone()).await;
        assert_eq!(result, path);
    }

    #[tokio::test]
    async fn find_available_path_appends_suffix_on_collision() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        tokio::fs::write(&path, b"existing").await.unwrap();
        let result = find_available_path(path.clone()).await;
        assert_eq!(result, dir.path().join("file (1).txt"));
    }

    #[tokio::test]
    async fn find_available_path_increments_existing_counter() {
        let dir = TempDir::new().unwrap();
        let path_1 = dir.path().join("file (1).txt");
        tokio::fs::write(&path_1, b"existing").await.unwrap();
        let result = find_available_path(path_1).await;
        assert_eq!(result, dir.path().join("file (2).txt"));
    }

    #[tokio::test]
    async fn find_available_path_handles_hidden_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".gitignore");
        tokio::fs::write(&path, b"existing").await.unwrap();
        let result = find_available_path(path.clone()).await;
        assert_eq!(result, dir.path().join(".gitignore (1)"));
    }

    #[tokio::test]
    async fn suffix_policy_returns_use_regardless_of_existence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        let result = resolve_collision(CollisionPolicy::Suffix, path)
            .await
            .unwrap();
        assert!(matches!(result, CollisionResolution::Use(_)));
    }

    #[tokio::test]
    async fn skip_policy_returns_skip_when_file_exists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        tokio::fs::write(&path, b"existing").await.unwrap();
        let result = resolve_collision(CollisionPolicy::Skip, path)
            .await
            .unwrap();
        assert!(matches!(result, CollisionResolution::Skip));
    }

    #[tokio::test]
    async fn skip_policy_returns_use_when_no_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        let result = resolve_collision(CollisionPolicy::Skip, path)
            .await
            .unwrap();
        assert!(matches!(result, CollisionResolution::Use(_)));
    }
}
