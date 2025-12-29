use anyhow::{Context, Result};
use positioned_io::{RandomAccessFile, ReadAt};
use std::fs::File;
use std::path::PathBuf;

pub struct SendFileHandle {
    file: RandomAccessFile,
    path: PathBuf,
    size: u64,
}
/// File handle using positioned reads for concurrent chunk serving.
impl SendFileHandle {
    pub fn open(path: PathBuf, size: u64) -> Result<Self> {
        let file = File::open(&path).context(format!(
            "Failed to open file for sending: {}",
            path.display()
        ))?;

        // Wrap in RandomAccessFile for optimized positioned reads
        // On Unix: advises OS with FADV_RANDOM
        // On Windows: orders of magnitude faster than direct FileExt
        let file = RandomAccessFile::try_new(file).context("Failed to create RandomAccessFile")?;

        Ok(Self { file, path, size })
    }

    /// Positioned read at offset. Thread-safe (takes `&self` not `&mut self`).
    pub fn read_chunk(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if offset >= self.size {
            anyhow::bail!("Chunk offset {} exceeds file size {}", offset, self.size);
        }

        let mut buffer = vec![0u8; len];

        // RandomAccessFile::read_exact_at is cross-platform and thread-safe
        // Takes &self (not &mut self), safe for concurrent reads
        self.file
            .read_exact_at(offset, &mut buffer)
            .context(format!("Failed to read chunk at offset {}", offset))?;

        Ok(buffer)
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}
