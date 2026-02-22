//! Random-access file reads for concurrent chunk serving.

use anyhow::{Context, Result};
use positioned_io::{RandomAccessFile, ReadAt};
use std::fs::File;
use std::path::Path;

/// Thread-safe random-access handle used by send handlers.
pub struct SendFileHandle {
    file: RandomAccessFile,
    size: u64,
}

impl SendFileHandle {
    /// Open a file handle for chunked reads with expected file size.
    #[tracing::instrument(fields(path = %path.display(), size))]
    pub fn open(path: &Path, size: u64) -> Result<Self> {
        let file = File::open(path).context(format!(
            "Failed to open file for sending: {}",
            path.display()
        ))?;

        // Wrap in RandomAccessFile for optimized positioned reads
        // On Unix: advises OS with FADV_RANDOM
        // On Windows: orders of magnitude faster than direct FileExt
        let file = RandomAccessFile::try_new(file).context("Failed to create RandomAccessFile")?;

        Ok(Self { file, size })
    }

    /// File handle using positioned reads for concurrent chunk serving.
    ///
    /// The buffer must have `capacity() >= len`.
    /// On success, `buffer.len()` is set to `len`.
    pub fn read_chunk(&self, offset: u64, len: usize, buffer: &mut Vec<u8>) -> Result<()> {
        if offset >= self.size {
            anyhow::bail!("Chunk offset {} exceeds file size {}", offset, self.size);
        }

        if buffer.capacity() < len {
            anyhow::bail!(
                "buffer capacity {} < requested len {}",
                buffer.capacity(),
                len
            );
        }

        // SAFETY: read_exact_at either fills all `len` bytes or returns Err,
        // so the buffer is fully initialized on the success path.
        // Caller guarantees capacity >= len (pool buffers are pre-sized).
        unsafe { buffer.set_len(len) };

        self.file
            .read_exact_at(offset, &mut buffer[..])
            .context(format!("Failed to read chunk at offset {offset}"))?;

        Ok(())
    }

    /// Return the expected file size for this handle.
    pub fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::AssertUnwindSafe;

    #[test]
    fn open_accepts_borrowed_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, b"abc").expect("write file");

        let handle = SendFileHandle::open(path.as_path(), 3).expect("open handle");
        assert_eq!(handle.size(), 3);
    }

    #[test]
    fn read_chunk_reads_expected_range() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, b"abcdef").expect("write file");

        let handle = SendFileHandle::open(path.as_path(), 6).expect("open handle");
        let mut buffer = Vec::with_capacity(3);
        handle
            .read_chunk(2, 3, &mut buffer)
            .expect("read chunk should succeed");

        assert_eq!(&buffer, b"cde");
    }

    #[test]
    fn read_chunk_rejects_offset_beyond_file_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, b"abc").expect("write file");

        let handle = SendFileHandle::open(path.as_path(), 3).expect("open handle");
        let mut buffer = Vec::with_capacity(1);
        let err = handle
            .read_chunk(3, 1, &mut buffer)
            .expect_err("offset at EOF should fail");

        assert!(err.to_string().contains("exceeds file size"));
    }

    #[test]
    fn read_chunk_returns_error_instead_of_panicking_for_small_buffer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, b"abcdef").expect("write file");

        let handle = SendFileHandle::open(path.as_path(), 6).expect("open handle");
        let mut buffer = Vec::with_capacity(2);

        let result =
            std::panic::catch_unwind(AssertUnwindSafe(|| handle.read_chunk(0, 3, &mut buffer)));

        assert!(result.is_ok(), "read_chunk should not panic");
        let err = result
            .expect("read_chunk should not panic")
            .expect_err("insufficient capacity should return error");
        assert!(err.to_string().contains("buffer capacity"));
    }
}
