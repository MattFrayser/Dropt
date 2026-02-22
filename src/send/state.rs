//! Shared send-session state and transfer-state implementation.

use crate::common::config::TransferSettings;
use crate::common::{Manifest, Session, TransferState, manifest::FileEntry};
use crate::crypto::types::EncryptionKey;
use crate::send::buffer_pool::BufferPool;
use crate::send::file_handle::SendFileHandle;
use crate::server::progress::ProgressTracker;
use dashmap::DashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cheaply cloned handle to send state stored behind `Arc`.
#[derive(Clone)]
pub struct SendAppState {
    inner: Arc<SendAppStateInner>,
}

/// Send-specific application state for handlers and progress tracking
pub struct SendAppStateInner {
    pub session: Session,
    pub manifest: Manifest,
    pub progress: Arc<ProgressTracker>,
    pub file_handles: Arc<DashMap<usize, Arc<SendFileHandle>>>,
    pub buffer_pool: Arc<BufferPool>,
    pub config: TransferSettings,
    sent_chunks: Arc<DashMap<(usize, usize), ()>>,
    total_chunks: Arc<AtomicU64>,
}

impl Deref for SendAppState {
    type Target = SendAppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl SendAppState {
    /// Build send state from session data, manifest, and transfer settings.
    pub fn new(
        session_key: EncryptionKey,
        manifest: Manifest,
        total_chunks: u64,
        progress: Arc<ProgressTracker>,
        config: TransferSettings,
    ) -> Self {
        // +16 bytes for AES-GCM tag appended during encrypt_in_place
        let buf_capacity = config.chunk_size as usize + 16;
        let pool_size = config.concurrency;

        Self {
            inner: Arc::new(SendAppStateInner {
                session: Session::new(session_key),
                manifest,
                progress,
                file_handles: Arc::new(DashMap::new()),
                buffer_pool: BufferPool::new(pool_size, buf_capacity),
                config,
                sent_chunks: Arc::new(DashMap::new()),
                total_chunks: Arc::new(AtomicU64::new(total_chunks)),
            }),
        }
    }

    /// Return the transfer manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Return a file entry by manifest index.
    pub fn get_file(&self, index: usize) -> Option<&FileEntry> {
        self.manifest.files.get(index)
    }

    /// Mark a file/chunk pair as sent; true if newly inserted.
    pub fn mark_chunk_sent(&self, file_index: usize, chunk_index: usize) -> bool {
        self.sent_chunks
            .insert((file_index, chunk_index), ())
            .is_none()
    }

    /// Return count of unique file/chunk pairs sent.
    pub fn unique_chunks_sent(&self) -> usize {
        self.sent_chunks.len()
    }

    /// Return count of unique chunks sent.
    pub fn get_chunks_sent(&self) -> u64 {
        self.unique_chunks_sent() as u64
    }

    /// Return expected total chunk count for this transfer.
    pub fn get_total_chunks(&self) -> u64 {
        self.total_chunks.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl TransferState for SendAppState {
    fn transfer_count(&self) -> usize {
        self.file_handles.len()
    }

    async fn cleanup(&self) {
        let count = self.file_handles.len();
        if count > 0 {
            tracing::debug!("Cleaning up {} send session(s)", count);
        }
        self.file_handles.clear();
    }

    fn session(&self) -> &Session {
        &self.session
    }

    fn service_path(&self) -> &'static str {
        "send"
    }

    fn is_receiving(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::TransferSettings;

    #[test]
    fn clone_shares_total_chunks_atomic() {
        let state = SendAppState::new(
            EncryptionKey::new(),
            Manifest {
                files: Vec::new(),
                config: TransferSettings {
                    chunk_size: 1024,
                    concurrency: 1,
                },
            },
            3,
            Arc::new(ProgressTracker::new()),
            TransferSettings {
                chunk_size: 1024,
                concurrency: 1,
            },
        );

        let cloned = state.clone();

        state.total_chunks.store(9, Ordering::SeqCst);

        assert_eq!(cloned.get_total_chunks(), 9);
    }

    #[test]
    fn chunks_sent_tracks_unique_chunk_marks() {
        let state = SendAppState::new(
            EncryptionKey::new(),
            Manifest {
                files: Vec::new(),
                config: TransferSettings {
                    chunk_size: 1024,
                    concurrency: 1,
                },
            },
            3,
            Arc::new(ProgressTracker::new()),
            TransferSettings {
                chunk_size: 1024,
                concurrency: 1,
            },
        );

        assert!(state.mark_chunk_sent(0, 0));
        assert!(!state.mark_chunk_sent(0, 0));
        assert!(state.mark_chunk_sent(0, 1));

        assert_eq!(state.unique_chunks_sent(), 2);
        assert_eq!(state.get_chunks_sent(), 2);
    }
}
