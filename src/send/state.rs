use crate::common::config::TransferSettings;
use crate::common::{manifest::FileEntry, Manifest, Session, TransferState};
use crate::crypto::types::EncryptionKey;
use crate::send::file_handle::SendFileHandle;
use crate::server::progress::ProgressTracker;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Send-specific application state
/// Passed to all send handlers via Axum State extractor
pub struct SendAppState {
    pub session: Session,
    pub manifest: Manifest,
    pub progress: Arc<ProgressTracker>,
    pub file_handles: Arc<DashMap<usize, Arc<SendFileHandle>>>,
    pub config: TransferSettings,
    chunks_sent: Arc<AtomicU64>,
    sent_chunks: Arc<DashMap<(usize, usize), ()>>,
    total_chunks: AtomicU64,
}

impl SendAppState {
    pub fn new(
        session_key: EncryptionKey,
        manifest: Manifest,
        total_chunks: u64,
        progress: Arc<ProgressTracker>,
        config: TransferSettings,
    ) -> Self {
        Self {
            session: Session::new(session_key),
            manifest,
            progress,
            file_handles: Arc::new(DashMap::new()),
            config,
            chunks_sent: Arc::new(AtomicU64::new(0)),
            sent_chunks: Arc::new(DashMap::new()),
            total_chunks: AtomicU64::new(total_chunks),
        }
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn get_file(&self, index: usize) -> Option<&FileEntry> {
        self.manifest.files.get(index)
    }

    pub fn increment_sent_chunk(&self) -> (u64, u64) {
        let new_count = self.chunks_sent.fetch_add(1, Ordering::SeqCst) + 1;
        let total = self.total_chunks.load(Ordering::SeqCst);
        (new_count, total)
    }

    pub fn has_chunk_been_sent(&self, file_index: usize, chunk_index: usize) -> bool {
        self.sent_chunks.contains_key(&(file_index, chunk_index))
    }

    pub fn mark_chunk_sent(&self, file_index: usize, chunk_index: usize) -> bool {
        self.sent_chunks
            .insert((file_index, chunk_index), ())
            .is_none()
    }

    pub fn unique_chunks_sent(&self) -> usize {
        self.sent_chunks.len()
    }

    pub fn get_chunks_sent(&self) -> u64 {
        self.chunks_sent.load(Ordering::SeqCst)
    }

    pub fn get_total_chunks(&self) -> u64 {
        self.total_chunks.load(Ordering::SeqCst)
    }
}

impl Clone for SendAppState {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            manifest: self.manifest.clone(),
            progress: self.progress.clone(),
            file_handles: self.file_handles.clone(),
            config: self.config.clone(),
            chunks_sent: self.chunks_sent.clone(),
            sent_chunks: self.sent_chunks.clone(),
            total_chunks: AtomicU64::new(self.total_chunks.load(Ordering::SeqCst)),
        }
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
