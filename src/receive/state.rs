use crate::common::config::TransferSettings;
use crate::common::{Session, TransferState};
use crate::crypto::types::EncryptionKey;
use crate::receive::storage::ChunkStorage;
use crate::server::progress::ProgressTracker;
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// State for a single file being received
pub struct FileReceiveState {
    pub storage: ChunkStorage,
    pub total_chunks: usize,
    pub nonce: String,
    pub relative_path: String,
    pub file_size: u64,
    pub file_index: usize,
}

/// Receive-specific application state
pub struct ReceiveAppState {
    pub session: Session,
    pub destination: PathBuf,
    pub progress: Arc<ProgressTracker>,
    pub receive_sessions: Arc<DashMap<String, Arc<Mutex<FileReceiveState>>>>,
    pub config: TransferSettings,
    total_chunks: AtomicU64,
    chunks_received: Arc<AtomicU64>,
}

impl ReceiveAppState {
    pub fn new(
        session_key: EncryptionKey,
        destination: PathBuf,
        progress: Arc<ProgressTracker>,
        config: TransferSettings,
    ) -> Self {
        Self {
            session: Session::new(session_key),
            destination,
            progress,
            receive_sessions: Arc::new(DashMap::new()),
            config,
            total_chunks: AtomicU64::new(0),
            chunks_received: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn destination(&self) -> &PathBuf {
        &self.destination
    }

    pub fn set_total_chunks(&self, total: u64) {
        self.total_chunks.store(total, Ordering::SeqCst);
    }

    pub fn increment_received_chunk(&self) -> (u64, u64) {
        let chunks_received = self.chunks_received.fetch_add(1, Ordering::SeqCst) + 1;
        let total = self.total_chunks.load(Ordering::SeqCst);
        (chunks_received, total)
    }

    pub fn get_progress(&self) -> (u64, u64) {
        let received = self.chunks_received.load(Ordering::SeqCst);
        let total = self.total_chunks.load(Ordering::SeqCst);
        (received, total)
    }
}

impl Clone for ReceiveAppState {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            destination: self.destination.clone(),
            progress: self.progress.clone(),
            receive_sessions: self.receive_sessions.clone(),
            config: self.config.clone(),
            total_chunks: AtomicU64::new(self.total_chunks.load(Ordering::SeqCst)),
            chunks_received: self.chunks_received.clone(),
        }
    }
}

#[async_trait::async_trait]
impl TransferState for ReceiveAppState {
    fn transfer_count(&self) -> usize {
        self.receive_sessions.len()
    }

    async fn cleanup(&self) {
        let count = self.receive_sessions.len();
        if count == 0 {
            return;
        }
        tracing::debug!("Cleaning up {} receive session(s)", count);

        let keys: Vec<String> = self
            .receive_sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        let cleanup_tasks: Vec<_> = keys
            .into_iter()
            .filter_map(|key| self.receive_sessions.remove(&key))
            .map(|(_key, file_state_mutex)| {
                tokio::spawn(async move {
                    let mut state = file_state_mutex.lock().await;
                    if let Err(e) = state.storage.cleanup().await {
                        tracing::error!("Error during async cleanup: {}", e);
                    }
                })
            })
            .collect();

        futures::future::join_all(cleanup_tasks).await;
    }

    fn session(&self) -> &Session {
        &self.session
    }

    fn service_path(&self) -> &'static str {
        "receive"
    }

    fn is_receiving(&self) -> bool {
        true
    }
}
