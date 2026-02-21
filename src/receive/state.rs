//! Shared receive-session state and transfer-state.

use crate::common::config::{CollisionPolicy, TransferSettings};
use crate::common::{Session, TransferState};
use crate::crypto::types::{EncryptionKey, Nonce};
use crate::receive::storage::ChunkStorage;
use crate::server::progress::ProgressTracker;
use dashmap::DashMap;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Per-file receive state tracked across chunk uploads.
pub struct FileReceiveState {
    pub storage: ChunkStorage,
    pub total_chunks: usize,
    pub nonce: Option<Nonce>,  // stored once, validated on subsequent chunks
    pub relative_path: String,
    pub file_size: u64,
    pub file_index: usize,
}

/// Cheaply cloned handle to receive state
#[derive(Clone)]
pub struct ReceiveAppState {
    inner: Arc<ReceiveAppStateInner>,
}

/// Backing state for receive handlers and progress tracking.
pub struct ReceiveAppStateInner {
    pub session: Session,
    pub destination: PathBuf,
    pub progress: Arc<ProgressTracker>,
    pub receive_sessions: Arc<DashMap<String, Arc<Mutex<FileReceiveState>>>>,
    pub config: TransferSettings,
    pub collision_policy: CollisionPolicy,
    total_chunks: Arc<AtomicU64>,
    chunks_received: Arc<AtomicU64>,
}

impl Deref for ReceiveAppState {
    type Target = ReceiveAppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ReceiveAppState {
    /// Build receive state from session key, destination, and settings.
    pub fn new(
        session_key: EncryptionKey,
        destination: PathBuf,
        progress: Arc<ProgressTracker>,
        config: TransferSettings,
        collision_policy: CollisionPolicy,
    ) -> Self {
        Self {
            inner: Arc::new(ReceiveAppStateInner {
                session: Session::new(session_key),
                destination,
                progress,
                receive_sessions: Arc::new(DashMap::new()),
                config,
                collision_policy,
                total_chunks: Arc::new(AtomicU64::new(0)),
                chunks_received: Arc::new(AtomicU64::new(0)),
            }),
        }
    }

    /// Return the destination root for received files.
    pub fn destination(&self) -> &PathBuf {
        &self.destination
    }

    /// Set expected total chunk count for this transfer.
    pub fn set_total_chunks(&self, total: u64) {
        self.total_chunks.store(total, Ordering::SeqCst);
    }

    /// Increment received-chunk counter and return `(received, total)`.
    pub fn increment_received_chunk(&self) -> (u64, u64) {
        let chunks_received = self.chunks_received.fetch_add(1, Ordering::SeqCst) + 1;
        let total = self.total_chunks.load(Ordering::SeqCst);
        (chunks_received, total)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::TransferSettings;

    #[test]
    fn clone_observes_total_chunks_updates() {
        let state = ReceiveAppState::new(
            EncryptionKey::new(),
            PathBuf::from("."),
            Arc::new(ProgressTracker::new()),
            TransferSettings {
                chunk_size: 1024,
                concurrency: 1,
            },
            CollisionPolicy::default(),
        );

        let cloned = state.clone();
        state.set_total_chunks(7);

        let (_received, total) = cloned.increment_received_chunk();
        assert_eq!(total, 7);
    }
}
