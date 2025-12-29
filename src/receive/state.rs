use crate::common::config::TransferConfig;
use crate::common::{Session, TransferState};
use crate::receive::storage::ChunkStorage;
use crate::receive::session::ReceiveSession;
use crate::server::progress::ProgressTracker;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// State for a single file being received
pub struct FileReceiveState {
    pub storage: ChunkStorage,
    pub total_chunks: usize,
    pub nonce: String,
    pub relative_path: String,
    pub file_size: u64,
}

/// Receive-specific application state
#[derive(Clone)]
pub struct ReceiveAppState {
    pub session: ReceiveSession,
    pub progress: ProgressTracker,
    pub receive_sessions: Arc<DashMap<String, Arc<Mutex<FileReceiveState>>>>, // ✅ Concrete type
    pub config: TransferConfig,
}

impl ReceiveAppState {
    pub fn new(session: ReceiveSession, progress: ProgressTracker, config: TransferConfig) -> Self {
        Self {
            session,
            progress,
            receive_sessions: Arc::new(DashMap::new()),
            config,
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

    fn session(&self) -> &dyn Session {
        &self.session
    }

    fn service_path(&self) -> &'static str {
        "receive"
    }

    fn is_receiving(&self) -> bool {
        true
    }
}
