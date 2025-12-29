use crate::common::session_core::SessionImpl;
use crate::common::session_trait::Session;
use crate::crypto::types::EncryptionKey;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Receive-specific session
/// Composes SessionImpl (auth + crypto) + receive-specific state (destination)
pub struct ReceiveSession {
    core: SessionImpl,
    destination: PathBuf,
    total_chunks: AtomicU64,
    chunks_received: Arc<AtomicU64>,
}

impl ReceiveSession {
    pub fn new(destination: PathBuf, session_key: EncryptionKey) -> Self {
        Self {
            core: SessionImpl::new(session_key),
            destination,
            total_chunks: AtomicU64::new(0), // Updated when manifest arrives
            chunks_received: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn destination(&self) -> &PathBuf {
        &self.destination
    }

    pub fn set_total_chunks(&self, total: u64) {
        self.total_chunks.store(total, Ordering::SeqCst);
    }

    // Receive-specific progress tracking
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

// Implement Session trait via delegation to core
impl Session for ReceiveSession {
    fn token(&self) -> &str {
        self.core.token()
    }

    fn session_key(&self) -> &crate::crypto::types::EncryptionKey {
        self.core.session_key()
    }

    fn cipher(&self) -> &Arc<aes_gcm::Aes256Gcm> {
        self.core.cipher()
    }

    fn session_key_b64(&self) -> String {
        self.core.session_key_b64()
    }

    fn claim(&self, token: &str, client_id: &str) -> bool {
        self.core.claim(token, client_id)
    }

    fn is_active(&self, token: &str, client_id: &str) -> bool {
        self.core.is_active(token, client_id)
    }

    fn complete(&self, token: &str, client_id: &str) -> bool {
        self.core.complete(token, client_id)
    }
}

impl Clone for ReceiveSession {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            destination: self.destination.clone(),
            total_chunks: AtomicU64::new(self.total_chunks.load(Ordering::SeqCst)),
            chunks_received: self.chunks_received.clone(),
        }
    }
}
