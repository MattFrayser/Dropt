use crate::crypto::types::EncryptionKey;
use crate::transfer::manifest::{FileEntry, Manifest};
use aes_gcm::{Aes256Gcm, KeyInit};
use dashmap::DashMap;
use sha2::digest::generic_array::GenericArray;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Clone)]
pub enum SessionMode {
    Send { manifest: Manifest },
    Receive { destination: PathBuf },
}

// Sessions are meant for a single user
// First user will claim the session and must match client_id
#[derive(Debug, Clone)]
pub enum SessionState {
    Unclaimed,
    Active { client_id: String },
    Completed,
}

// Sessions hold information about crypto, progress, session owner
pub struct Session {
    token: String,
    session_key: EncryptionKey,
    cipher: Arc<Aes256Gcm>, // Shared cipher is initialized here and reused
    mode: SessionMode,
    state: Arc<RwLock<SessionState>>, // RwLock inside Arc for concurrent safe access
    pub total_chunks: AtomicU64,
    pub chunks_sent: Arc<AtomicU64>, // Arc for concurrent file/chunk transfers
    sent_chunks: Arc<DashMap<(usize, usize), ()>>, // Track sent chunks for deduplication
}

// AppState holds session and AppState needs to be cloned
// Session holds thread shared resources,
// Need to make custom shallow copy,
impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            session_key: self.session_key.clone(),
            cipher: self.cipher.clone(),
            mode: self.mode.clone(),
            state: self.state.clone(),
            total_chunks: AtomicU64::new(self.total_chunks.load(Ordering::SeqCst)),
            chunks_sent: self.chunks_sent.clone(),
            sent_chunks: self.sent_chunks.clone(),
        }
    }
}

impl Session {
    pub fn new_send(manifest: Manifest, session_key: EncryptionKey, total_chunks: u64) -> Self {
        Self::new(SessionMode::Send { manifest }, session_key, total_chunks)
    }

    pub fn new_receive(
        destination: PathBuf,
        session_key: EncryptionKey,
        total_chunks: u64,
    ) -> Self {
        Self::new(
            SessionMode::Receive { destination },
            session_key,
            total_chunks,
        )
    }

    pub fn new(mode: SessionMode, session_key: EncryptionKey, total_chunks: u64) -> Self {
        let token = Uuid::new_v4().to_string();

        let cipher = Arc::new(Aes256Gcm::new(GenericArray::from_slice(
            session_key.as_bytes(),
        )));

        Self {
            token,
            session_key,
            cipher,
            mode,
            state: Arc::new(RwLock::new(SessionState::Unclaimed)),
            total_chunks: AtomicU64::new(total_chunks),
            chunks_sent: Arc::new(AtomicU64::new(0)),
            sent_chunks: Arc::new(DashMap::new()),
        }
    }

    //  safely increment the count
    pub fn increment_sent_chunk(&self) -> (u64, u64) {
        let new_count = self.chunks_sent.fetch_add(1, Ordering::SeqCst) + 1;
        let total = self.total_chunks.load(Ordering::SeqCst);

        (new_count, total)
    }

    // Set total chunks (for receive mode when manifest arrives)
    pub fn set_total_chunks(&self, total: u64) {
        self.total_chunks.store(total, Ordering::SeqCst);
    }

    // Increment received chunk counter (reuses chunks_sent for receive mode)
    pub fn increment_received_chunk(&self) -> (u64, u64) {
        let chunks_received = self.chunks_sent.fetch_add(1, Ordering::SeqCst) + 1;
        let total = self.total_chunks.load(Ordering::SeqCst);
        (chunks_received, total)
    }

    //-- Chunk Deduplication (Send Mode)

    /// Check if a chunk has already been sent (for deduplication)
    pub fn has_chunk_been_sent(&self, file_index: usize, chunk_index: usize) -> bool {
        self.sent_chunks.contains_key(&(file_index, chunk_index))
    }

    /// Mark a chunk as sent. Returns true if this is the first time.
    pub fn mark_chunk_sent(&self, file_index: usize, chunk_index: usize) -> bool {
        self.sent_chunks
            .insert((file_index, chunk_index), ())
            .is_none()
    }

    /// Get count of unique chunks sent (for debugging/logging)
    pub fn unique_chunks_sent(&self) -> usize {
        self.sent_chunks.len()
    }

    //-- Accessors

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn session_key(&self) -> &EncryptionKey {
        &self.session_key
    }

    pub fn cipher(&self) -> &Arc<Aes256Gcm> {
        &self.cipher
    }

    pub fn session_key_b64(&self) -> String {
        self.session_key.to_base64()
    }

    //-- Session lock logic
    // First come first serve

    // Claims inactive session, creates client_id
    pub fn claim(&self, token: &str, client_id: &str) -> bool {
        if token != self.token {
            return false;
        }

        // Convert for storage in SessionState::Active
        let client_id_owned = client_id.to_string();

        // Try to claim
        let mut state = match self.state.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("Session lock poisoned during claim, recovering");
                poisoned.into_inner()
            }
        };
        match &*state {
            SessionState::Unclaimed => {
                tracing::debug!("Session claimed by client: {}", client_id);
                *state = SessionState::Active {
                    client_id: client_id_owned,
                };
                true
            }
            SessionState::Active {
                client_id: stored_id,
            } => {
                // Session is already claimed: Check if the client IDs match
                let matches = stored_id == client_id;
                if !matches {
                    tracing::warn!(
                        "Session access denied: expected client_id '{}', got '{}'",
                        stored_id, client_id
                    );
                }
                matches
            }
            SessionState::Completed => {
                tracing::debug!("Session already completed");
                false
            }
        }
    }

    pub fn is_active(&self, token: &str, client_id: &str) -> bool {
        if token != self.token {
            return false;
        }

        let state = match self.state.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("Session lock poisoned during is_active check, recovering");
                poisoned.into_inner()
            }
        };
        match &*state {
            SessionState::Active {
                client_id: stored_id,
            } => stored_id == client_id,
            _ => false,
        }
    }

    pub fn complete(&self, token: &str, client_id: &str) -> bool {
        if !self.is_active(token, client_id) {
            return false;
        }

        let mut state = match self.state.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("Session lock poisoned during complete, recovering");
                poisoned.into_inner()
            }
        };
        tracing::info!("Session completed by client: {}", client_id);
        *state = SessionState::Completed;
        true
    }

    //-- Mode based Helpers

    pub fn manifest(&self) -> Option<&Manifest> {
        match &self.mode {
            SessionMode::Send { manifest } => Some(manifest),
            _ => None,
        }
    }

    pub fn get_file(&self, index: usize) -> Option<&FileEntry> {
        self.manifest().and_then(|m| m.files.get(index))
    }

    pub fn destination(&self) -> Option<&PathBuf> {
        match &self.mode {
            SessionMode::Receive { destination } => Some(destination),
            _ => None,
        }
    }
}
