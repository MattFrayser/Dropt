//! Session authentication and lock lifecycle primitives.

use crate::crypto::types::EncryptionKey;
use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

fn generate_lock_token() -> String {
    Uuid::new_v4().to_string()
}

/// Reasons a session claim can be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    InvalidToken,
    AlreadyClaimed,
    Completed,
}

/// Session lock state machine for transfer ownership.
#[derive(Debug, Clone)]
pub enum SessionState {
    Unclaimed,
    Active { lock_token: String },
    Completed,
}

/// Shared session context containing auth token, encryption key, cipher, and lock state.
pub struct Session {
    token: String,
    session_key: EncryptionKey,
    cipher: Arc<LessSafeKey>,
    state: Arc<RwLock<SessionState>>, // RwLock inside Arc for concurrent safe access
}

impl Session {
    /// Creates a new session with fresh token, key-backed cipher, and unclaimed state.
    pub fn new(session_key: EncryptionKey) -> Self {
        let token = Uuid::new_v4().to_string();

        let unbound = UnboundKey::new(&AES_256_GCM, session_key.as_bytes())
            .expect("valid 32-byte AES-256 key");
        let cipher = Arc::new(LessSafeKey::new(unbound));

        tracing::debug!("Created new session");

        Self {
            token,
            session_key,
            cipher,
            state: Arc::new(RwLock::new(SessionState::Unclaimed)),
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn session_key(&self) -> &EncryptionKey {
        &self.session_key
    }

    pub fn cipher(&self) -> &Arc<LessSafeKey> {
        &self.cipher
    }

    pub fn session_key_b64(&self) -> String {
        self.session_key.to_base64()
    }

    //-- Session lock logic

    /// Claims an unclaimed session and returns the server-issued lock token.
    pub fn claim(&self, token: &str) -> Result<String, ClaimError> {
        if token != self.token {
            tracing::warn!("Session claim rejected: token mismatch");
            return Err(ClaimError::InvalidToken);
        }

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
                let lock_token = generate_lock_token();
                tracing::debug!("Session claimed");
                *state = SessionState::Active {
                    lock_token: lock_token.clone(),
                };
                Ok(lock_token)
            }
            SessionState::Active { .. } => Err(ClaimError::AlreadyClaimed),
            SessionState::Completed => Err(ClaimError::Completed),
        }
    }

    /// Returns true only when both session token and lock token match active state.
    pub fn is_active(&self, token: &str, lock_token: &str) -> bool {
        if token != self.token {
            return false;
        }

        if lock_token.trim().is_empty() {
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
            SessionState::Active { lock_token: active } => active == lock_token,
            _ => false,
        }
    }

    /// Marks session completed when caller holds valid active ownership tokens.
    pub fn complete(&self, token: &str, lock_token: &str) -> bool {
        if !self.is_active(token, lock_token) {
            return false;
        }

        let mut state = match self.state.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("Session lock poisoned during complete, recovering");
                poisoned.into_inner()
            }
        };
        tracing::info!("Session completed");
        *state = SessionState::Completed;
        true
    }

    /// Returns true when session has entered terminal completed state.
    pub fn is_completed(&self) -> bool {
        let state = match self.state.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("Session lock poisoned during is_completed check, recovering");
                poisoned.into_inner()
            }
        };
        matches!(&*state, SessionState::Completed)
    }
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
            state: self.state.clone(),
        }
    }
}
