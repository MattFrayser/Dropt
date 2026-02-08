use crate::crypto::types::EncryptionKey;
use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Validates that client_id is not empty or whitespace-only
fn validate_client_id(client_id: &str) -> bool {
    !client_id.trim().is_empty()
}

/// First-come-first-served session locking.
#[derive(Debug, Clone)]
pub enum SessionState {
    Unclaimed,
    Active { client_id: String },
    Completed,
}

/// Shared session infrastructure
/// For cypto and auth
pub struct Session {
    token: String,
    session_key: EncryptionKey,
    cipher: Arc<LessSafeKey>,
    state: Arc<RwLock<SessionState>>, // RwLock inside Arc for concurrent safe access
}

impl Session {
    pub fn new(session_key: EncryptionKey) -> Self {
        let token = Uuid::new_v4().to_string();

        let unbound = UnboundKey::new(&AES_256_GCM, session_key.as_bytes())
            .expect("valid 32-byte AES-256 key");
        let cipher = Arc::new(LessSafeKey::new(unbound));

        tracing::debug!("Created new session with token: '{}'", token);

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

    /// Claims unclaimed session or validates existing claim. Rejects empty client_ids.
    pub fn claim(&self, token: &str, client_id: &str) -> bool {
        if token != self.token {
            tracing::warn!(
                "Session claim rejected: token mismatch (expected: '{}', got: '{}')",
                self.token,
                token
            );
            return false;
        }

        // Validate client_id - reject empty or whitespace-only
        if !validate_client_id(client_id) {
            tracing::warn!("Session claim rejected: empty client_id");
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
                        stored_id,
                        client_id
                    );
                }
                matches
            }
            SessionState::Completed => false,
        }
    }

    pub fn is_active(&self, token: &str, client_id: &str) -> bool {
        if token != self.token {
            return false;
        }

        // Validate client_id - reject empty or whitespace-only
        if !validate_client_id(client_id) {
            tracing::warn!("Session active check rejected: empty client_id");
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

