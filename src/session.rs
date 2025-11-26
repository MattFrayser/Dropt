use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

const SESSION_LIFETIME: Duration = Duration::from_secs(15 * 60);

pub struct SessionData {
    pub file_path: PathBuf,
    pub used: bool, // flag to prevent replay attacks
    pub created_at: Instant,
}

impl SessionData {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > SESSION_LIFETIME
    }

    fn is_valid(&self) -> bool {
        !self.used && !self.is_expired()
    }
}
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<Mutex<HashMap<String, SessionData>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            // wrap hashmap in mutex for safe access
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_session(&self, file_path: PathBuf) -> String {
        let token = Uuid::new_v4().to_string();

        // Acquire lock to HashMap
        // if annother tasks holds lock, await (doesnt block thread)
        let mut sessions = self.sessions.lock().await;

        // clone() is used since HashMap::insert takes ownership of the key
        // without it token would move and be unavailable for return
        sessions.insert(
            token.clone(),
            SessionData {
                file_path,
                used: false,
                created_at: Instant::now(),
            },
        );

        token
    }

    pub async fn validate_and_mark_used(&self, token: &str) -> Option<PathBuf> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(token) {
            // lazy check expiration
            if session.is_expired() {
                sessions.remove(token);
                return None;
            }
            if session.is_valid() {
                // mark as used FIRST, prevent possible race condition
                session.used = true;
                return Some(session.file_path.clone());
            }
        }

        // Token doesnt exists or is already used
        None
    }

    // check if token exists and is not used (read only)
    pub async fn is_valid(&self, token: &str) -> bool {
        let sessions = self.sessions.lock().await;
        sessions
            .get(token)
            .map(|session| session.is_valid())
            .unwrap_or(false)
    }
}
