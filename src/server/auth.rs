//! Request extractors and session-gating helpers for server endpoints.

use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::common::{AppError, session_core::ClaimError, session_core::Session};

/// Header name carrying the transfer lock token.
pub const LOCK_HEADER_NAME: &str = "x-transfer-lock";

/// Extracted bearer token from `Authorization: Bearer <token>`.
pub struct BearerToken(pub String);

/// Extracted lock token from `X-Transfer-Lock`.
pub struct LockToken(pub String);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for BearerToken {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing authorization header".to_string()))?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid authorization header".to_string()))?;

        if token.trim().is_empty() {
            return Err(AppError::Unauthorized(
                "invalid authorization header".to_string(),
            ));
        }

        Ok(BearerToken(token.to_string()))
    }
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for LockToken {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(LOCK_HEADER_NAME)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing transfer lock header".to_string()))?;

        if value.trim().is_empty() {
            return Err(AppError::Unauthorized(
                "invalid transfer lock header".to_string(),
            ));
        }

        Ok(LockToken(value.to_string()))
    }
}

/// Require a currently active session for `(token, lock_token)`.
pub fn require_active_session(
    session: &Session,
    token: &str,
    lock_token: &str,
) -> Result<(), AppError> {
    if !session.is_active(token, lock_token) {
        return Err(AppError::Unauthorized("session not active".to_string()));
    }
    Ok(())
}

/// Claim a session and return its lock token.
pub fn claim_session(session: &Session, token: &str) -> Result<String, AppError> {
    match session.claim(token) {
        Ok(lock_token) => Ok(lock_token),
        Err(ClaimError::InvalidToken) => {
            Err(AppError::Unauthorized("invalid session token".to_string()))
        }
        Err(ClaimError::AlreadyClaimed) => {
            Err(AppError::Conflict("session already claimed".to_string()))
        }
        Err(ClaimError::Completed) => Err(AppError::Conflict("session completed".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::session_core::Session;
    use crate::crypto::types::EncryptionKey;

    #[test]
    fn test_require_active_unclaimed_session() {
        let key = EncryptionKey::new();
        let session = Session::new(key);
        let token = session.token();

        let result = require_active_session(&session, token, "lock1");
        assert!(result.is_err());
    }

    #[test]
    fn test_require_active_wrong_lock_token() {
        let key = EncryptionKey::new();
        let session = Session::new(key);
        let token = session.token();
        let lock = claim_session(&session, token).expect("claim should succeed");

        let result = require_active_session(&session, token, &format!("{lock}-bad"));
        assert!(result.is_err());
    }

    #[test]
    fn test_require_active_valid_session() {
        let key = EncryptionKey::new();
        let session = Session::new(key);
        let token = session.token();
        let lock = claim_session(&session, token).expect("claim should succeed");

        let result = require_active_session(&session, token, &lock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_claim_session_second_claim_conflict() {
        let key = EncryptionKey::new();
        let session = Session::new(key);
        let token = session.token();

        let first = claim_session(&session, token);
        assert!(first.is_ok());

        let second = claim_session(&session, token);
        assert!(matches!(second, Err(AppError::Conflict(_))));
    }

    #[test]
    fn test_claim_invalid_token() {
        let key = EncryptionKey::new();
        let session = Session::new(key);

        let result = claim_session(&session, "invalid-token-12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_require_active_with_wrong_bearer() {
        let key = EncryptionKey::new();
        let session = Session::new(key);
        let token = session.token();
        let lock = claim_session(&session, token).expect("claim should succeed");

        let result = require_active_session(&session, "wrong-token", &lock);
        assert!(result.is_err());
    }
}
