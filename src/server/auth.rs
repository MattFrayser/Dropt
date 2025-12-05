use crate::errors::AppError;
use crate::server::session::Session;

#[derive(serde::Deserialize)]
pub struct ClientIdParam {
    #[serde(rename = "clientId")]
    pub client_id: String,
}

// Used for handlers that should only work with already claimed sessions
pub fn require_active_session(
    session: &Session,
    token: &str,
    client_id: &str,
) -> Result<(), AppError> {
    if !session.is_active(token, client_id) {
        return Err(anyhow::anyhow!("Invalid or inactive session").into());
    }
    Ok(())
}

// Used for handlers that initiate transfer
pub fn claim_or_validate_session(
    session: &Session,
    token: &str,
    client_id: &str,
) -> Result<(), AppError> {
    if !session.claim(token, client_id) {
        return Err(
            anyhow::anyhow!("Invalid token or session already claimed by another client").into(),
        );
    }
    Ok(())
}
