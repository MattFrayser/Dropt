// AppError is used throughout server
// return 500 to client side, log errors serverside
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::error;

/// Automatic conversion: any error -> HTTP 500 response
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!(
            error = ?self.0,
            backtrace = ?self.0.backtrace(),
            "Internal Server error"
        );
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error> + Send + Sync,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
