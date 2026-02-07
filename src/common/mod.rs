pub mod config;
pub mod errors;
pub mod manifest;
pub mod session_core;

pub use config::{AppConfig, CliArgs, Transport, TransferSettings};
pub use errors::AppError;
pub use manifest::{FileEntry, Manifest};
pub use session_core::{Session, SessionState};

/// Trait for application states (Send/Receive) used by runtime
#[async_trait::async_trait]
pub trait TransferState: Clone + Send + Sync + 'static {
    fn transfer_count(&self) -> usize;
    async fn cleanup(&self);

    // Session access for authentication and URL generation
    fn session(&self) -> &session_core::Session;

    // Direction info for URL path and TUI
    fn service_path(&self) -> &'static str; // "send" or "receive"
    fn is_receiving(&self) -> bool; // true for receive mode
}
