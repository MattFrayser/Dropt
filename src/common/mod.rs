pub mod config;
pub mod errors;
pub mod manifest;
pub mod session_core;
pub mod session_trait;

pub use config::TransferConfig;
pub use errors::AppError;
pub use manifest::{FileEntry, Manifest};
pub use session_core::{SessionImpl, SessionState};
pub use session_trait::Session;

/// Trait for application states (Send/Receive) used by runtime
#[async_trait::async_trait]
pub trait TransferState: Clone + Send + Sync + 'static {
    fn transfer_count(&self) -> usize;
    async fn cleanup(&self);

    // Session access for authentication and URL generation
    fn session(&self) -> &dyn Session;

    // Direction info for URL path and TUI
    fn service_path(&self) -> &'static str;  // "send" or "receive"
    fn is_receiving(&self) -> bool;  // true for receive mode
}
