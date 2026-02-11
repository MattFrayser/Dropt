//! Shared domain types and contracts
//!
//! Exposes config, error mapping, manifest metadata, and session primitives.
pub mod config;
pub mod config_commands;
pub mod errors;
pub mod manifest;
pub mod progress;
pub mod session_core;

pub use config::{AppConfig, ConfigOverrides, TransferSettings, Transport};
pub use errors::AppError;
pub use manifest::{FileEntry, Manifest};
pub use progress::{FileProgress, FileStatus, TransferProgress};
pub use session_core::{ClaimError, Session, SessionState};

/// Runtime contract for send/receive state implementations.
#[async_trait::async_trait]
pub trait TransferState: Clone + Send + Sync + 'static {
    // Inflight tranfer count
    fn transfer_count(&self) -> usize;

    // Best effort clean up on incomplete
    async fn cleanup(&self);

    // Shared session for authentication and URL generation
    fn session(&self) -> &session_core::Session;

    // Returns URL segment path ("send" or "receive")
    fn service_path(&self) -> &'static str;

    // True is state is receive mode
    fn is_receiving(&self) -> bool;
}
