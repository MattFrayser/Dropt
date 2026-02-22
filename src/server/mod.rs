//! Server startup, routing, auth, progress, and runtime orchestration.

// Submodules
mod api;
pub mod auth;
pub mod progress;
pub mod routes;
mod runtime;

// Public API (what main.rs imports)
pub use api::{ServerInstance, start_receive_server, start_send_server};
