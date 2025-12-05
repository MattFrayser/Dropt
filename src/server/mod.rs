// Submodules
mod api;
pub mod auth;
mod helpers;
mod routes;
mod runtime;
mod session;
pub mod state;
mod static_files;

// Public API (what main.rs imports)
pub use api::{
    start_receive_server, start_receive_server_for_test, start_send_server,
    start_send_server_for_test, ServerDirection, ServerInstance, ServerMode,
};

// Semi-public (what transfer/ imports)
pub use session::Session;
pub use state::{AppState, FileReceiveState};
