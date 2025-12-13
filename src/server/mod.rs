// Submodules
mod api;
pub mod auth;
mod helpers;
pub mod routes;
mod runtime;
mod session;
pub mod state;
mod static_files;

// Public API (what main.rs imports)
pub use api::{
    get_transfer_config, start_receive_server, start_send_server, ServerDirection, ServerInstance,
    ServerMode,
};

// Semi-public (what transfer/ imports)
pub use session::Session;
pub use state::{AppState, FileReceiveState};
