pub mod crypto;
pub mod errors;
pub mod server;
pub mod transfer;
pub mod tunnel;
pub mod ui;

// Constant used through out rust and JS code
pub mod config {
    pub const CHUNK_SIZE: u64 = 1024 * 1024; // 1MB
}
