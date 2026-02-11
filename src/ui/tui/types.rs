use crate::common::config::Transport;
pub use crate::common::progress::{FileProgress, FileStatus, TransferProgress};

/// Static configuration passed to TUI at startup
#[derive(Clone, Debug)]
pub struct TuiConfig {
    pub is_receiving: bool,
    pub transport: Transport,
    pub url: String,
    pub qr_code: String,
    pub display_name: String,
    pub display_files: Vec<String>,
    pub display_overflow_count: Option<usize>,
    pub show_qr: bool,
    pub show_url: bool,
}
