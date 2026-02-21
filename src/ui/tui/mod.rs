//! Terminal UI modules: runtime, layout, panels, links, and QR utilities.

mod connection;
mod hyperlink;
mod output;
mod render;
mod styles;
mod transfer_panel;
mod types;
mod ui;

pub use output::{spinner, spinner_error, spinner_success};
pub use render::{spawn_tui, TransferUI};
pub use types::{FileProgress, FileStatus, TransferProgress, TuiConfig};
pub use ui::generate_qr;
