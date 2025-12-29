use anyhow::{Context, Result};
use qrcode::render::unicode;
use qrcode::QrCode;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::tui::TransferUI;

pub fn generate_qr(url: &str) -> Result<String> {
    let code = QrCode::new(url.as_bytes()).context("Failed to generate QR code")?;

    Ok(code
        .render::<unicode::Dense1x2>()
        // colors are inverted for better visability in terminal
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build())
}

pub fn spawn_tui(
    progress: watch::Receiver<f64>,
    file_name: String,
    qr_code: String,
    is_recieving: bool,
    status_message: watch::Receiver<Option<String>>,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ui = TransferUI::new(progress, file_name, qr_code, is_recieving, status_message);

        tokio::select! {
            result = ui.run() => {
                if let Err(e) = result {
                    eprintln!("ui err: {}", e);
                }
            }
            _ = cancel_token.cancelled() => {
                tracing::debug!("TUI task cancelled gracefully");
                // TUI will drop and restore terminal automatically
            }
        }
    })
}
