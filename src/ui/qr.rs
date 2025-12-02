use anyhow::{Context, Result};
use qrcode::render::unicode;
use qrcode::QrCode;

pub fn generate_qr(url: &str) -> Result<String> {
    let code = QrCode::new(url.as_bytes()).context("Failed to generate QR code")?;

    Ok(code
        .render::<unicode::Dense1x2>()
        // colors are inverted for better visability in terminal
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build())
}
