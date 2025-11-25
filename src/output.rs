use std::time::Duration;

use console::style;
use indicatif::{ProgressBar, ProgressStyle};

pub fn success(msg: &str) {
    println!("{} {}", style("✓").green().bold(), msg);
}

pub fn error(msg: &str) {
    eprintln!("{} {}", style("✗").red().bold(), msg);
}

pub fn info(msg: &str) {
    println!("{} {}", style("→").cyan(), msg);
}

pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

pub fn finish_spinner_success(spinner: &ProgressBar, msg: &str) {
    spinner.finish_with_message(format!("{} {}", style("✓").green().bold(), msg));
}

pub fn finish_spinner_error(spinner: &ProgressBar, msg: &str) {
    spinner.finish_with_message(format!("{} {}", style("✗").red().bold(), msg));
}
