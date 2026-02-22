//! Restoring config defaults.

use super::defaults_toml;
use super::io::atomic_write;
use anyhow::{Result, bail};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

/// Reset config to defaults, enforcing confirmation in interactive mode.
pub(super) fn reset_config(path: &Path, yes: bool) -> Result<bool> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let interactive = std::io::stdin().is_terminal();

    reset_config_with_io(path, yes, interactive, &mut input, &mut output)
}

fn reset_config_with_io(
    path: &Path,
    yes: bool,
    interactive: bool,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<bool> {
    if !yes {
        if !interactive {
            bail!("Refusing to reset config in non-interactive mode. Use --yes");
        }

        write!(
            output,
            "Reset config to application defaults at {}? [y/N]: ",
            path.display()
        )?;
        output.flush()?;

        let mut response = String::new();
        input.read_line(&mut response)?;
        let confirmed = matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        if !confirmed {
            writeln!(output, "Reset cancelled. Existing config unchanged.")?;
            return Ok(false);
        }
    }

    let text = defaults_toml()?;
    atomic_write(path, &text)?;
    writeln!(output, "Config reset to defaults: {}", path.display())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::reset_config_with_io;
    use std::fs;
    use std::io::Cursor;

    fn write_text(path: &std::path::Path, text: &str) {
        fs::write(path, text).expect("write config")
    }

    #[test]
    fn reset_non_interactive_requires_yes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        write_text(&path, "[local]\nport = 1234\n");

        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        let err = reset_config_with_io(&path, false, false, &mut input, &mut output)
            .expect_err("should fail without --yes");

        assert!(err.to_string().contains("Use --yes"));
        let content = fs::read_to_string(&path).expect("read config");
        assert!(content.contains("port = 1234"));
    }

    #[test]
    fn reset_with_yes_rewrites_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        write_text(&path, "[local]\nport = 1234\n");

        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        let changed = reset_config_with_io(&path, true, false, &mut input, &mut output)
            .expect("reset should succeed");

        assert!(changed);
        let content = fs::read_to_string(&path).expect("read config");
        assert!(content.contains("default_transport = \"local\""));
    }
}
