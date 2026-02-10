use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Write the resolved config path to provided writer.
pub(super) fn path_config_with_writer(path: &Path, output: &mut dyn Write) -> Result<()> {
    writeln!(output, "{}", path.display())?;
    Ok(())
}

/// Stream config file contents (fallback guidance when missing.)
pub(super) fn show_config_with_io(
    path: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<()> {
    if path.exists() {
        let mut file = fs::File::open(path)
            .with_context(|| format!("Failed to open config file {}", path.display()))?;
        std::io::copy(&mut file, stdout)?;
    } else {
        writeln!(stderr, "No config file found at {}", path.display())?;
        writeln!(
            stderr,
            "Using default settings. Create {} to override defaults.",
            path.display()
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{path_config_with_writer, show_config_with_io};
    use std::fs;

    fn write_text(path: &std::path::Path, text: &str) {
        fs::write(path, text).expect("write config")
    }

    #[test]
    fn path_command_writes_display_path() {
        let path = std::path::Path::new("/tmp/archdrop-config.toml");
        let mut out = Vec::new();

        path_config_with_writer(path, &mut out).expect("path output should succeed");

        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(text, "/tmp/archdrop-config.toml\n");
    }

    #[test]
    fn show_command_streams_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        write_text(&path, "[local]\nport = 1234\n");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        show_config_with_io(&path, &mut stdout, &mut stderr).expect("show should succeed");

        assert_eq!(
            String::from_utf8(stdout).expect("utf8"),
            "[local]\nport = 1234\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn show_command_emits_missing_file_guidance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing-config.toml");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        show_config_with_io(&path, &mut stdout, &mut stderr)
            .expect("show should succeed when file is missing");

        assert!(stdout.is_empty());
        let err = String::from_utf8(stderr).expect("utf8");
        assert!(err.contains("No config file found at"));
        assert!(err.contains("Using default settings."));
    }
}
