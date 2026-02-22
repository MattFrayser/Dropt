//! Edit config flow. Validation and retry prompts

use super::defaults_toml;
use super::io::{atomic_write, temp_path_for};
use crate::common::config::AppConfig;
use anyhow::{Context, Result};
use figment::{Figment, providers::Format, providers::Serialized, providers::Toml};
use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryChoice {
    Edit,
    View,
    Abort,
}

fn parse_retry_choice(input: &str) -> Option<RetryChoice> {
    match input.trim().to_ascii_lowercase().as_str() {
        "e" => Some(RetryChoice::Edit),
        "v" => Some(RetryChoice::View),
        "a" | "" => Some(RetryChoice::Abort),
        _ => None,
    }
}

fn validate_config_text(text: &str) -> Result<AppConfig> {
    let config: AppConfig = Figment::new()
        .merge(Serialized::defaults(AppConfig::default()))
        .merge(Toml::string(text))
        .extract()
        .context("Failed to parse edited config")?;

    config.validate()?;
    Ok(config)
}

fn run_editor(path: &Path) -> Result<()> {
    let editor = std::env::var("EDITOR")
        .context("EDITOR is not set. Export EDITOR (for example: export EDITOR=nvim)")?;

    let mut parts = editor.split_whitespace();
    let cmd = parts
        .next()
        .context("EDITOR is empty. Set it to a valid editor command")?;

    let status = Command::new(cmd)
        .args(parts)
        .arg(path)
        .status()
        .with_context(|| format!("Failed to launch editor command `{editor}`"))?;

    anyhow::ensure!(status.success(), "Editor exited with status: {status}");
    Ok(())
}

fn config_text_for_edit(path: &Path) -> Result<String> {
    if path.exists() {
        fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file {}", path.display()))
    } else {
        defaults_toml()
    }
}

/// Edit the config file via $EDITOR (validates before persisting.)
pub(super) fn edit_config(path: &Path, no_retry: bool) -> Result<bool> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let interactive = std::io::stdin().is_terminal();

    edit_config_with_editor(
        path,
        no_retry,
        interactive,
        &mut input,
        &mut output,
        run_editor,
    )
}

fn edit_config_with_editor(
    path: &Path,
    no_retry: bool,
    interactive: bool,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    mut editor: impl FnMut(&Path) -> Result<()>,
) -> Result<bool> {
    let mut draft = config_text_for_edit(path)?;

    loop {
        let temp_path = temp_path_for(path);
        fs::write(&temp_path, &draft)
            .with_context(|| format!("Failed to write editor temp file {}", temp_path.display()))?;

        let edit_result = editor(&temp_path);
        let edited_text = fs::read_to_string(&temp_path).with_context(|| {
            format!(
                "Failed to read edited config from temporary file {}",
                temp_path.display()
            )
        })?;
        let _ = fs::remove_file(&temp_path);
        edit_result?;

        match validate_config_text(&edited_text) {
            Ok(config) => {
                let normalized = toml::to_string_pretty(&config)
                    .context("Failed to serialize updated config")?;
                atomic_write(path, &normalized)?;
                writeln!(output, "Config updated: {}", path.display())?;
                return Ok(true);
            }
            Err(err) => {
                writeln!(output, "Invalid config: {err}")?;

                if no_retry || !interactive {
                    return Err(err);
                }

                loop {
                    write!(
                        output,
                        "[e]dit again, [v]iew errors, [a]bort (default: a): "
                    )?;
                    output.flush()?;

                    let mut response = String::new();
                    input.read_line(&mut response)?;

                    match parse_retry_choice(&response) {
                        Some(RetryChoice::Edit) => {
                            draft = edited_text;
                            break;
                        }
                        Some(RetryChoice::View) => {
                            writeln!(output, "Invalid config: {err}")?;
                        }
                        Some(RetryChoice::Abort) => {
                            writeln!(output, "Edit aborted. Existing config unchanged.")?;
                            return Ok(false);
                        }
                        None => {
                            writeln!(output, "Invalid choice. Use e, v, or a.")?;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::edit_config_with_editor;
    use std::fs;
    use std::io::Cursor;

    fn write_text(path: &std::path::Path, text: &str) {
        fs::write(path, text).expect("write config")
    }

    #[test]
    fn edit_invalid_then_abort_keeps_original() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        write_text(&path, "[local]\nport = 7777\n");

        let mut input = Cursor::new(b"\n".to_vec());
        let mut output = Vec::new();
        let changed =
            edit_config_with_editor(&path, false, true, &mut input, &mut output, |temp_path| {
                fs::write(temp_path, "[local]\nconcurrency = 0\n").expect("write invalid config");
                Ok(())
            })
            .expect("edit flow should complete");

        assert!(!changed);
        let content = fs::read_to_string(&path).expect("read config");
        assert!(content.contains("port = 7777"));
    }

    #[test]
    fn edit_invalid_no_retry_fails_and_keeps_original() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        write_text(&path, "[local]\nport = 8888\n");

        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        let err =
            edit_config_with_editor(&path, true, true, &mut input, &mut output, |temp_path| {
                fs::write(temp_path, "[local]\nconcurrency = 0\n").expect("write invalid config");
                Ok(())
            })
            .expect_err("invalid config should fail with --no-retry");

        assert!(err.to_string().contains("concurrency"));
        let content = fs::read_to_string(&path).expect("read config");
        assert!(content.contains("port = 8888"));
    }

    #[test]
    fn edit_retry_then_valid_save_updates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        write_text(&path, "[local]\nport = 9000\n");

        let mut input = Cursor::new(b"e\n".to_vec());
        let mut output = Vec::new();
        let mut attempts = 0usize;
        let changed =
            edit_config_with_editor(&path, false, true, &mut input, &mut output, |temp_path| {
                attempts += 1;
                if attempts == 1 {
                    fs::write(temp_path, "[local]\nconcurrency = 0\n")
                        .expect("write invalid config");
                } else {
                    fs::write(temp_path, "[local]\nport = 4321\n").expect("write valid config");
                }
                Ok(())
            })
            .expect("edit should eventually succeed");

        assert!(changed);
        let content = fs::read_to_string(&path).expect("read config");
        assert!(content.contains("port = 4321"));
    }
}
