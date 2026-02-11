use anyhow::{ensure, Context, Result};
use archdrop::{
    common::{config, config_commands, CliArgs, Manifest},
    send, server,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use walkdir::WalkDir;

// Clap for CLI w/ arg parsing
#[derive(Parser)]
#[command(name = "archdrop")]
#[command(about = "Secure file transfer")]
struct Cli {
    // subcommands
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum ConfigAction {
    Path,
    Show,
    Edit {
        #[arg(long, help = "Do not prompt to retry after validation errors")]
        no_retry: bool,
    },
    Reset {
        #[arg(long, short = 'y', help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum Commands {
    Send {
        #[arg(required = true, help = "Files or directories to send")]
        path: Vec<PathBuf>,

        #[arg(long, help = "Zip inputs into a temporary archive before sending")]
        zip: bool,

        #[arg(
            long = "no-zip",
            conflicts_with = "zip",
            help = "Disable zip even when enabled in config"
        )]
        no_zip: bool,

        #[command(flatten)]
        args: CliArgs,
    },
    Receive {
        #[arg(default_value = ".", help = "Destination directory")]
        destination: PathBuf,

        #[command(flatten)]
        args: CliArgs,
    },
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var("TOKIO_CONSOLE").is_ok() {
        eprintln!("tokio-console enabled, listening on 127.0.0.1:6669");
        console_subscriber::init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info,reqwest=warn,hyper_util=warn")),
            )
            .init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            path,
            zip,
            no_zip,
            args,
        } => {
            let config = config::load_config(&args)?;
            let use_zip = resolve_zip_enabled(zip, no_zip, config.zip);

            // Best-effort cleanup: hard kill (SIGKILL) can leave temp zips behind.
            let mut temp_archive: Option<send::TempArchive> = None;

            // collect all files
            let files_to_send = if use_zip {
                let archive = send::create_temp_zip_archive(&path)?;
                let archive_path = archive.path().to_path_buf();
                temp_archive = Some(archive);
                vec![archive_path]
            } else {
                let mut files = Vec::new();
                for file in path {
                    // fail fast on no file
                    ensure!(file.exists(), "File not found: {}", file.display());

                    if file.is_dir() {
                        // Add files in dir recursively
                        // handle nested directories
                        for entry in WalkDir::new(&file)
                            .into_iter()
                            .filter_map(|e| e.ok())
                            .filter(|e| e.path().is_file())
                        {
                            files.push(entry.path().to_path_buf());
                        }
                    } else {
                        files.push(file); // single file
                    }
                }
                files
            };

            ensure!(!files_to_send.is_empty(), "No files to send");

            // Send needs to build a manifest of file metadata
            // to send to the receiver before download begins
            let transport = args.via.unwrap_or(config.default_transport);
            let transfer_settings = config.transfer_settings(transport);
            let manifest = Manifest::new(files_to_send, None, transfer_settings)
                .await
                .context("Failed to create manifest")?;

            server::start_send_server(manifest, transport, &config).await?;

            drop(temp_archive);
        }
        Commands::Receive { destination, args } => {
            let config = config::load_config(&args)?;

            if !destination.exists() {
                tokio::fs::create_dir_all(&destination)
                    .await
                    .context(format!("Cannot create directory {}", destination.display()))?;
            }

            ensure!(
                destination.is_dir(),
                "{} is not a directory",
                destination.display()
            );

            let transport = args.via.unwrap_or(config.default_transport);

            server::start_receive_server(destination, transport, &config)
                .await
                .context("Failed to start file receiver")?;
        }
        Commands::Config { action } => match action {
            ConfigAction::Path => {
                config_commands::run_config_path()?;
            }
            ConfigAction::Show => {
                config_commands::run_config_show()?;
            }
            ConfigAction::Edit { no_retry } => {
                let _ = config_commands::run_config_edit(no_retry)?;
            }
            ConfigAction::Reset { yes } => {
                let _ = config_commands::run_config_reset(yes)?;
            }
        },
    }
    Ok(())
}

fn resolve_zip_enabled(zip: bool, no_zip: bool, config_zip: bool) -> bool {
    if no_zip {
        false
    } else if zip {
        true
    } else {
        config_zip
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_zip_enabled, Cli, Commands};
    use clap::Parser;

    #[test]
    fn send_zip_flag_parses() {
        let cli = Cli::parse_from(["archdrop", "send", "--zip", "file.txt"]);
        match cli.command {
            Commands::Send { zip, no_zip, .. } => {
                assert!(zip);
                assert!(!no_zip);
            }
            _ => panic!("expected send command"),
        }
    }

    #[test]
    fn send_zip_flag_defaults_false() {
        let cli = Cli::parse_from(["archdrop", "send", "file.txt"]);
        match cli.command {
            Commands::Send { zip, no_zip, .. } => {
                assert!(!zip);
                assert!(!no_zip);
            }
            _ => panic!("expected send command"),
        }
    }

    #[test]
    fn send_no_zip_flag_parses() {
        let cli = Cli::parse_from(["archdrop", "send", "--no-zip", "file.txt"]);
        match cli.command {
            Commands::Send { zip, no_zip, .. } => {
                assert!(!zip);
                assert!(no_zip);
            }
            _ => panic!("expected send command"),
        }
    }

    #[test]
    fn no_zip_overrides_config_zip_true() {
        assert!(!resolve_zip_enabled(false, true, true));
    }
}
