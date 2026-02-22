use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use dropt::{
    common::{CollisionPolicy, ConfigOverrides, Manifest, Transport, config, config_commands},
    send, server,
};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use walkdir::WalkDir;

// Clap for CLI w/ arg parsing
#[derive(Parser)]
#[command(name = "dropt")]
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

        #[arg(
            long = "conflict",
            short = 'C',
            value_enum,
            help = "File collision policy (default: suffix)"
        )]
        conflict: Option<CliCollisionPolicy>,

        #[command(flatten)]
        args: CliArgs,
    },
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

// CLI mirror type for CollisionPolicy.
// Keeps clap out of the lib crate: lib = serde only, binary = clap only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliCollisionPolicy {
    Suffix,
    Overwrite,
    Skip,
}

impl From<CliCollisionPolicy> for CollisionPolicy {
    fn from(value: CliCollisionPolicy) -> Self {
        match value {
            CliCollisionPolicy::Suffix => CollisionPolicy::Suffix,
            CliCollisionPolicy::Overwrite => CollisionPolicy::Overwrite,
            CliCollisionPolicy::Skip => CollisionPolicy::Skip,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliTransport {
    Local,
    Cloudflare,
    Tailscale,
}

impl From<CliTransport> for Transport {
    fn from(value: CliTransport) -> Self {
        match value {
            CliTransport::Local => Transport::Local,
            CliTransport::Cloudflare => Transport::Cloudflare,
            CliTransport::Tailscale => Transport::Tailscale,
        }
    }
}

/// Command line arguments shared between Send and Recieve
#[derive(Args, Debug, Clone, Default)]
struct CliArgs {
    /// Transport method (overrides config default)
    #[arg(long, value_enum)]
    via: Option<CliTransport>,

    /// Port override for the selected/default transport (0 = auto-assign)
    #[arg(long)]
    port: Option<u16>,
}

impl From<&CliArgs> for ConfigOverrides {
    fn from(args: &CliArgs) -> Self {
        Self {
            transport: args.via.map(Into::into),
            port: args.port,
        }
    }
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
            let overrides = ConfigOverrides::from(&args);
            let config = config::apply_overrides(config::load_config()?, &overrides);
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
                        let mut skipped = Vec::new();
                        for entry in WalkDir::new(&file) {
                            match entry {
                                Ok(e) if e.path().is_file() => {
                                    files.push(e.path().to_path_buf());
                                }
                                Ok(_) => {} // directory entry, skip
                                Err(e) => {
                                    skipped.push(format!(
                                        "  {}",
                                        e.path()
                                            .map(|p| p.display().to_string())
                                            .unwrap_or_else(|| e.to_string())
                                    ));
                                }
                            }
                        }
                        if !skipped.is_empty() {
                            eprintln!(
                                "Warning: skipped {} path(s) due to errors:\n{}",
                                skipped.len(),
                                skipped.join("\n")
                            );
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
            let transport = overrides.transport.unwrap_or(config.default_transport);
            let transfer_settings = config.transfer_settings(transport);
            let manifest = Manifest::new(files_to_send, None, transfer_settings)
                .await
                .context("Failed to create manifest")?;

            server::start_send_server(manifest, transport, &config).await?;

            drop(temp_archive);
        }
        Commands::Receive {
            destination,
            conflict,
            args,
        } => {
            let overrides = ConfigOverrides::from(&args);
            let config = config::apply_overrides(config::load_config()?, &overrides);

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

            let transport = overrides.transport.unwrap_or(config.default_transport);
            let collision_policy = conflict.map(Into::into).unwrap_or(config.on_conflict);

            server::start_receive_server(destination, transport, collision_policy, &config)
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
    use super::{Cli, Commands, resolve_zip_enabled};
    use clap::Parser;

    #[test]
    fn send_zip_flag_parses() {
        let cli = Cli::parse_from(["dropt", "send", "--zip", "file.txt"]);
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
        let cli = Cli::parse_from(["dropt", "send", "file.txt"]);
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
        let cli = Cli::parse_from(["dropt", "send", "--no-zip", "file.txt"]);
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
