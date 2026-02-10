use anyhow::{ensure, Context, Result};
use archdrop::{
    common::{config, config_commands, CliArgs, Manifest},
    server,
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
        Commands::Send { path, args } => {
            let config = config::load_config(&args)?;

            // collect all files
            let mut files_to_send = Vec::new();

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
                        files_to_send.push(entry.path().to_path_buf());
                    }
                } else {
                    files_to_send.push(file) // single file
                }
            }

            ensure!(!files_to_send.is_empty(), "No files to send");

            // Send needs to build a manifest of file metadata
            // to send to the receiver before download begins
            let transport = args.via.unwrap_or(config.default_transport);
            let transfer_settings = config.transfer_settings(transport);
            let manifest = Manifest::new(files_to_send, None, transfer_settings)
                .await
                .context("Failed to create manifest")?;

            server::start_send_server(manifest, transport, &config).await?;
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
