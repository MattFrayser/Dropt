use anyhow::{ensure, Context, Result};
use archdrop::{
    server::{start_receive_server, start_send_server, ServerMode},
    transfer::manifest::Manifest,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use walkdir::WalkDir;

// Clap for CLI w/ arg parsing
#[derive(Parser)]
#[command(name = "archdrop")] // name in --help
#[command(about = "Secure file transfer")] // desc in --help
struct Cli {
    // subcommands
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Send {
        #[arg(help = "Path to file to send")]
        paths: Vec<PathBuf>,

        #[arg(long, help = "Use HTTPS with self-signed cert. (Faster)")]
        local: bool,
    },
    Receive {
        #[arg(default_value = ".", help = "Destination directory")]
        destination: PathBuf,

        #[arg(long)]
        local: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // log tracing, default to info
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Send { paths, local } => {
            // collect all files
            let mut files_to_send = Vec::new();

            for path in paths {
                // fail fast on no file
                ensure!(path.exists(), "File not found: {}", path.display());

                if path.is_dir() {
                    // Add files in dir recursively
                    // handle nested directories
                    for entry in WalkDir::new(&path)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().is_file())
                    {
                        files_to_send.push(entry.path().to_path_buf());
                    }
                } else {
                    files_to_send.push(path) // single file
                }
            }

            ensure!(!files_to_send.is_empty(), "No files to send");

            let manifest = Manifest::new(files_to_send, None)
                .await
                .context("Failed to create manifest")?;

            // handle local flag
            let mode = if local {
                ServerMode::Local
            } else {
                ServerMode::Tunnel
            };

            //  Start server with mode
            start_send_server(manifest, mode).await?;
        }
        Commands::Receive { destination, local } => {
            // check dir location exits
            if !destination.exists() {
                tokio::fs::create_dir_all(&destination)
                    .await
                    .context(format!("Cannot create directory {}", destination.display()))?;
            }

            // Verify its a dir
            ensure!(
                destination.is_dir(),
                "{} is not a directory",
                destination.display()
            );

            // handle local flag
            let mode = if local {
                ServerMode::Local
            } else {
                ServerMode::Tunnel
            };

            //  Start server with mode
            start_receive_server(destination, mode)
                .await
                .context("Failed to start file receiver")?;
        }
    }
    Ok(())
}
