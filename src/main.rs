use archdrop::output;
use archdrop::server::{self, ServerMode};
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;

// Clap reads this struct and creates CLI
#[derive(Parser)] // generates arg parsing code at compile time
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
        path: PathBuf, // PathBuf for typesafe paths

        #[arg(long, help = "Use HTPS with self-signed cert. (Faster)")]
        local: bool,

        #[arg(
            long,
            help = "Use HTTP. Downloads may not work on all devices. (Fastest)"
        )]
        http: bool,
    },
    Recieve {
        #[arg(default_value = ".", help = "Destination directory")]
        destination: PathBuf,

        #[arg(long)]
        local: bool,

        #[arg(long)]
        http: bool,
    },
}

#[tokio::main]
async fn main() {
    // Reads std::env::args(), matches against struct def
    let cli = Cli::parse();

    match cli.command {
        Commands::Send { path, local, http } => {
            // PathBuf.exits(); Check for file before spinning up
            // fail fast on no file
            if !path.exists() {
                // file.display() formats paths
                output::error(&format!("File not found: {}", path.display()));
                std::process::exit(1);
            }

            // handle local flag
            let mode = if local {
                ServerMode::Local
            } else if http {
                ServerMode::Http
            } else {
                ServerMode::Tunnel
            };

            // Handle folder
            let (file_to_send, cleanup_path) = if path.is_dir() {
                let zip_path = create_zip_from_dir(&path).await.unwrap();
                (zip_path.clone(), Some(zip_path))
            } else {
                // singe file
                (path, None)
            };

            //  Start server with mode
            match server::start_server(file_to_send, mode, server::ServerDirection::Send).await {
                Ok(_) => {}
                Err(e) => {
                    output::error(&format!("{}", e));
                    std::process::exit(1);
                }
            }

            // cleanup temp zip
            if let Some(temp_path) = cleanup_path {
                let _ = tokio::fs::remove_file(temp_path).await;
            }
        }
        Commands::Recieve {
            destination,
            local,
            http,
        } => {
            // check dir location exits
            if !destination.exists() {
                if let Err(e) = tokio::fs::create_dir_all(&destination).await {
                    output::error(&format!(
                        "Cannot create directory {}: {}",
                        destination.display(),
                        e
                    ));
                    std::process::exit(1);
                }
            }

            // Verify its a dir
            if !destination.is_dir() {
                output::error(&format!("{} is not a directory", destination.display()));
                std::process::exit(1);
            }

            // handle local flag
            let mode = if local {
                ServerMode::Local
            } else if http {
                ServerMode::Http
            } else {
                ServerMode::Tunnel
            };

            //  Start server with mode
            match server::start_server(destination, mode, server::ServerDirection::Recieve).await {
                Ok(_) => {}
                Err(e) => {
                    output::error(&format!("{}", e));
                    std::process::exit(1);
                }
            }
        }
    }
}

async fn create_zip_from_dir(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("archive");

    let temp_dir = std::env::temp_dir();
    let zip_path = temp_dir.join(format!("{}.zip", dir_name));

    let file = File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path.strip_prefix(dir)?;

        if path.is_file() {
            zip.start_file(name.to_string_lossy().to_string(), options)?;
            let contents = std::fs::read(path)?;
            zip.write_all(&contents)?;
        } else if !name.as_os_str().is_empty() {
            zip.add_directory(name.to_string_lossy().to_string(), options)?;
        }
    }

    zip.finish()?;
    Ok(zip_path)
}
