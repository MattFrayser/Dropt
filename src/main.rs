mod server;
use archdrop::crypto::test_encryption;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

// Clap reads this struct and creates CLI 
#[derive(Parser)] // generates arg parsing code at compile time
#[command(name = "archdrop")] // name in --help
#[command(about = "Secure file transfer")] // desc in --help
struct Cli {
    // subcommands
    #[command(subcommand)] 
    command: Commands,
}


// set a enum for possible future commands
#[derive(Subcommand)]
enum Commands {

    Send {
        #[arg(help = "Path to file to send")]
        file: PathBuf, // PathBuf for typesafe paths 
    },
}


#[tokio::main]
async fn main() {
    
    test_encryption();
    // Reads std::env::args(), matches against struct def
    let cli = Cli::parse();

    match cli.command {
        Commands::Send { file } => {

            // PathBuf.exits(); Check for file before spinning up
            // fail fast on no file
            if !file.exists() {
                // file.display() formats paths
                eprintln!("Error: File not found: {}", file.display());
                std::process::exit(1);

            }
            
            println!("Sending: {}", file.display());

            //server::start_server().await.unwrap();
        }
    }
}
