mod crypto;
mod download;
mod erasure;
mod http;
mod manifest;
mod resume;
mod upload;
mod validator;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "helppeer")]
#[command(about = "Asynchronous ephemeral file transfer for AI model weights")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Relay server URL
    #[arg(long, global = true, default_value = "http://127.0.0.1:7000")]
    relay: String,

    /// Storage node URLs (comma-separated)
    #[arg(long, global = true, default_value = "http://127.0.0.1:7001")]
    nodes: String,

    /// Output machine-readable JSON instead of human text
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file or directory
    Send {
        /// Path to the file or directory to send
        path: PathBuf,

        /// Name for this transfer
        #[arg(long, default_value = "untitled-transfer")]
        name: String,
    },
    /// Receive a file or directory using a code
    Receive {
        /// The transfer code (e.g., orbit-velvet-zoom-candle-harbor-ember)
        code: String,

        /// Output directory
        #[arg(long, default_value = "./received")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let storage_nodes: Vec<String> = cli
        .nodes
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    match cli.command {
        Commands::Send { path, name } => {
            if !cli.json {
                println!("Help Peer — Sending: {}", path.display());
                println!("Transfer name: {}", name);
                println!("Relay: {}", cli.relay);
                println!("Storage nodes: {} (total)", storage_nodes.len());
                println!();
            }

            let config = upload::UploadConfig {
                storage_nodes: storage_nodes.clone(),
                relay_url: cli.relay.clone(),
            };

            match upload::upload_path(&path, &name, &config).await {
                Ok((code, manifest)) => {
                    if cli.json {
                        let json = serde_json::json!({
                            "status": "ok",
                            "code": code,
                            "transfer_name": name,
                            "path": path.display().to_string(),
                            "files": manifest.files.len(),
                            "total_bytes": manifest.total_bytes,
                        });
                        println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    } else {
                        println!();
                        println!("✓ Upload complete!");
                        println!();
                        println!("  Transfer code: {}", code);
                        println!();
                        println!("  Share this code with the recipient.");
                        println!("  The data will be available for 24 hours.");
                    }
                }
                Err(e) => {
                    if cli.json {
                        let json = serde_json::json!({
                            "status": "error",
                            "error": e,
                        });
                        println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    } else {
                        eprintln!("✗ Upload failed: {}", e);
                    }
                    std::process::exit(1);
                }
            }
        }
        Commands::Receive { code, output } => {
            if !cli.json {
                println!("Help Peer — Receiving with code: {}", code);
                println!("Output directory: {}", output.display());
                println!("Relay: {}", cli.relay);
                println!();
            }

            match download::download_transfer(&code, &output, &cli.relay).await {
                Ok(result) => {
                    let manifest = result.manifest;
                    if cli.json {
                        let files: Vec<_> = manifest
                            .files
                            .iter()
                            .zip(&result.file_hashes)
                            .map(|(f, (_, hash))| {
                                serde_json::json!({
                                    "path": f.path,
                                    "size": f.size,
                                    "blake3": hash,
                                })
                            })
                            .collect();
                        let json = serde_json::json!({
                            "status": "ok",
                            "transfer_name": manifest.transfer_name,
                            "total_bytes": manifest.total_bytes,
                            "files": files,
                            "acknowledged": result.acknowledged,
                        });
                        println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    } else {
                        println!();
                        println!("✓ Download complete!");
                        println!();
                        println!("  Transfer: {}", manifest.transfer_name);
                        println!("  Files: {}", manifest.files.len());
                        println!("  Total size: {} bytes", manifest.total_bytes);
                        println!();
                        println!("  File hashes (BLAKE3, verified against sender):");
                        for (path, hash) in &result.file_hashes {
                            println!("  {} → {}", path, hash);
                        }
                    }
                }
                Err(e) => {
                    if cli.json {
                        let json = serde_json::json!({
                            "status": "error",
                            "error": e,
                        });
                        println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    } else {
                        eprintln!("✗ Download failed: {}", e);
                    }
                    std::process::exit(1);
                }
            }
        }
    }
}
