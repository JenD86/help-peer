mod account;
mod cancel;
mod crypto;
mod download;
mod erasure;
mod http;
mod manifest;
mod resume;
mod upload;
mod validator;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;

const DEFAULT_RELAY: &str = "http://127.0.0.1:7000";
const DEFAULT_NODES: &str = "http://127.0.0.1:7001";

#[derive(Parser)]
#[command(name = "helppeer")]
#[command(about = "Asynchronous ephemeral file transfer for AI model weights")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Relay server URL [default: $HELPEER_RELAY_URL, else the logged-in
    /// website's relay, else http://127.0.0.1:7000]
    #[arg(long, global = true)]
    relay: Option<String>,

    /// Storage node URLs, comma-separated [default: $HELPEER_STORAGE_NODES,
    /// else the logged-in website's nodes, else http://127.0.0.1:7001]
    #[arg(long, global = true)]
    nodes: Option<String>,

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

        /// Recipients, comma-separated: usernames (alice or @alice) get it in
        /// their inbox, email addresses get the code by email. Needs `login`.
        #[arg(long)]
        to: Option<String>,
    },
    /// Receive a file or directory using a code
    Receive {
        /// The transfer code (e.g., orbit-velvet-zoom-candle-harbor-ember)
        code: String,

        /// Output directory
        #[arg(long, default_value = "./received")]
        output: PathBuf,
    },
    /// Cancel a transfer before it expires, deleting it from the relay and storage nodes
    Cancel {
        /// The transfer code
        code: String,
    },
    /// List transfers sent to your username (needs `login`)
    Inbox,
    /// Log in to a Help Peer website with an API token (create one on its Account page)
    Login {
        /// Website URL, e.g. https://helppeer.example.com
        #[arg(long)]
        server: String,

        /// API token (hp_...)
        #[arg(long)]
        token: String,
    },
    /// Forget the saved login
    Logout,
}

/// Prints a result: JSON in --json mode, otherwise the human-readable text.
struct Output {
    json: bool,
}

impl Output {
    fn ok(&self, value: Value, human: impl FnOnce()) {
        if self.json {
            let mut v = json!({ "status": "ok" });
            if let (Some(obj), Value::Object(extra)) = (v.as_object_mut(), value) {
                obj.extend(extra);
            }
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        } else {
            human();
        }
    }

    fn fail(&self, what: &str, error: String) -> ! {
        if self.json {
            println!("{}", serde_json::to_string_pretty(&json!({ "status": "error", "error": error })).unwrap());
        } else {
            eprintln!("✗ {} failed: {}", what, error);
        }
        std::process::exit(1);
    }

    fn say(&self, line: &str) {
        if !self.json {
            println!("{}", line);
        }
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

/// Pick the relay and storage nodes: flags, then environment variables, then
/// the logged-in website's settings, then local defaults.
async fn resolve_servers(cli: &Cli, api: Option<&account::Api>) -> (String, Vec<String>) {
    let mut relay = cli.relay.clone().or_else(|| std::env::var("HELPEER_RELAY_URL").ok());
    let mut nodes = cli.nodes.clone().or_else(|| std::env::var("HELPEER_STORAGE_NODES").ok());

    if relay.is_none() || nodes.is_none() {
        if let Some(api) = api {
            match api.server_config().await {
                Ok((r, n)) => {
                    relay = relay.or(Some(r));
                    nodes = nodes.or(Some(n.join(",")));
                }
                Err(e) => eprintln!("warning: couldn't get server settings from the website ({}); using defaults", e),
            }
        }
    }

    (
        relay.unwrap_or_else(|| DEFAULT_RELAY.to_string()).trim_end_matches('/').to_string(),
        split_list(&nodes.unwrap_or_else(|| DEFAULT_NODES.to_string())),
    )
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let out = Output { json: cli.json };

    let client = match http::client() {
        Ok(c) => c,
        Err(e) => out.fail("Startup", e),
    };
    let api = account::load().map(|login| account::Api::new(client.clone(), login));

    match &cli.command {
        Commands::Send { path, name, to } => {
            let recipients = to.as_deref().map(split_list).unwrap_or_default();

            // Check recipients before uploading anything.
            if !recipients.is_empty() {
                let Some(api) = &api else {
                    out.fail("Send", "sending to recipients needs a login: run `helppeer login` first".into())
                };
                for r in recipients.iter().filter(|r| !account::is_email(r)) {
                    match api.username_exists(r).await {
                        Ok(true) => {}
                        Ok(false) => out.fail("Send", format!("unknown username: {}", r)),
                        Err(e) => out.fail("Send", e),
                    }
                }
            }

            let (relay, storage_nodes) = resolve_servers(&cli, api.as_ref()).await;
            out.say(&format!("Help Peer — Sending: {}", path.display()));
            out.say(&format!("Transfer name: {}", name));
            out.say(&format!("Relay: {}", relay));
            out.say(&format!("Storage nodes: {} (total)", storage_nodes.len()));
            out.say("");

            let config = upload::UploadConfig { storage_nodes, relay_url: relay };
            let (code, relay_hash, manifest) = match upload::upload_path(path, name, &config).await {
                Ok(r) => r,
                Err(e) => out.fail("Upload", e),
            };

            // Tell the recipients. The upload already succeeded, so a failure
            // here is reported but the code is still printed.
            let mut notified = Value::Null;
            let mut notify_error = None;
            if let (false, Some(api)) = (recipients.is_empty(), &api) {
                match api
                    .notify(&relay_hash, &code, name, manifest.files.len(), manifest.total_bytes, &recipients)
                    .await
                {
                    Ok(v) => notified = v,
                    Err(e) => notify_error = Some(e),
                }
            }

            out.ok(
                json!({
                    "code": code,
                    "transfer_name": name,
                    "path": path.display().to_string(),
                    "files": manifest.files.len(),
                    "total_bytes": manifest.total_bytes,
                    "recipients": recipients,
                    "notify_errors": notified["errors"].as_array().cloned().unwrap_or_default()
                        .into_iter().chain(notify_error.clone().map(Value::from)).collect::<Vec<_>>(),
                }),
                || {
                    println!();
                    println!("✓ Upload complete!");
                    println!();
                    println!("  Transfer code: {}", code);
                    println!();
                    if !recipients.is_empty() && notify_error.is_none() {
                        println!("  Sent to: {}", recipients.join(", "));
                        println!("  (usernames get it in their inbox; email addresses get the code by email)");
                    } else {
                        println!("  Share this code with the recipient.");
                    }
                    println!("  The data will be available for 24 hours.");
                    for e in notified["errors"].as_array().into_iter().flatten() {
                        println!("  warning: {}", e.as_str().unwrap_or_default());
                    }
                    if let Some(e) = &notify_error {
                        println!("  warning: couldn't notify recipients ({}); share the code yourself", e);
                    }
                },
            );
        }

        Commands::Receive { code, output } => {
            let (relay, _) = resolve_servers(&cli, api.as_ref()).await;
            out.say(&format!("Help Peer — Receiving into: {}", output.display()));
            out.say(&format!("Relay: {}", relay));
            out.say("");

            let result = match download::download_transfer(code, output, &relay).await {
                Ok(r) => r,
                Err(e) => out.fail("Download", e),
            };
            // If it was sent to our username, clear it from the inbox.
            if let Some(api) = &api {
                let _ = api.mark_received(&result.relay_hash).await;
            }

            let manifest = &result.manifest;
            let files: Vec<_> = manifest
                .files
                .iter()
                .zip(&result.file_hashes)
                .map(|(f, (_, hash))| json!({ "path": f.path, "size": f.size, "blake3": hash }))
                .collect();
            out.ok(
                json!({
                    "transfer_name": manifest.transfer_name,
                    "total_bytes": manifest.total_bytes,
                    "files": files,
                    "acknowledged": result.acknowledged,
                    "resumed_segments": result.resumed_segments,
                }),
                || {
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
                },
            );
        }

        Commands::Cancel { code } => {
            let (relay, _) = resolve_servers(&cli, api.as_ref()).await;
            let r = match cancel::cancel_transfer(code, &relay).await {
                Ok(r) => r,
                Err(e) => out.fail("Cancel", e),
            };
            out.ok(
                json!({
                    "transfer_name": r.transfer_name,
                    "shards_deleted": r.shards_deleted,
                    "shards_already_gone": r.shards_already_gone,
                    "shards_failed": r.shards_failed,
                }),
                || {
                    println!("✓ Transfer cancelled: {}", r.transfer_name);
                    println!(
                        "  Deleted {} shards ({} had already expired or been deleted)",
                        r.shards_deleted, r.shards_already_gone
                    );
                    if r.shards_failed > 0 {
                        println!(
                            "  {} shards could not be deleted (node unreachable, or the same data is shared with another transfer); they expire within 24 hours",
                            r.shards_failed
                        );
                    }
                },
            );
        }

        Commands::Inbox => {
            let Some(api) = &api else {
                out.fail("Inbox", "not logged in: run `helppeer login` first".into())
            };
            let items = match api.inbox().await {
                Ok(i) => i,
                Err(e) => out.fail("Inbox", e),
            };
            out.ok(json!({ "items": items }), || {
                if items.is_empty() {
                    println!("Nothing waiting for you.");
                }
                for item in &items {
                    let from = item["sender_username"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(|u| format!("@{}", u))
                        .unwrap_or_else(|| item["sender_email"].as_str().unwrap_or("?").to_string());
                    println!(
                        "{} — from {} ({} file(s), {} bytes, expires {})",
                        item["transfer_name"].as_str().unwrap_or("untitled"),
                        from,
                        item["files"],
                        item["total_bytes"],
                        item["expires_at"].as_str().unwrap_or("?"),
                    );
                    println!("  helppeer receive {}", item["code"].as_str().unwrap_or("?"));
                }
            });
        }

        Commands::Login { server, token } => {
            let login = account::Login { server: server.trim_end_matches('/').to_string(), token: token.clone() };
            let api = account::Api::new(client.clone(), login.clone());
            let (email, username) = match api.whoami().await {
                Ok(w) => w,
                Err(e) => out.fail("Login", e),
            };
            let path = match account::save(&login) {
                Ok(p) => p,
                Err(e) => out.fail("Login", e),
            };
            out.ok(
                json!({ "server": login.server, "email": email, "username": username, "config": path.display().to_string() }),
                || {
                    let who = if username.is_empty() { email.clone() } else { format!("{} (@{})", email, username) };
                    println!("✓ Logged in to {} as {}", login.server, who);
                    println!("  Saved to {}", path.display());
                },
            );
        }

        Commands::Logout => {
            let removed = match account::remove() {
                Ok(r) => r,
                Err(e) => out.fail("Logout", e),
            };
            out.ok(json!({ "was_logged_in": removed }), || {
                println!("{}", if removed { "✓ Logged out" } else { "Not logged in" });
            });
        }
    }
}
