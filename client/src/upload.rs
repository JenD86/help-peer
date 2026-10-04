use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tokio::task::JoinSet;

use crate::crypto;
use crate::erasure;
use crate::http;
use crate::manifest::{self, Manifest, ManifestShard};

/// Configuration for the upload pipeline.
pub struct UploadConfig {
    pub storage_nodes: Vec<String>,
    pub relay_url: String,
}

/// Upload a file or directory to the network.
/// Returns the transfer code, its relay hash, and the manifest that was sent.
pub async fn upload_path(
    path: &Path,
    transfer_name: &str,
    config: &UploadConfig,
) -> Result<(String, String, Manifest), String> {
    if config.storage_nodes.is_empty() {
        return Err("no storage nodes configured".into());
    }
    let shards_per_node = (crypto::TOTAL_SHARDS + config.storage_nodes.len() - 1) / config.storage_nodes.len();
    if shards_per_node > crypto::PARITY_SHARDS {
        eprintln!(
            "warning: with {} storage node(s), each holds up to {} of {} shards per segment; \
             losing a single node makes the transfer unrecoverable (use at least {} nodes)",
            config.storage_nodes.len(),
            shards_per_node,
            crypto::TOTAL_SHARDS,
            (crypto::TOTAL_SHARDS + crypto::PARITY_SHARDS - 1) / crypto::PARITY_SHARDS,
        );
    }

    let client = http::client()?;

    // Generate a transfer code
    let code = generate_code();
    let (k_data, k_index) = crypto::derive_keys(&code);
    let relay_hash = crypto::relay_hash(&k_index);

    // Build the initial manifest (without shard info)
    let (mut manifest, base_dir) = Manifest::build(path, transfer_name)?;
    let segment_size = manifest.segment_size as usize;
    manifest.ack_secret = crypto::new_secret();
    manifest.delete_token = crypto::new_secret();
    let delete_token_hash = crypto::secret_hash(&manifest.delete_token);

    // Nodes that failed during this transfer; their shards go to the others.
    let nodes = Arc::new(config.storage_nodes.clone());
    let dead_nodes: Arc<Mutex<HashSet<usize>>> = Arc::default();

    // Process each file
    for file in manifest.files.iter_mut() {
        let file_path = base_dir.join(&file.path);
        let mut file_hasher = blake3::Hasher::new();

        for (seg_idx, segment) in file.segments.iter_mut().enumerate() {
            // Read the segment
            let plaintext = manifest::read_file_segment(&file_path, seg_idx, segment_size)?;
            if plaintext.len() != segment.original_size {
                return Err(format!("{} changed size while being sent", file.path));
            }
            file_hasher.update(&plaintext);

            // Encrypt
            let encrypted = crypto::encrypt_segment(&k_data, &plaintext);

            // Erasure code
            let shards = erasure::encode_segment(&encrypted)?;

            // Upload the shards in parallel (round-robin node assignment)
            let mut tasks = JoinSet::new();
            for (shard_idx, shard) in shards.into_iter().enumerate() {
                let client = client.clone();
                let nodes = nodes.clone();
                let dead_nodes = dead_nodes.clone();
                let delete_token_hash = delete_token_hash.clone();
                tasks.spawn(async move {
                    let hash = crypto::content_hash(&shard);
                    let node = upload_shard_with_failover(
                        &client, &nodes, &dead_nodes, shard_idx, &hash, &shard, &delete_token_hash,
                    )
                    .await?;
                    Ok::<_, String>(ManifestShard {
                        index: shard_idx as u8,
                        hash,
                        node,
                    })
                });
            }

            let mut shard_infos = Vec::with_capacity(crypto::TOTAL_SHARDS);
            while let Some(result) = tasks.join_next().await {
                shard_infos.push(result.map_err(|e| format!("shard upload task failed: {}", e))??);
            }
            shard_infos.sort_by_key(|s| s.index);

            // Update manifest with shard info
            segment.encrypted_size = encrypted.len();
            segment.shards = shard_infos;
        }

        file.blake3 = Some(hex::encode(file_hasher.finalize().as_bytes()));
    }

    let failed: Vec<&str> = dead_nodes.lock().unwrap().iter().map(|&i| nodes[i].as_str()).collect();
    if !failed.is_empty() {
        eprintln!(
            "warning: storage node(s) {} failed; their shards were stored on the remaining nodes, \
             so this transfer tolerates fewer node failures",
            failed.join(", ")
        );
    }

    // Encrypt and upload the manifest to the relay
    let manifest_json = manifest.to_json()?;
    let encrypted_manifest = crypto::encrypt_segment(&k_data, &manifest_json);
    let url = format!("{}/manifest/{}", config.relay_url, relay_hash);
    let ack_hash = crypto::secret_hash(&manifest.ack_secret);
    http::put(&client, &url, &encrypted_manifest, &[("X-Ack-Hash", &ack_hash)], "manifest upload").await?;

    Ok((code, relay_hash, manifest))
}

/// Upload a shard to its round-robin node, falling back to the next healthy
/// node if that one fails. Returns the URL of the node that stored it.
async fn upload_shard_with_failover(
    client: &reqwest::Client,
    nodes: &[String],
    dead_nodes: &Mutex<HashSet<usize>>,
    shard_idx: usize,
    hash: &str,
    shard: &[u8],
    delete_token_hash: &str,
) -> Result<String, String> {
    let mut last_err = String::from("all storage nodes have failed");
    for offset in 0..nodes.len() {
        let i = (shard_idx + offset) % nodes.len();
        if dead_nodes.lock().unwrap().contains(&i) {
            continue;
        }
        let url = format!("{}/shard/{}", nodes[i], hash);
        let headers = [("X-Delete-Token-Hash", delete_token_hash)];
        match http::put(client, &url, shard, &headers, &format!("shard upload to {}", nodes[i])).await {
            Ok(()) => return Ok(nodes[i].clone()),
            Err(e) => {
                dead_nodes.lock().unwrap().insert(i);
                last_err = e;
            }
        }
    }
    Err(last_err)
}

/// Number of words in a transfer code. Each word from the 7776-word EFF
/// list adds ~12.9 bits, so 6 words gives ~77 bits. The code is the only
/// secret (there is no PAKE in an async transfer), so it must resist offline
/// brute force and enumeration of the relay.
pub const CODE_WORDS: usize = 6;

const WORDLIST: &str = include_str!("../../protocol/wordlist.txt");

/// Generate a human-readable transfer code: word-word-word-word-word-word
fn generate_code() -> String {
    use rand::seq::SliceRandom;
    // OsRng: draw the secret straight from the operating system CSPRNG.
    let mut rng = rand::rngs::OsRng;
    let words: Vec<&str> = WORDLIST.lines().collect();

    (0..CODE_WORDS)
        .map(|_| *words.choose(&mut rng).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_size() {
        assert_eq!(WORDLIST.lines().count(), 7776);
    }

    #[test]
    fn test_generate_code_format() {
        let code = generate_code();
        let words: Vec<&str> = code.split('-').collect();
        assert_eq!(words.len(), CODE_WORDS);
        assert!(words.iter().all(|w| WORDLIST.lines().any(|l| l == *w)));
        assert_ne!(code, generate_code());
    }
}
