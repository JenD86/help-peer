use std::path::Path;

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
/// Returns the transfer code and the manifest that was sent.
pub async fn upload_path(
    path: &Path,
    transfer_name: &str,
    config: &UploadConfig,
) -> Result<(String, Manifest), String> {
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
                let hash = crypto::content_hash(&shard);
                let node = config.storage_nodes[shard_idx % config.storage_nodes.len()].clone();
                let client = client.clone();
                tasks.spawn(async move {
                    let url = format!("{}/shard/{}", node, hash);
                    http::put(&client, &url, &shard, &[], &format!("shard upload to {}", node)).await?;
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

    // Encrypt and upload the manifest to the relay
    let manifest_json = manifest.to_json()?;
    let encrypted_manifest = crypto::encrypt_segment(&k_data, &manifest_json);
    let url = format!("{}/manifest/{}", config.relay_url, relay_hash);
    http::put(&client, &url, &encrypted_manifest, &[], "manifest upload").await?;

    Ok((code, manifest))
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
