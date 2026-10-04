use std::path::Path;

use crate::crypto;
use crate::erasure;
use crate::manifest::{self, Manifest, ManifestShard};

/// Configuration for the upload pipeline.
pub struct UploadConfig {
    pub storage_nodes: Vec<String>,
    pub relay_url: String,
}

/// Upload a directory to the network.
/// Returns the transfer code and relay hash.
pub async fn upload_directory(
    dir: &Path,
    transfer_name: &str,
    config: &UploadConfig,
) -> Result<(String, String), String> {
    // Generate a transfer code
    let code = generate_code();
    let (k_data, k_index) = crypto::derive_keys(&code);
    let relay_hash = crypto::relay_hash(&k_index);

    // Build the initial manifest (without shard info)
    let mut manifest = Manifest::build_from_dir(dir, transfer_name)?;

    // Process each file
    for file_idx in 0..manifest.files.len() {
        let file_path = dir.join(&manifest.files[file_idx].path);
        let num_segments = manifest.files[file_idx].segments.len();

        for seg_idx in 0..num_segments {
            // Read the segment
            let plaintext = manifest::read_file_segment(&file_path, seg_idx)?;

            // Encrypt
            let encrypted = crypto::encrypt_segment(&k_data, &plaintext);

            // Erasure code
            let shards = erasure::encode_segment(&encrypted)?;

            // Upload shards to storage nodes (round-robin assignment)
            let mut shard_infos = Vec::with_capacity(shards.len());
            for (shard_idx, shard) in shards.iter().enumerate() {
                let hash = crypto::content_hash(shard);
                let node = &config.storage_nodes[shard_idx % config.storage_nodes.len()];

                upload_shard(node, &hash, shard).await?;

                shard_infos.push(ManifestShard {
                    index: shard_idx as u8,
                    hash,
                    node: node.clone(),
                });
            }

            // Update manifest with shard info
            manifest.files[file_idx].segments[seg_idx].encrypted_size = encrypted.len();
            manifest.files[file_idx].segments[seg_idx].shards = shard_infos;
        }
    }

    // Encrypt and upload the manifest to the relay
    let manifest_json = manifest.to_json()?;
    let encrypted_manifest = crypto::encrypt_segment(&k_data, &manifest_json);
    upload_manifest(&config.relay_url, &relay_hash, &encrypted_manifest).await?;

    Ok((code, relay_hash))
}

/// Upload a single shard to a storage node.
async fn upload_shard(node_url: &str, hash: &str, data: &[u8]) -> Result<(), String> {
    let url = format!("{}/shard/{}", node_url, hash);
    let client = reqwest::Client::new();

    let resp = client
        .put(&url)
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec())
        .send()
        .await
        .map_err(|e| format!("shard upload failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "shard upload to {} returned status {}",
            node_url,
            resp.status()
        ));
    }

    Ok(())
}

/// Upload the encrypted manifest to the relay.
async fn upload_manifest(relay_url: &str, relay_hash: &str, data: &[u8]) -> Result<(), String> {
    let url = format!("{}/manifest/{}", relay_url, relay_hash);
    let client = reqwest::Client::new();

    let resp = client
        .put(&url)
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec())
        .send()
        .await
        .map_err(|e| format!("manifest upload failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "manifest upload returned status {}",
            resp.status()
        ));
    }

    Ok(())
}

/// Generate a human-readable transfer code: number-word-word
fn generate_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let num: u8 = rng.gen_range(1..=99);

    let words = [
        "orbit", "velvet", "guitar", "battery", "candle", "dragon", "ember",
        "falcon", "galaxy", "harbor", "iris", "jungle", "kettle", "lantern",
        "meadow", "nebula", "ocean", "phoenix", "quartz", "raven", "silver",
        "thunder", "umbra", "vortex", "willow", "xenon", "yonder", "zephyr",
        "amber", "breeze",
    ];
    let w1 = words[rng.gen_range(0..words.len())];
    let w2 = words[rng.gen_range(0..words.len())];

    format!("{}-{}-{}", num, w1, w2)
}
