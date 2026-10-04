use std::path::Path;
use tokio::fs;

use crate::crypto;
use crate::erasure;
use crate::manifest::Manifest;
use crate::validator::ValidatorRegistry;

/// Download and reconstruct a transfer using a code.
pub async fn download_transfer(
    code: &str,
    output_dir: &Path,
    relay_url: &str,
) -> Result<Manifest, String> {
    let (k_data, k_index) = crypto::derive_keys(code);
    let relay_hash = crypto::relay_hash(&k_index);

    // Download encrypted manifest from relay
    let encrypted_manifest = download_manifest(relay_url, &relay_hash).await?;

    // Decrypt manifest
    let manifest_json = crypto::decrypt_segment(&k_data, &encrypted_manifest)?;
    let manifest = Manifest::from_json(&manifest_json)?;

    // Pre-allocate files
    preallocate_files(&manifest, output_dir)?;

    // Download and reconstruct each file
    let registry = ValidatorRegistry::new();

    for file in &manifest.files {
        let file_path = output_dir.join(&file.path);

        // Ensure parent directory exists
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| format!("mkdir failed: {}", e))?;
        }

        for (seg_idx, segment) in file.segments.iter().enumerate() {
            // Download shards for this segment
            let shard_data = download_shards_for_segment(segment).await?;

            // Reconstruct the encrypted segment
            let encrypted = erasure::decode_segment(shard_data, segment.encrypted_size)?;

            // Decrypt
            let plaintext = crypto::decrypt_segment(&k_data, &encrypted)?;

            // Validate first segment if applicable
            if seg_idx == 0 {
                let validator = registry.validator_for(&file.path);
                validator.validate_first_segment(&plaintext).map_err(|e| {
                    format!("validation failed for {}: {}", file.path, e)
                })?;
            }

            // Write to file at the correct offset
            let offset = seg_idx * crypto::SEGMENT_SIZE;
            write_segment_at_offset(&file_path, offset, &plaintext)?;
        }

        // Print hash for verification
        let hash = compute_file_hash(&file_path)?;
        println!("  {} → {}", file.path, hash);
    }

    Ok(manifest)
}

/// Download the encrypted manifest from the relay (one-time retrieval).
async fn download_manifest(relay_url: &str, relay_hash: &str) -> Result<Vec<u8>, String> {
    let url = format!("{}/manifest/{}", relay_url, relay_hash);
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("manifest download failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("manifest download returned status {}", resp.status()));
    }

    let data = resp
        .bytes()
        .await
        .map_err(|e| format!("failed to read manifest body: {}", e))?;

    Ok(data.to_vec())
}

/// Download all shards for a segment. Returns 12 Option<Vec<u8>> entries.
async fn download_shards_for_segment(
    segment: &crate::manifest::ManifestSegment,
) -> Result<Vec<Option<Vec<u8>>>, String> {
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; crate::crypto::TOTAL_SHARDS];

    let mut tasks = Vec::new();

    for shard in &segment.shards {
        let hash = shard.hash.clone();
        let node = shard.node.clone();
        let index = shard.index as usize;

        tasks.push(tokio::spawn(async move {
            let url = format!("{}/shard/{}", node, hash);
            let resp = reqwest::get(&url).await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    let data = r.bytes().await.ok();
                    data.map(|b| (index, b.to_vec()))
                }
                _ => None,
            }
        }));
    }

    for task in tasks {
        if let Ok(Some((index, data))) = task.await {
            shards[index] = Some(data);
        }
    }

    Ok(shards)
}

/// Pre-allocate all files with the correct sizes (zero-filled).
fn preallocate_files(manifest: &Manifest, output_dir: &Path) -> Result<(), String> {
    for file in &manifest.files {
        let file_path = output_dir.join(&file.path);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {}", e))?;
        }
        let f = std::fs::File::create(&file_path).map_err(|e| format!("create failed: {}", e))?;
        f.set_len(file.size).map_err(|e| format!("set_len failed: {}", e))?;
    }
    Ok(())
}

/// Write a segment at a specific offset in a file.
fn write_segment_at_offset(path: &Path, offset: usize, data: &[u8]) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open for write failed: {}", e))?;

    file.seek(SeekFrom::Start(offset as u64))
        .map_err(|e| format!("seek failed: {}", e))?;
    file.write_all(data).map_err(|e| format!("write failed: {}", e))?;
    Ok(())
}

/// Compute BLAKE3 hash of a file for verification.
fn compute_file_hash(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| format!("open failed: {}", e))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("read failed: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize().as_bytes()))
}
