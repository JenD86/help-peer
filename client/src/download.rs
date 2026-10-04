use std::path::{Path, PathBuf};

use reqwest::Client;
use tokio::task::JoinSet;

use crate::crypto;
use crate::erasure;
use crate::http;
use crate::manifest::{self, Manifest, ManifestSegment};
use crate::validator::ValidatorRegistry;

/// A completed download: the manifest and each file's BLAKE3 hash.
pub struct DownloadResult {
    pub manifest: Manifest,
    pub file_hashes: Vec<(String, String)>,
}

/// Download and reconstruct a transfer using a code.
pub async fn download_transfer(
    code: &str,
    output_dir: &Path,
    relay_url: &str,
) -> Result<DownloadResult, String> {
    let client = http::client()?;
    let (k_data, k_index) = crypto::derive_keys(code);
    let relay_hash = crypto::relay_hash(&k_index);

    // Download encrypted manifest from relay (one-time retrieval)
    let url = format!("{}/manifest/{}", relay_url, relay_hash);
    let encrypted_manifest = http::get(&client, &url, "manifest download")
        .await?
        .ok_or("transfer not found: the code is wrong, it expired, or it was already received")?;

    // Decrypt manifest
    let manifest_json = crypto::decrypt_segment(&k_data, &encrypted_manifest)?;
    let manifest = Manifest::from_json(&manifest_json)?;
    manifest.validate()?;

    // Validate every path before touching the filesystem.
    let file_paths = manifest
        .files
        .iter()
        .map(|f| manifest::safe_output_path(output_dir, &f.path))
        .collect::<Result<Vec<_>, _>>()?;

    // Pre-allocate files
    preallocate_files(&manifest, &file_paths)?;

    // Download and reconstruct each file
    let registry = ValidatorRegistry::new();
    let segment_size = manifest.segment_size as usize;
    let mut file_hashes = Vec::with_capacity(manifest.files.len());

    for (file, file_path) in manifest.files.iter().zip(&file_paths) {
        for (seg_idx, segment) in file.segments.iter().enumerate() {
            // Download shards for this segment
            let shard_data = download_shards_for_segment(&client, segment).await?;

            // Reconstruct the encrypted segment
            let encrypted = erasure::decode_segment(shard_data, segment.encrypted_size)?;

            // Decrypt
            let plaintext = crypto::decrypt_segment(&k_data, &encrypted).map_err(|e| {
                format!("segment {} of {}: {}", seg_idx, file.path, e)
            })?;

            // Validate first segment if applicable
            if seg_idx == 0 {
                let validator = registry.validator_for(&file.path);
                validator.validate_first_segment(&plaintext).map_err(|e| {
                    format!("validation failed for {}: {}", file.path, e)
                })?;
            }

            // Write to file at the correct offset
            write_segment_at_offset(file_path, seg_idx * segment_size, &plaintext)?;
        }

        // Check the reassembled file against the sender's hash, when provided
        let hash = compute_file_hash(file_path)?;
        if let Some(expected) = &file.blake3 {
            if &hash != expected {
                return Err(format!(
                    "{} is corrupt: BLAKE3 {} does not match sender's {}",
                    file.path, hash, expected
                ));
            }
        }
        file_hashes.push((file.path.clone(), hash));
    }

    Ok(DownloadResult {
        manifest,
        file_hashes,
    })
}

/// Download enough shards to rebuild a segment. Returns 12 Option<Vec<u8>>
/// entries. Shards are fetched in parallel; any whose content doesn't match
/// the manifest hash (corrupt or malicious node) is discarded, and fetching
/// stops as soon as DATA_SHARDS good shards have arrived.
async fn download_shards_for_segment(
    client: &Client,
    segment: &ManifestSegment,
) -> Result<Vec<Option<Vec<u8>>>, String> {
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; crypto::TOTAL_SHARDS];
    let mut tasks = JoinSet::new();

    for shard in &segment.shards {
        let client = client.clone();
        let url = format!("{}/shard/{}", shard.node, shard.hash);
        let hash = shard.hash.clone();
        let index = shard.index as usize;

        tasks.spawn(async move {
            match http::get(&client, &url, "shard download").await {
                Ok(Some(data)) if crypto::content_hash(&data) == hash => Some((index, data)),
                _ => None,
            }
        });
    }

    let mut have = 0;
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some((index, data))) = result {
            shards[index] = Some(data);
            have += 1;
            if have == crypto::DATA_SHARDS {
                break; // dropping `tasks` cancels the remaining downloads
            }
        }
    }

    if have < crypto::DATA_SHARDS {
        return Err(format!(
            "segment {}: only {} of {} needed shards are available",
            segment.id,
            have,
            crypto::DATA_SHARDS
        ));
    }
    Ok(shards)
}

/// Pre-allocate all files with the correct sizes (zero-filled).
fn preallocate_files(manifest: &Manifest, file_paths: &[PathBuf]) -> Result<(), String> {
    for (file, file_path) in manifest.files.iter().zip(file_paths) {
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {}", e))?;
        }
        let f = std::fs::File::create(file_path).map_err(|e| format!("create failed: {}", e))?;
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
