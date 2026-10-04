use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub transfer_name: String,
    pub total_bytes: u64,
    pub segment_size: u32,
    pub erasure_data_shards: u8,
    pub erasure_parity_shards: u8,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub segments: Vec<ManifestSegment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSegment {
    pub id: String,
    pub original_size: usize,
    pub encrypted_size: usize,
    pub shards: Vec<ManifestShard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestShard {
    pub index: u8,
    pub hash: String,
    pub node: String,
}

impl Manifest {
    /// Build a manifest by crawling a directory.
    /// Does NOT populate shard info — that's filled in during upload.
    pub fn build_from_dir(dir: &Path, transfer_name: &str) -> Result<Self, String> {
        let mut files = Vec::new();
        let mut total_bytes: u64 = 0;

        crawl_dir(dir, dir, &mut files, &mut total_bytes)?;

        Ok(Manifest {
            version: 1,
            transfer_name: transfer_name.to_string(),
            total_bytes,
            segment_size: crypto::SEGMENT_SIZE as u32,
            erasure_data_shards: crypto::DATA_SHARDS as u8,
            erasure_parity_shards: crypto::PARITY_SHARDS as u8,
            files,
        })
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("JSON serialization failed: {}", e))
    }

    /// Deserialize from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("JSON deserialization failed: {}", e))
    }
}

fn crawl_dir(
    root: &Path,
    current: &Path,
    files: &mut Vec<ManifestFile>,
    total_bytes: &mut u64,
) -> Result<(), String> {
    let entries = std::fs::read_dir(current).map_err(|e| format!("read_dir failed: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry failed: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            crawl_dir(root, &path, files, total_bytes)?;
        } else if path.is_file() {
            let metadata = std::fs::metadata(&path).map_err(|e| format!("metadata failed: {}", e))?;
            let rel_path = path
                .strip_prefix(root)
                .map_err(|e| format!("strip_prefix failed: {}", e))?
                .to_string_lossy()
                .to_string();

            let size = metadata.len();
            *total_bytes += size;

            let num_segments = if size == 0 {
                0
            } else {
                ((size as usize + crypto::SEGMENT_SIZE - 1) / crypto::SEGMENT_SIZE) as usize
            };

            let segments: Vec<ManifestSegment> = (0..num_segments)
                .map(|i| ManifestSegment {
                    id: format!("seg_{:06}", i),
                    original_size: std::cmp::min(
                        crypto::SEGMENT_SIZE,
                        size as usize - i * crypto::SEGMENT_SIZE,
                    ),
                    encrypted_size: 0, // filled during upload
                    shards: Vec::new(), // filled during upload
                })
                .collect();

            files.push(ManifestFile {
                path: rel_path,
                size,
                segments,
            });
        }
    }

    Ok(())
}

/// Read a specific segment from a file.
pub fn read_file_segment(path: &Path, segment_index: usize) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).map_err(|e| format!("open failed: {}", e))?;
    let offset = (segment_index * crypto::SEGMENT_SIZE) as u64;
    file.seek(SeekFrom::Start(offset)).map_err(|e| format!("seek failed: {}", e))?;

    let mut buf = vec![0u8; crypto::SEGMENT_SIZE];
    let n = file.read(&mut buf).map_err(|e| format!("read failed: {}", e))?;
    buf.truncate(n);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_manifest_build_from_dir() {
        let tmp = std::env::temp_dir().join("helppeer_test_manifest");
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("config.json"), b"{}").unwrap();
        fs::write(tmp.join("model.safetensors"), b"weights").unwrap();

        let manifest = Manifest::build_from_dir(&tmp, "test-transfer").unwrap();
        assert_eq!(manifest.transfer_name, "test-transfer");
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.files.len(), 2);
        assert!(manifest.total_bytes > 0);

        // Check segment counts
        for file in &manifest.files {
            if file.path == "config.json" {
                assert_eq!(file.segments.len(), 1);
                assert_eq!(file.segments[0].original_size, 2);
            }
        }

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_manifest_json_roundtrip() {
        let manifest = Manifest {
            version: 1,
            transfer_name: "test".into(),
            total_bytes: 100,
            segment_size: 67108864,
            erasure_data_shards: 8,
            erasure_parity_shards: 4,
            files: vec![ManifestFile {
                path: "test.txt".into(),
                size: 100,
                segments: vec![ManifestSegment {
                    id: "seg_000000".into(),
                    original_size: 100,
                    encrypted_size: 0,
                    shards: vec![],
                }],
            }],
        };

        let json = manifest.to_json().unwrap();
        let restored = Manifest::from_json(&json).unwrap();
        assert_eq!(restored.transfer_name, "test");
        assert_eq!(restored.files.len(), 1);
        assert_eq!(restored.files[0].path, "test.txt");
    }
}
