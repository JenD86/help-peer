use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

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
    /// BLAKE3 of the whole plaintext file, checked by the receiver after
    /// reconstruction. Optional so manifests from older senders still parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
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

/// Largest segment size a receiver will accept, to bound memory use.
const MAX_SEGMENT_SIZE: usize = 256 * 1024 * 1024;

impl Manifest {
    /// Build a manifest for a file or a directory.
    /// Returns the manifest and the directory its paths are relative to.
    /// Does NOT populate shard info — that's filled in during upload.
    pub fn build(path: &Path, transfer_name: &str) -> Result<(Self, PathBuf), String> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;

        let mut files = Vec::new();
        let base_dir = if metadata.is_file() {
            let name = path
                .file_name()
                .ok_or_else(|| format!("invalid file path: {}", path.display()))?
                .to_string_lossy()
                .to_string();
            files.push(new_file_entry(name, metadata.len()));
            match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            }
        } else {
            crawl_dir(path, path, &mut files)?;
            path.to_path_buf()
        };
        files.sort_by(|a, b| a.path.cmp(&b.path));

        let manifest = Manifest {
            version: 1,
            transfer_name: transfer_name.to_string(),
            total_bytes: files.iter().map(|f| f.size).sum(),
            segment_size: crypto::SEGMENT_SIZE as u32,
            erasure_data_shards: crypto::DATA_SHARDS as u8,
            erasure_parity_shards: crypto::PARITY_SHARDS as u8,
            files,
        };
        Ok((manifest, base_dir))
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("JSON serialization failed: {}", e))
    }

    /// Deserialize from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("JSON deserialization failed: {}", e))
    }

    /// Check a received manifest is internally consistent before acting on
    /// it. It comes from the sender, so sizes and indexes are untrusted and
    /// would otherwise drive allocations, file offsets and array indexing.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported manifest version {}", self.version));
        }
        if self.erasure_data_shards as usize != crypto::DATA_SHARDS
            || self.erasure_parity_shards as usize != crypto::PARITY_SHARDS
        {
            return Err(format!(
                "unsupported erasure coding {}+{}",
                self.erasure_data_shards, self.erasure_parity_shards
            ));
        }
        let seg_size = self.segment_size as usize;
        if seg_size == 0 || seg_size > MAX_SEGMENT_SIZE {
            return Err(format!("invalid segment size {}", seg_size));
        }

        let mut total: u64 = 0;
        for f in &self.files {
            let bad = |what: &str| format!("invalid manifest entry for {:?}: {}", f.path, what);

            total = total.checked_add(f.size).ok_or_else(|| bad("size overflow"))?;
            let expected_segments = (f.size + seg_size as u64 - 1) / seg_size as u64;
            if f.segments.len() as u64 != expected_segments {
                return Err(bad("wrong number of segments"));
            }
            if let Some(h) = &f.blake3 {
                if !is_hex_hash(h) {
                    return Err(bad("invalid file hash"));
                }
            }

            for (i, seg) in f.segments.iter().enumerate() {
                let expected_len = std::cmp::min(seg_size as u64, f.size - (i * seg_size) as u64);
                if seg.original_size as u64 != expected_len {
                    return Err(bad("wrong segment size"));
                }
                if seg.encrypted_size != seg.original_size + crypto::NONCE_SIZE + crypto::TAG_SIZE {
                    return Err(bad("wrong encrypted segment size"));
                }
                let mut seen = [false; crypto::TOTAL_SHARDS];
                for shard in &seg.shards {
                    let idx = shard.index as usize;
                    if idx >= crypto::TOTAL_SHARDS || seen[idx] {
                        return Err(bad("invalid shard index"));
                    }
                    seen[idx] = true;
                    if !is_hex_hash(&shard.hash) {
                        return Err(bad("invalid shard hash"));
                    }
                }
            }
        }
        if total != self.total_bytes {
            return Err("manifest total_bytes does not match its files".into());
        }
        Ok(())
    }
}

fn is_hex_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn new_file_entry(path: String, size: u64) -> ManifestFile {
    let seg = crypto::SEGMENT_SIZE as u64;
    let num_segments = (size + seg - 1) / seg;
    let segments = (0..num_segments)
        .map(|i| ManifestSegment {
            id: format!("seg_{:06}", i),
            original_size: std::cmp::min(seg, size - i * seg) as usize,
            encrypted_size: 0,  // filled during upload
            shards: Vec::new(), // filled during upload
        })
        .collect();

    ManifestFile {
        path,
        size,
        blake3: None, // filled during upload
        segments,
    }
}

fn crawl_dir(root: &Path, current: &Path, files: &mut Vec<ManifestFile>) -> Result<(), String> {
    let entries = std::fs::read_dir(current).map_err(|e| format!("read_dir failed: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry failed: {}", e))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| format!("file_type failed: {}", e))?;

        if file_type.is_dir() {
            crawl_dir(root, &path, files)?;
            continue;
        }

        // Follow symlinks to files (e.g. Hugging Face cache snapshots link to
        // blobs), but not to directories, which could loop or escape the tree.
        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                eprintln!("warning: skipping broken symlink {}", path.display());
                continue;
            }
        };
        if metadata.is_dir() {
            eprintln!("warning: skipping symlinked directory {}", path.display());
            continue;
        }
        if !metadata.is_file() {
            continue;
        }

        // Manifest paths always use '/' so receivers on any OS parse them the same way.
        let rel_path = path
            .strip_prefix(root)
            .map_err(|e| format!("strip_prefix failed: {}", e))?
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");

        files.push(new_file_entry(rel_path, metadata.len()));
    }

    Ok(())
}

/// Resolve a manifest path under `output_dir`, rejecting anything that could
/// escape it. The manifest comes from the sender, who must not be able to
/// write outside the directory the receiver chose (e.g. `../../.bashrc` or
/// an absolute path, which `Path::join` would otherwise honour).
pub fn safe_output_path(output_dir: &Path, rel_path: &str) -> Result<PathBuf, String> {
    let invalid = || format!("unsafe path in manifest: {:?}", rel_path);

    if rel_path.is_empty() {
        return Err(invalid());
    }

    let mut out = output_dir.to_path_buf();
    for part in rel_path.split('/') {
        // Reject empty / dot segments, and anything another OS could treat
        // as a separator, drive letter or special name.
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.contains(|c: char| c == '\\' || c == ':' || c == '\0')
        {
            return Err(invalid());
        }
        let mut components = Path::new(part).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(_)), None) => out.push(part),
            _ => return Err(invalid()),
        }
    }

    Ok(out)
}

/// Read a specific segment from a file.
pub fn read_file_segment(path: &Path, segment_index: usize, segment_size: usize) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).map_err(|e| format!("open failed: {}", e))?;
    let offset = (segment_index * segment_size) as u64;
    file.seek(SeekFrom::Start(offset)).map_err(|e| format!("seek failed: {}", e))?;

    // A single read() may return less than asked for; read until full or EOF.
    let mut buf = Vec::with_capacity(segment_size);
    file.take(segment_size as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {}", e))?;

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_manifest_build_from_dir() {
        let tmp = std::env::temp_dir().join("helppeer_test_manifest");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("sub")).unwrap();
        fs::write(tmp.join("config.json"), b"{}").unwrap();
        fs::write(tmp.join("sub/model.safetensors"), b"weights").unwrap();

        let (manifest, base) = Manifest::build(&tmp, "test-transfer").unwrap();
        assert_eq!(base, tmp);
        assert_eq!(manifest.transfer_name, "test-transfer");
        assert_eq!(manifest.version, 1);
        let paths: Vec<_> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["config.json", "sub/model.safetensors"]);
        assert_eq!(manifest.total_bytes, 9);
        assert_eq!(manifest.files[0].segments.len(), 1);
        assert_eq!(manifest.files[0].segments[0].original_size, 2);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_manifest_build_single_file() {
        let tmp = std::env::temp_dir().join("helppeer_test_single");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("model.bin"), b"abc").unwrap();
        fs::write(tmp.join("unrelated.txt"), b"not sent").unwrap();

        let (manifest, base) = Manifest::build(&tmp.join("model.bin"), "single").unwrap();
        assert_eq!(base, tmp);
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].path, "model.bin");
        assert_eq!(manifest.total_bytes, 3);

        fs::remove_dir_all(&tmp).unwrap();
    }

    fn valid_manifest() -> Manifest {
        Manifest {
            version: 1,
            transfer_name: "t".into(),
            total_bytes: 100,
            segment_size: 64,
            erasure_data_shards: 8,
            erasure_parity_shards: 4,
            files: vec![ManifestFile {
                path: "a".into(),
                size: 100,
                blake3: None,
                segments: vec![
                    ManifestSegment { id: "seg_000000".into(), original_size: 64, encrypted_size: 92, shards: vec![] },
                    ManifestSegment { id: "seg_000001".into(), original_size: 36, encrypted_size: 64, shards: vec![] },
                ],
            }],
        }
    }

    #[test]
    fn test_validate_accepts_consistent_manifest() {
        valid_manifest().validate().unwrap();
    }

    #[test]
    fn test_validate_rejects_inconsistent_manifests() {
        let shard = |index| ManifestShard { index, hash: "ab".repeat(32), node: "n".into() };
        let cases: Vec<(&str, Box<dyn Fn(&mut Manifest)>)> = vec![
            ("total", Box::new(|m| m.total_bytes = 5)),
            ("erasure", Box::new(|m| m.erasure_parity_shards = 2)),
            ("segment size", Box::new(|m| m.segment_size = 0)),
            ("segment count", Box::new(|m| { m.files[0].segments.pop(); })),
            ("original size", Box::new(|m| m.files[0].segments[1].original_size = 1)),
            ("encrypted size", Box::new(|m| m.files[0].segments[0].encrypted_size = 1 << 40)),
            ("shard index", Box::new(move |m| m.files[0].segments[0].shards = vec![shard(12)])),
            ("dup shard", Box::new(move |m| m.files[0].segments[0].shards = vec![shard(1), shard(1)])),
            ("file hash", Box::new(|m| m.files[0].blake3 = Some("zz".into()))),
        ];
        for (name, mutate) in cases {
            let mut m = valid_manifest();
            mutate(&mut m);
            assert!(m.validate().is_err(), "accepted bad {}", name);
        }
    }

    #[test]
    fn test_safe_output_path_accepts_nested() {
        let out = Path::new("/tmp/out");
        assert_eq!(
            safe_output_path(out, "sub/dir/model.safetensors").unwrap(),
            PathBuf::from("/tmp/out/sub/dir/model.safetensors")
        );
    }

    #[test]
    fn test_safe_output_path_rejects_escapes() {
        let out = Path::new("/tmp/out");
        for bad in [
            "",
            "../evil",
            "a/../../evil",
            "/etc/passwd",
            "a//b",
            "./a",
            "a/.",
            "..\\evil",
            "C:evil",
            "a\0b",
        ] {
            assert!(safe_output_path(out, bad).is_err(), "accepted {:?}", bad);
        }
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
                blake3: None,
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
