//! Resume state for interrupted downloads (protocol/SPEC.md §8).
//!
//! Progress is an append-only log at `<output>/.helppeer/<manifest_id>.partial`,
//! where `manifest_id` is the BLAKE3 of the decrypted manifest. The first line
//! is a header; each further line records one segment that was fully written,
//! with the BLAKE3 of its plaintext so a resumed download can check the data
//! on disk is still intact before skipping it:
//!
//! ```text
//! {"version":1,"manifest_id":"<hex>"}
//! {"file":"sub/model.safetensors","segment":3,"blake3":"<hex>"}
//! ```
//!
//! The log holds no secrets; the code is still needed to fetch and decrypt
//! the manifest on retry.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const STATE_DIR: &str = ".helppeer";

#[derive(Serialize, Deserialize)]
struct Header {
    version: u32,
    manifest_id: String,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    file: String,
    segment: usize,
    blake3: String,
}

pub struct ResumeLog {
    path: PathBuf,
    file: File,
    done: HashMap<(String, usize), String>,
}

impl ResumeLog {
    /// Open the log for this manifest, loading any progress from a previous run.
    pub fn open(output_dir: &Path, manifest_id: &str) -> Result<Self, String> {
        let dir = output_dir.join(STATE_DIR);
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
        let path = dir.join(format!("{}.partial", manifest_id));

        let done = match File::open(&path) {
            Ok(f) => load(BufReader::new(f), manifest_id),
            Err(_) => HashMap::new(),
        };

        // Start a fresh log if there was nothing usable to resume from.
        let fresh = done.is_empty();
        let mut file = OpenOptions::new()
            .create(true)
            .append(!fresh)
            .write(true)
            .truncate(fresh)
            .open(&path)
            .map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
        if !fresh {
            // A killed run may have left a partial last line; start ours on
            // a new line so it isn't glued onto it. Blank lines are skipped.
            writeln!(file).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
        } else {
            let header = Header {
                version: 1,
                manifest_id: manifest_id.to_string(),
            };
            writeln!(file, "{}", serde_json::to_string(&header).unwrap())
                .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
        }

        Ok(ResumeLog { path, file, done })
    }

    /// Number of segments recorded by a previous run.
    pub fn previously_done(&self) -> usize {
        self.done.len()
    }

    /// The plaintext hash recorded for a segment, if it was completed before.
    pub fn completed(&self, file: &str, segment: usize) -> Option<&str> {
        self.done.get(&(file.to_string(), segment)).map(String::as_str)
    }

    /// Record a segment as written. Call only after its data is on disk.
    pub fn record(&mut self, file: &str, segment: usize, blake3: &str) -> Result<(), String> {
        let entry = Entry {
            file: file.to_string(),
            segment,
            blake3: blake3.to_string(),
        };
        writeln!(self.file, "{}", serde_json::to_string(&entry).unwrap())
            .and_then(|_| self.file.sync_data())
            .map_err(|e| format!("cannot write {}: {}", self.path.display(), e))
    }

    /// Remove the log (on success, or to force the next run to start over).
    pub fn remove(self) {
        let dir = self.path.parent().map(Path::to_path_buf);
        drop(self.file);
        let _ = fs::remove_file(&self.path);
        if let Some(dir) = dir {
            let _ = fs::remove_dir(dir); // only succeeds if empty
        }
    }
}

/// Parse a log, ignoring it entirely if the header doesn't match and skipping
/// any malformed line (e.g. one cut short when the process was killed).
fn load(reader: impl BufRead, manifest_id: &str) -> HashMap<(String, usize), String> {
    let mut lines = reader.lines();
    let header_ok = lines
        .next()
        .and_then(|l| l.ok())
        .and_then(|l| serde_json::from_str::<Header>(&l).ok())
        .map_or(false, |h| h.version == 1 && h.manifest_id == manifest_id);
    if !header_ok {
        return HashMap::new();
    }

    lines
        .filter_map(|l| l.ok())
        .filter_map(|l| serde_json::from_str::<Entry>(&l).ok())
        .map(|e| ((e.file, e.segment), e.blake3))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_records_survive_reopen() {
        let dir = tmp("helppeer_resume_reopen");
        let mut log = ResumeLog::open(&dir, "abc").unwrap();
        assert_eq!(log.previously_done(), 0);
        log.record("a/b.bin", 0, "h0").unwrap();
        log.record("a/b.bin", 2, "h2").unwrap();
        drop(log);

        let log = ResumeLog::open(&dir, "abc").unwrap();
        assert_eq!(log.previously_done(), 2);
        assert_eq!(log.completed("a/b.bin", 2), Some("h2"));
        assert_eq!(log.completed("a/b.bin", 1), None);

        log.remove();
        assert!(!dir.join(STATE_DIR).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_other_manifest_starts_fresh() {
        let dir = tmp("helppeer_resume_other");
        let mut log = ResumeLog::open(&dir, "abc").unwrap();
        log.record("f", 0, "h").unwrap();
        drop(log);

        let path = dir.join(STATE_DIR).join("abc.partial");
        fs::rename(&path, dir.join(STATE_DIR).join("def.partial")).unwrap();
        assert_eq!(ResumeLog::open(&dir, "def").unwrap().previously_done(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_ignores_truncated_line() {
        let log = "{\"version\":1,\"manifest_id\":\"m\"}\n\
                   {\"file\":\"f\",\"segment\":0,\"blake3\":\"h\"}\n\
                   {\"file\":\"f\",\"segm";
        let done = load(log.as_bytes(), "m");
        assert_eq!(done.len(), 1);
    }
}
