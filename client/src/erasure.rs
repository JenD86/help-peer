use reed_solomon_erasure::galois_8::Field as GF8;
use reed_solomon_erasure::ReedSolomon;

use crate::crypto::{DATA_SHARDS, PARITY_SHARDS, TOTAL_SHARDS};

/// Split an encrypted segment into (8 data + 4 parity) shards using Reed-Solomon erasure coding.
/// Returns 12 shards, each roughly 1/8 the size of the input.
pub fn encode_segment(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let rs: ReedSolomon<GF8> = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|e| format!("RS init failed: {}", e))?;

    let shard_size = (data.len() + DATA_SHARDS - 1) / DATA_SHARDS;
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(TOTAL_SHARDS);

    // Fill data shards
    for i in 0..DATA_SHARDS {
        let start = i * shard_size;
        let end = std::cmp::min(start + shard_size, data.len());
        let mut shard = Vec::with_capacity(shard_size);
        shard.extend_from_slice(&data[start..end]);
        // Pad to shard_size
        while shard.len() < shard_size {
            shard.push(0);
        }
        shards.push(shard);
    }

    // Fill parity shards with zeros (will be computed by RS)
    for _ in 0..PARITY_SHARDS {
        shards.push(vec![0u8; shard_size]);
    }

    rs.encode(&mut shards)
        .map_err(|e| format!("RS encode failed: {}", e))?;

    Ok(shards)
}

/// Reconstruct the original segment from at least 8 of 12 shards.
/// `shards` should have 12 entries; missing shards should be None.
pub fn decode_segment(shards: Vec<Option<Vec<u8>>>, original_len: usize) -> Result<Vec<u8>, String> {
    if shards.len() != TOTAL_SHARDS {
        return Err(format!("expected {} shards, got {}", TOTAL_SHARDS, shards.len()));
    }

    let rs: ReedSolomon<GF8> = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|e| format!("RS init failed: {}", e))?;

    let shard_size = shards
        .iter()
        .find_map(|s| s.as_ref().map(|s| s.len()))
        .ok_or("no shards available")?;

    // Verify we have enough shards
    let available = shards.iter().filter(|s| s.is_some()).count();
    if available < DATA_SHARDS {
        return Err(format!(
            "insufficient shards: have {}, need {}",
            available, DATA_SHARDS
        ));
    }

    // Convert to (Vec<u8>, bool) tuples for reconstruct: bool indicates if shard is present
    let mut owned_shards: Vec<(Vec<u8>, bool)> = shards
        .into_iter()
        .map(|s| match s {
            Some(data) => (data, true),
            None => (vec![0u8; shard_size], false),
        })
        .collect();

    rs.reconstruct(&mut owned_shards)
        .map_err(|e| format!("RS reconstruct failed: {}", e))?;

    // Concatenate data shards and trim to original length
    let mut result = Vec::with_capacity(original_len);
    for i in 0..DATA_SHARDS {
        result.extend_from_slice(&owned_shards[i].0);
    }
    result.truncate(original_len);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = b"Hello, Help Peer! This is a test segment for erasure coding.";
        let shards = encode_segment(data).unwrap();
        assert_eq!(shards.len(), TOTAL_SHARDS);

        // Reconstruct from all shards
        let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let reconstructed = decode_segment(shard_opts, data.len()).unwrap();
        assert_eq!(data.as_slice(), reconstructed.as_slice());
    }

    #[test]
    fn test_decode_with_missing_shards() {
        let data = b"Test data for erasure coding with missing shards!";
        let shards = encode_segment(data).unwrap();

        // Drop 4 parity shards — should still recover with 8 data shards
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for i in DATA_SHARDS..TOTAL_SHARDS {
            shard_opts[i] = None;
        }
        let reconstructed = decode_segment(shard_opts, data.len()).unwrap();
        assert_eq!(data.as_slice(), reconstructed.as_slice());
    }

    #[test]
    fn test_decode_with_some_data_missing() {
        let data = b"Test data for erasure coding with some data shards missing!";
        let shards = encode_segment(data).unwrap();

        // Drop 2 data shards and 2 parity shards — should still recover with 8 of 12
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[1] = None; // data shard
        shard_opts[3] = None; // data shard
        shard_opts[9] = None; // parity shard
        shard_opts[11] = None; // parity shard
        let reconstructed = decode_segment(shard_opts, data.len()).unwrap();
        assert_eq!(data.as_slice(), reconstructed.as_slice());
    }

    #[test]
    fn test_decode_insufficient_shards() {
        let data = b"Too many missing shards!";
        let shards = encode_segment(data).unwrap();

        // Drop 5 shards — only 7 remain, need 8
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[0] = None;
        shard_opts[1] = None;
        shard_opts[2] = None;
        shard_opts[3] = None;
        shard_opts[4] = None;

        let result = decode_segment(shard_opts, data.len());
        assert!(result.is_err());
    }
}
