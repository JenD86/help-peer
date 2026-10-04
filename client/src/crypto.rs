use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use blake3;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

pub const SEGMENT_SIZE: usize = 64 * 1024 * 1024; // 64 MB
pub const DATA_SHARDS: usize = 8;
pub const PARITY_SHARDS: usize = 4;
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;
pub const NONCE_SIZE: usize = 12;
pub const KEY_SIZE: usize = 32;

/// Derive K_data and K_index from a shared secret (the PAKE code).
/// In the MVP, the shared secret IS the code itself.
/// In production, this would come from SPAKE2 key exchange.
pub fn derive_keys(code: &str) -> (Vec<u8>, Vec<u8>) {
    let ikm = code.as_bytes();
    let h = Hkdf::<Sha256>::new(None, ikm);

    let mut k_data = [0u8; KEY_SIZE];
    let mut k_index = [0u8; KEY_SIZE];

    h.expand(b"help-peer-data-key", &mut k_data).unwrap();
    h.expand(b"help-peer-index-key", &mut k_index).unwrap();

    (k_data.to_vec(), k_index.to_vec())
}

/// Compute the relay hash from K_index: BLAKE3(K_index) hex-encoded
pub fn relay_hash(k_index: &[u8]) -> String {
    let hash = blake3::hash(k_index);
    hex::encode(hash.as_bytes())
}

/// Encrypt a plaintext segment using AES-256-GCM.
/// Returns nonce || ciphertext (which includes the GCM tag).
pub fn encrypt_segment(k_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(k_data);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypt a segment (nonce || ciphertext) using AES-256-GCM.
pub fn decrypt_segment(k_data: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted.len() < NONCE_SIZE {
        return Err("encrypted data too short".into());
    }

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(k_data);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {}", e))
}

/// Compute HMAC-SHA256 of shard data for integrity verification.
pub fn shard_hmac(k_data: &[u8], shard: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k_data).unwrap();
    mac.update(shard);
    mac.finalize().into_bytes().to_vec()
}

/// Verify shard HMAC.
pub fn verify_shard_hmac(k_data: &[u8], shard: &[u8], expected_hmac: &[u8]) -> bool {
    let actual = shard_hmac(k_data, shard);
    actual.as_slice() == expected_hmac
}

/// Compute BLAKE3 hash of data, return hex string.
pub fn content_hash(data: &[u8]) -> String {
    hex::encode(blake3::hash(data).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let k_data = vec![0u8; 32];
        let plaintext = b"Hello, Help Peer!";
        let encrypted = encrypt_segment(&k_data, plaintext);
        let decrypted = decrypt_segment(&k_data, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let (k1_data, k1_index) = derive_keys("7-orbit-velvet");
        let (k2_data, k2_index) = derive_keys("7-orbit-velvet");
        assert_eq!(k1_data, k2_data);
        assert_eq!(k1_index, k2_index);

        let (k3_data, _) = derive_keys("8-orbit-velvet");
        assert_ne!(k1_data, k3_data);
    }

    #[test]
    fn test_relay_hash_consistency() {
        let (_, k_index) = derive_keys("7-orbit-velvet");
        let h1 = relay_hash(&k_index);
        let h2 = relay_hash(&k_index);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 32 bytes hex = 64 chars
    }

    #[test]
    fn test_hmac_verification() {
        let k_data = vec![0u8; 32];
        let shard = b"some shard data";
        let hmac = shard_hmac(&k_data, shard);
        assert!(verify_shard_hmac(&k_data, shard, &hmac));
        assert!(!verify_shard_hmac(&k_data, b"tampered", &hmac));
    }
}
