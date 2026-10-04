use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::{Algorithm, Argon2, Params, Version};
use blake3;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

pub const SEGMENT_SIZE: usize = 64 * 1024 * 1024; // 64 MB
pub const DATA_SHARDS: usize = 8;
pub const PARITY_SHARDS: usize = 4;
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

// Argon2id parameters for stretching the transfer code (protocol/SPEC.md §4.1).
// Every client must use exactly these values.
pub const ARGON2_SALT: &[u8] = b"help-peer/v2";
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;

/// Derive K_data and K_index from the transfer code.
/// Sender and receiver are never online together, so there is no PAKE: the
/// code itself is the shared secret. It is stretched with Argon2id so each
/// guess is expensive, then split into two keys with HKDF-SHA256.
pub fn derive_keys(code: &str) -> (Vec<u8>, Vec<u8>) {
    let code = normalize_code(code);

    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(KEY_SIZE))
        .expect("valid Argon2 parameters");
    let mut secret = [0u8; KEY_SIZE];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(code.as_bytes(), ARGON2_SALT, &mut secret)
        .expect("Argon2id failed");

    let h = Hkdf::<Sha256>::new(None, &secret);
    let mut k_data = [0u8; KEY_SIZE];
    let mut k_index = [0u8; KEY_SIZE];
    h.expand(b"help-peer-data-key", &mut k_data).unwrap();
    h.expand(b"help-peer-index-key", &mut k_index).unwrap();

    (k_data.to_vec(), k_index.to_vec())
}

/// A random 32-byte secret, hex-encoded (ack secrets, delete tokens).
pub fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// BLAKE3 of a hex secret's raw bytes, as given to the relay or a storage
/// node so it can later check the secret without storing it.
pub fn secret_hash(secret_hex: &str) -> String {
    let bytes = hex::decode(secret_hex).expect("secret is hex");
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// Canonicalize a typed-in code so "Apple Banana", " apple-banana " and
/// "APPLE-BANANA" all derive the same keys.
pub fn normalize_code(code: &str) -> String {
    code.split(|c: char| c == '-' || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join("-")
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
    fn test_normalize_code() {
        assert_eq!(normalize_code(" Orbit  velvet-ZOOM "), "orbit-velvet-zoom");
        assert_eq!(derive_keys("Orbit Velvet"), derive_keys("orbit-velvet"));
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
    fn test_shared_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../protocol/test-vectors.json")).unwrap();
        let kd = &v["key_derivation"];
        let mut inputs = vec![kd["code"].as_str().unwrap()];
        inputs.extend(kd["equivalent_inputs"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()));
        for code in inputs {
            let (k_data, k_index) = derive_keys(code);
            assert_eq!(hex::encode(&k_data), kd["k_data"].as_str().unwrap(), "{:?}", code);
            assert_eq!(hex::encode(&k_index), kd["k_index"].as_str().unwrap());
            assert_eq!(relay_hash(&k_index), kd["relay_hash"].as_str().unwrap());
        }

        let sh = &v["secret_hash"];
        assert_eq!(secret_hash(sh["secret"].as_str().unwrap()), sh["blake3"].as_str().unwrap());
    }
}
