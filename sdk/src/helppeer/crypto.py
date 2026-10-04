"""Cryptographic operations for Help Peer."""
import os
import struct
import hmac
import hashlib
import hkdf
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
KEY_SIZE = 32


def derive_keys(code: str) -> tuple[bytes, bytes]:
    """Derive K_data and K_index from a transfer code using HKDF-SHA256."""
    ikm = code.encode("utf-8")
    k_data = hkdf.Hkdf(None, ikm, hashlib.sha256).expand(b"help-peer-data-key", KEY_SIZE)
    k_index = hkdf.Hkdf(None, ikm, hashlib.sha256).expand(b"help-peer-index-key", KEY_SIZE)
    return k_data, k_index


def relay_hash(k_index: bytes) -> str:
    """Compute the relay hash: hex(BLAKE3(K_index))."""
    import blake3
    return blake3.blake3(k_index).hexdigest()


def encrypt_segment(k_data: bytes, plaintext: bytes) -> bytes:
    """Encrypt a segment with AES-256-GCM. Returns nonce || ciphertext."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(k_data)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_segment(k_data: bytes, encrypted: bytes) -> bytes:
    """Decrypt a segment (nonce || ciphertext) with AES-256-GCM."""
    if len(encrypted) < NONCE_SIZE:
        raise ValueError("encrypted data too short")
    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:]
    aesgcm = AESGCM(k_data)
    return aesgcm.decrypt(nonce, ciphertext, None)


def content_hash(data: bytes) -> str:
    """Compute BLAKE3 hash of data, return hex string."""
    import blake3
    return blake3.blake3(data).hexdigest()


def shard_hmac(k_data: bytes, shard: bytes) -> bytes:
    """Compute HMAC-SHA256 of shard data."""
    return hmac.new(k_data, shard, hashlib.sha256).digest()


def verify_shard_hmac(k_data: bytes, shard: bytes, expected: bytes) -> bool:
    """Verify shard HMAC."""
    actual = shard_hmac(k_data, shard)
    return hmac.compare_digest(actual, expected)
