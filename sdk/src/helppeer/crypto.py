"""Cryptographic operations for Help Peer."""
from __future__ import annotations
import os
import re
import hashlib

import hkdf
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
KEY_SIZE = 32


def normalize_code(code: str) -> str:
    """Canonicalize a typed-in code so "Apple Banana", " apple-banana " and
    "APPLE-BANANA" all derive the same keys."""
    return "-".join(w.lower() for w in re.split(r"[-\s]+", code) if w)


# Argon2id parameters for stretching the transfer code (protocol/SPEC.md §4.1).
# Every client must use exactly these values.
ARGON2_SALT = b"help-peer/v2"
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1


def derive_keys(code: str) -> tuple[bytes, bytes]:
    """Derive K_data and K_index from a transfer code.

    The code is stretched with Argon2id (making each guess expensive), then
    split into two keys with HKDF-SHA256.
    """
    secret = hash_secret_raw(
        normalize_code(code).encode("utf-8"),
        ARGON2_SALT,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )
    k_data = hkdf.Hkdf(None, secret, hashlib.sha256).expand(b"help-peer-data-key", KEY_SIZE)
    k_index = hkdf.Hkdf(None, secret, hashlib.sha256).expand(b"help-peer-index-key", KEY_SIZE)
    return k_data, k_index


def new_secret() -> str:
    """A random 32-byte secret, hex-encoded (ack secrets, delete tokens)."""
    return os.urandom(32).hex()


def secret_hash(secret_hex: str) -> str:
    """BLAKE3 of a hex secret's raw bytes, as given to the relay or a storage
    node so it can later check the secret without storing it."""
    import blake3
    return blake3.blake3(bytes.fromhex(secret_hex)).hexdigest()


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
