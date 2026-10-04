# Help Peer Protocol Specification v1

## Overview

This document defines the wire protocols for the three system components:
1. **Relay Server** — manifest store-and-forward
2. **Storage Node** — encrypted shard storage with TTL
3. **Client** — orchestrates PAKE handshake, encryption, erasure coding, upload/download

All communication in v1 uses HTTP/1.1 over TCP. Future versions may use QUIC.

---

## 1. Relay Server Protocol

### 1.1 PUT /manifest/{hash}

Store an encrypted manifest blob.

**Request:**
```
PUT /manifest/{hash} HTTP/1.1
Content-Type: application/octet-stream
Content-Length: {n}

{encrypted_manifest_bytes}
```

`{hash}` = lowercase hex-encoded `BLAKE3(K_index)` (64 characters), where `K_index` is derived from the transfer code (section 4.1).

Optional header `X-Max-Retrievals: {n}` (1–1000) lets the manifest be fetched `n` times, e.g. once per recipient. Manifests expire after the relay's TTL (default 24 hours).

**Response (success):**
```
HTTP/1.1 201 Created
```

**Response (conflict — manifest already exists):**
```
HTTP/1.1 409 Conflict
```

**Response (invalid hash or `X-Max-Retrievals`, or empty body):**
```
HTTP/1.1 400 Bad Request
```

**Response (manifest larger than the relay's limit, default 32MB):**
```
HTTP/1.1 413 Request Entity Too Large
```

### 1.2 GET /manifest/{hash}

Retrieve and atomically delete the manifest (one-time retrieval).

**Request:**
```
GET /manifest/{hash} HTTP/1.1
```

**Response (success):**
```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: {n}

{encrypted_manifest_bytes}
```

**Response (not found or expired):**
```
HTTP/1.1 404 Not Found
```

**Response (rate limited — too many failed lookups from this client):**
```
HTTP/1.1 429 Too Many Requests
```

### 1.3 GET /health

**Response:**
```json
{
  "status": "ok",
  "manifests_stored": 42,
  "uptime_seconds": 86400
}
```

---

## 2. Storage Node Protocol

### 2.1 PUT /shard/{hash}

Upload an encrypted shard for temporary storage.

**Request:**
```
PUT /shard/{hash} HTTP/1.1
Content-Type: application/octet-stream
Content-Length: {n}
X-TTL-Seconds: 86400

{shard_bytes}
```

`{hash}` = lowercase hex-encoded `BLAKE3(shard_bytes)`. The node verifies it and rejects content that doesn't match, so a hash can't be claimed by different data. `X-TTL-Seconds` can only shorten the node's TTL.

**Response (success):**
```
HTTP/1.1 201 Created
```

**Response (node full):**
```
HTTP/1.1 507 Insufficient Storage
```

**Response (shard already exists — dedup; the TTL is refreshed):**
```
HTTP/1.1 200 OK
```

**Response (invalid hash, or content doesn't match it):**
```
HTTP/1.1 400 Bad Request
```

**Response (shard larger than the node's limit, default 16MB):**
```
HTTP/1.1 413 Request Entity Too Large
```

### 2.2 GET /shard/{hash}

Retrieve a shard.

**Request:**
```
GET /shard/{hash} HTTP/1.1
```

**Response (success):**
```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: {n}

{shard_bytes}
```

**Response (not found / expired):**
```
HTTP/1.1 404 Not Found
```

### 2.3 DELETE /shard/{hash}

Delete a shard after successful transfer.

**Request:**
```
DELETE /shard/{hash} HTTP/1.1
```

**Response:**
```
HTTP/1.1 204 No Content
```

### 2.4 GET /health

**Response:**
```json
{
  "status": "ok",
  "capacity_bytes": 53687091200,
  "used_bytes": 12000000000,
  "shard_count": 342,
  "uptime_seconds": 86400,
  "node_id": "ed25519:base64..."
}
```

---

## 3. Manifest Format (JSON)

The manifest is a JSON object created by the sender, encrypted with `K_data` (AES-256-GCM), and uploaded to the relay.

```json
{
  "version": 1,
  "transfer_name": "Llama-3-70B-Instruct-Safetensors",
  "total_bytes": 140000000000,
  "segment_size": 67108864,
  "erasure_data_shards": 8,
  "erasure_parity_shards": 4,
  "files": [
    {
      "path": "config.json",
      "size": 435,
      "blake3": "hex...",
      "segments": [
        {
          "id": "seg_000000",
          "original_size": 435,
          "encrypted_size": 463,
          "shards": [
            {"index": 0, "hash": "hex...", "node": "http://10.0.0.1:7001"},
            {"index": 1, "hash": "hex...", "node": "http://10.0.0.2:7001"}
          ]
        }
      ]
    },
    {
      "path": "model-00001-of-00004.safetensors",
      "size": 35000000000,
      "blake3": "hex...",
      "segments": [
        {
          "id": "seg_000000",
          "original_size": 67108864,
          "encrypted_size": 67108892,
          "shards": [
            {"index": 0, "hash": "hex...", "node": "http://10.0.0.1:7001"},
            {"index": 1, "hash": "hex...", "node": "http://10.0.0.2:7001"}
          ]
        }
      ]
    }
  ]
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `version` | int | Protocol version (currently 1) |
| `transfer_name` | string | Human-readable name for the transfer |
| `total_bytes` | u64 | Total size of all files combined |
| `segment_size` | u32 | Segment size in bytes (default 67108864 = 64MB) |
| `erasure_data_shards` | u8 | Number of data shards per segment (default 8) |
| `erasure_parity_shards` | u8 | Number of parity shards per segment (default 4) |
| `files` | array | List of files in the transfer |
| `files[].path` | string | Relative path within the transfer, `/`-separated (see section 7) |
| `files[].size` | u64 | File size in bytes |
| `files[].blake3` | string (optional) | Hex BLAKE3 of the whole plaintext file; receivers verify it when present |
| `files[].segments` | array | List of segments for this file (`ceil(size / segment_size)` entries) |
| `segments[].id` | string | Segment identifier, `seg_{index:06}` within the file |
| `segments[].original_size` | u64 | Plaintext size: `segment_size`, except for a file's last segment |
| `segments[].encrypted_size` | u64 | `original_size + 28` (12-byte nonce + 16-byte GCM tag) |
| `segments[].shards` | array | List of erasure-coded shards |
| `shards[].index` | u8 | Shard index (0-11 for 8+4 coding) |
| `shards[].hash` | string | Hex BLAKE3 of the shard; receivers discard shards that don't match |
| `shards[].node` | string | Storage node URL where this shard lives |

---

## 4. Key Derivation

### 4.1 Code-Based Key Derivation

Sender and receiver are never online at the same time, so an interactive PAKE
(e.g. SPAKE2) is not possible. The transfer code itself is the shared secret
`S`, which is why codes must carry enough entropy to resist offline guessing
(see section 6).

1. `S = normalize(code)` — lowercase, with runs of whitespace or `-` collapsed to a single `-`.
2. `K_data = HKDF-SHA256(ikm=S, salt=none, info="help-peer-data-key")` — 32 bytes, used for AES-256-GCM encryption.
3. `K_index = HKDF-SHA256(ikm=S, salt=none, info="help-peer-index-key")` — 32 bytes, used for relay routing.
4. `relay_hash = BLAKE3(K_index)` — hex-encoded, used as the manifest key on the relay.

### 4.2 Segment Encryption

Each 64MB segment is encrypted independently:

1. Generate a random 12-byte nonce `N`.
2. Ciphertext = `AES-256-GCM(K_data, N, plaintext_segment)`.
3. The nonce is prepended to the ciphertext: `N || ciphertext || tag`.
4. The encrypted segment is then erasure-coded into 12 shards.

### 4.3 Shard Hashing

Each shard's content hash is `BLAKE3(shard_bytes)` — used for dedup, addressing, and integrity verification.

---

## 5. Erasure Coding

Each encrypted segment is split using Reed-Solomon erasure coding:

* **Data shards**: 8
* **Parity shards**: 4
* **Total shards**: 12
* **Recovery threshold**: Any 8 of 12 shards suffice to reconstruct the segment.

For implementations to interoperate they must produce identical shards
(this matches `reed-solomon-erasure` in Rust and `klauspost/reedsolomon` in Go):

* Arithmetic is in GF(2^8) with the polynomial `0x11D` (x^8 + x^4 + x^3 + x^2 + 1).
* The encoding matrix is the 12×8 Vandermonde matrix `V[r][c] = r^c`, multiplied by the inverse of its top 8×8 square so that the first 8 rows are the identity.
* The encrypted segment is split into 8 data shards of `ceil(len / 8)` bytes each, zero-padding the last ones; receivers truncate the rebuilt data to `encrypted_size`.

`protocol/test-vectors.json` contains reference outputs that every implementation's tests check.

The 12 shards are distributed across different storage nodes (round-robin). The manifest records which node holds which shard.

---

## 6. Transfer Codes

Transfer codes are six words joined by `-` (e.g., `orbit-velvet-zoom-candle-harbor-ember`).

* Words are drawn uniformly from the EFF long wordlist (`protocol/wordlist.txt`, 7776 words), giving ~77 bits of entropy.
* Words must be chosen with a cryptographically secure RNG.
* The code is the only secret protecting the transfer: anyone who guesses it can fetch (and consume) the manifest and decrypt everything.

## 7. Receiver Path Handling

Receivers must also check the manifest's internal consistency (segment
counts and sizes, shard indexes in range and unique, hashes well formed,
`total_bytes` equal to the sum of file sizes) before allocating or writing
anything.

`files[].path` is supplied by the sender and must be treated as untrusted.
Paths use `/` as the separator. Receivers must reject any path that is empty,
absolute, or has a component that is empty, `.`, `..`, or contains `\`, `:`
or NUL, and must do so before creating any files.
