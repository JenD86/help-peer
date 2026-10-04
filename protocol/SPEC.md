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

`{hash}` = hex-encoded `BLAKE3(K_index)` where `K_index` is derived from the PAKE exchange.

**Response (success):**
```
HTTP/1.1 201 Created
```

**Response (conflict — manifest already exists):**
```
HTTP/1.1 409 Conflict
```

**Response (rate limited):**
```
HTTP/1.1 429 Too Many Requests
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

**Response (not found):**
```
HTTP/1.1 404 Not Found
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

`{hash}` = hex-encoded content hash of the shard (used for dedup and addressing).

**Response (success):**
```
HTTP/1.1 201 Created
```

**Response (node full):**
```
HTTP/1.1 507 Insufficient Storage
```

**Response (shard already exists — dedup):**
```
HTTP/1.1 200 OK
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
      "segments": [
        {
          "id": "seg_000000",
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
      "segments": [
        {
          "id": "seg_000001",
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
| `files[].path` | string | Relative path within the transfer directory |
| `files[].size` | u64 | File size in bytes |
| `files[].segments` | array | List of segments for this file |
| `segments[].id` | string | Segment identifier (sequential) |
| `segments[].shards` | array | List of erasure-coded shards |
| `shards[].index` | u8 | Shard index (0-11 for 8+4 coding) |
| `shards[].hash` | string | Hex-encoded content hash of the shard |
| `shards[].node` | string | Storage node URL where this shard lives |

---

## 4. Key Derivation

### 4.1 PAKE Exchange

The sender and receiver use SPAKE2 with a shared password (the human-readable code, e.g., `7-orbit-velvet`).

1. Both sides derive a shared secret `S` via SPAKE2.
2. `K_data = HKDF(S, "help-peer-data-key")` — 32 bytes, used for AES-256-GCM encryption.
3. `K_index = HKDF(S, "help-peer-index-key")` — 32 bytes, used for relay routing.
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

The 12 shards are distributed across different storage nodes. The manifest records which node holds which shard.

---

## 6. Transfer Codes

Transfer codes are human-readable strings in the format `{number}-{word}-{word}` (e.g., `7-orbit-velvet`).

* The number is 1-99.
* Words are drawn from the EFF short wordlist.
* The code serves as the SPAKE2 password.
