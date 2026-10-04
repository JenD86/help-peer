# Architecture Guide: Asynchronous Ephemeral "Wormhole" for AI Models

## 1. System Overview

This system is explicitly designed for the secure, decentralized, and asynchronous transfer of massive AI model weight directories (often $50\text{ GB} - 150\text{ GB}+$). It combines a human-readable Password-Authenticated Key Exchange (PAKE) with an encrypted, sharded ephemeral storage layer, optimized for the unique constraints of handling large machine learning assets.

**Core AI-Specific Properties:**

* **Multi-File Aware:** Native support for directories (model shards, tokenizers, configs).

* **Bulletproof Resumability:** Network drops at 98% will not require starting over.

* **Malware Resilient:** Enforces strict `.safetensors` parsing in memory before saving to disk.

* **Verifiable:** Incrementally calculates model hashes during download for checksum verification.

## 2. The Multi-File Manifest Structure

Unlike a single-file transfer, the Sender's client crawls the chosen model directory and generates a hierarchical, JSON-based Manifest. This manifest maps files to their respective 64MB segments, which are then mapped to storage nodes.

```
{
  "transfer_name": "Llama-3-70B-Instruct-Safetensors",
  "total_bytes": 140000000000,
  "files": [
    {
      "path": "config.json",
      "size": 435,
      "segments": [ ... ]
    },
    {
      "path": "model-00001-of-00004.safetensors",
      "size": 35000000000,
      "segments": [
        { "id": "seg_001", "nodes": ["ip1", "ip2", ... "ip12"] },
        { "id": "seg_002", "nodes": ["ip3", "ip4", ... "ip14"] }
      ]
    }
  ]
}

```

*This entire JSON object is encrypted with the symmetric key (*$K_{data}$*) before being uploaded to the Relay Network.*

## 3. Step-by-Step Data Flow

### Phase 1: Handshake & Manifest Generation

1. The **Sender** selects a local model directory and generates a code (e.g., `7-orbit-velvet`).

2. SPAKE2 derives $K_{data}$ (encryption key) and $K_{index}$ (Relay routing key).

3. The Sender's client generates the Multi-File Manifest (as shown above).

### Phase 2: Pipelined Streaming & Upload

1. Files are read sequentially in $64\text{ MB}$ segments.

2. Each segment is encrypted (AES-256-GCM) with $K_{data}$, then Erasure Coded (e.g., 8 data + 4 parity shards).

3. The 12 shards are uploaded concurrently to temporary Storage Nodes.

4. The Manifest is finalized, encrypted, and uploaded to the Relay Network.

### Phase 3: Retrieval & Safe Allocation

1. The **Receiver** inputs `7-orbit-velvet`.

2. The Receiver's client derives the keys, downloads the encrypted Manifest from the Relay, and decrypts it.

3. **Pre-allocation Check:** The client reads `total_bytes`. It checks local disk space. If sufficient, it instantly creates empty, zero-filled files matching the exact directory structure and file sizes. This prevents Out-Of-Space errors at the very end of a 100GB download.

### Phase 4: Download, Validation & Resumability

1. **Resumable State:** The client creates a local lightweight database (e.g., SQLite or JSON state file) tracking the download status of every 64MB segment.

2. The client fetches the required $K$ shards for a segment and reconstructs the encrypted block.

3. **The `.safetensors` Filter:**

   * When decrypting the *first* segment of any file ending in `.safetensors`, the client reads the first few bytes in memory.

   * It parses the JSON header native to the safetensors format.

   * If the header is malformed, or if a user attempts to force a malicious `.pt` (Python Pickle) payload under a fake extension, the client immediately aborts the transfer and alerts the user.

4. **Direct-to-Disk Injection:** Validated, decrypted segments are written directly into the pre-allocated files at their precise byte offsets.

### Phase 5: Hashing & Cleanup

1. **Streaming Hash:** As each 64MB chunk is decrypted and written, the client updates a rolling BLAKE3 or SHA-256 hash state.

2. Upon completion, the final hashes are output to the UI, allowing the user to verify them against HuggingFace or Civitai.

3. The Receiver client broadcasts cryptographic "Delete" signals to the Storage Nodes to clear the shards. (Nodes also enforce a 24-hour TTL fallback).

## 4. Tech Stack Recommendations for AI Assets

* **Language:** **Rust**. Memory safety is critical when manually parsing binary headers in memory.

* **Cryptography:** `spake2` (Key Exchange), `ring` or `rust-crypto` (AES-GCM).

* **Erasure Coding:** `reed-solomon-erasure` crate.

* **Hashing:** `blake3` crate (BLAKE3 is significantly faster than SHA-256 and highly parallelizable, ideal for 100GB+ streams).

* **AI Specific:** `safetensors` Rust crate (maintained by HuggingFace) for native, fast header validation directly in the download pipeline.

## 5. Networking & Discovery Layer

The system operates over a decentralized network of volunteer Storage Nodes, coordinated by lightweight Relay Servers. Discovery and connectivity are handled as follows:

### 5.1 Kademlia DHT for Node Discovery

Each Storage Node generates an Ed25519 keypair on first launch. The public key serves as its node identity. Nodes register themselves in a Kademlia Distributed Hash Table (DHT) with the following record:

```
{
  "node_id": "ed25519:base64...",
  "endpoints": ["ip:port", "ip:port"],
  "capacity_bytes": 53687091200,
  "used_bytes": 12000000000,
  "uptime_seconds": 86400,
  "protocol_version": 1
}
```

Clients query the DHT to discover available storage nodes. Nodes periodically refresh their DHT records and update their `used_bytes` and `uptime_seconds` fields.

### 5.2 Relay Coordination

Relay Servers are lightweight coordinators that store encrypted manifests indexed by a hash of $K_{index}$. They do not participate in shard storage — only manifest routing.

* **Multiple relays** can run independently. Clients discover relay endpoints via DHT or a bootstrap list.
* **No plaintext access**: The relay only sees encrypted manifest blobs. It never possesses $K_{data}$.
* **Federation**: Clients can use any relay. If one relay is down, the client falls back to another.

### 5.3 NAT Traversal

Storage Nodes use UDP hole-punching (STUN-like) for direct peer-to-peer shard transfer:

1. Both client and storage node exchange endpoint hints via the DHT or relay.
2. They attempt direct UDP connections in parallel (LAN > IPv6 > public IP).
3. If direct connection fails (symmetric NAT, firewalls), traffic is relayed through a relay tunnel.
4. All shard data is encrypted end-to-end; relays see only opaque ciphertext.

### 5.4 Transport Protocol

* **MVP**: HTTP/1.1 over TCP for simplicity and debuggability.
* **Future**: QUIC for multiplexed, congestion-controlled transfers with connection migration.

## 6. Storage Node Design

### 6.1 Language & Runtime

Storage Nodes are implemented in **Go** for excellent networking performance, simple deployment (single static binary), and efficient goroutine-based concurrency for handling many concurrent shard uploads and downloads.

### 6.2 Responsibilities

* Accept encrypted shards from senders and store them on local disk.
* Serve shards to receivers on authenticated request.
* Enforce per-shard TTL (default 24 hours, configurable to 48 hours).
* Enforce storage quotas (node operator configures max capacity).
* Report health metrics (available space, uptime, shard count) to the DHT.

### 6.3 Shard Storage

Shards are stored as flat files in a configurable data directory, keyed by their content hash:

```
/data/
  shards/
    ab/cd/ef/abcdef0123456789...  (shard file)
    12/34/56/1234567890abcdef...  (shard file)
```

A two-level directory prefix prevents single-directory performance issues at scale.

* **TTL cleanup**: A background goroutine ticks every 60 seconds, scanning for expired shards and deleting them.
* **LRU eviction**: If disk usage exceeds the configured quota, the oldest-accessed shards are evicted first.
* **Atomic writes**: Shards are written to a temporary file then renamed to prevent partial writes.

### 6.4 API

The Storage Node exposes a simple HTTP API:

| Method | Path | Body | Description |
|---|---|---|---|
| `PUT` | `/shard/{hash}` | Raw shard bytes | Store a shard with TTL |
| `GET` | `/shard/{hash}` | — | Retrieve a shard |
| `DELETE` | `/shard/{hash}` | — | Delete a shard (with auth token) |
| `GET` | `/health` | — | Node health and capacity info |

Shard integrity is verified by the client via HMAC tags — the node itself cannot verify shard contents (zero-knowledge).

## 7. Relay Server Design

### 7.1 Language & Runtime

The Relay Server is implemented in **Go** as a lightweight, stateless-friendly service backed by SQLite for manifest persistence.

### 7.2 Responsibilities

* Store encrypted manifests indexed by `H(K_index)`.
* Serve manifests to receivers who present the correct code-derived key.
* Enforce one-time retrieval (manifest is deleted after first successful download).
* Rate-limit manifest creation to prevent abuse.

### 7.3 API

| Method | Path | Body | Description |
|---|---|---|---|
| `PUT` | `/manifest/{hash}` | Encrypted manifest blob | Store an encrypted manifest |
| `GET` | `/manifest/{hash}` | — | Retrieve and delete manifest (one-time) |
| `GET` | `/health` | — | Relay health check |

### 7.4 Security

* Manifests are encrypted client-side with $K_{data}$ before upload. The relay never sees plaintext.
* The `{hash}` in the URL is `BLAKE3(K_index)`, so the relay cannot enumerate transfers.
* One-time retrieval prevents replay attacks.
* Rate limiting (e.g., 10 manifest PUTs per minute per IP) prevents abuse.

## 8. Security & Edge Cases

### 8.1 Sybil Resistance

Storage Nodes sign shard receipts with their Ed25519 private key. The DHT tracks node reputation based on:
* Uptime percentage (measured via periodic health checks).
* Successful transfer count.
* Shard integrity pass rate (measured by receivers reporting corrupt shards).

Nodes with poor reputation are deprioritized in shard placement decisions.

### 8.2 Shard Integrity

Each shard carries an HMAC tag derived from $K_{data}$. Storage nodes cannot tamper with shard contents undetectably. The client verifies the HMAC upon download before attempting erasure reconstruction.

### 8.3 Churn Handling

If a Storage Node goes offline during a transfer:
* Erasure coding (8 data + 4 parity) ensures any 8 of 12 shards suffice for reconstruction.
* The download manager retries failed shards from other nodes automatically.
* If fewer than 8 nodes are available for a segment, the transfer pauses and waits for node recovery (within the TTL window).

### 8.4 Code Reuse Prevention

PAKE codes are single-use. The relay enforces one-time manifest retrieval — once a receiver downloads the manifest, it is deleted from the relay. This prevents a second party from intercepting the transfer.

### 8.5 Abuse Prevention

* **Relay rate limiting**: 10 manifest PUTs per minute per IP.
* **Storage node quotas**: Nodes reject shards when their configured capacity is reached.
* **Optional proof-of-work**: The client may be required to solve a small PoW puzzle to create a manifest, preventing spam.
* **TTL enforcement**: All shards auto-expire after 24–48 hours regardless of retrieval status.

## 9. Pluggable Validation Pipeline

The `.safetensors` filter is generalized into a pluggable validation trait. Validators are registered by file extension and invoked on the first segment of each file during download:

```rust
pub trait FileValidator: Send + Sync {
    fn file_extensions(&self) -> &[&str];
    fn validate_first_segment(&self, data: &[u8]) -> Result<(), ValidationError>;
}
```

### Built-in Validators

* **SafetensorsValidator**: Parses the safetensors JSON header from the first 8 bytes (N) + N bytes of JSON. Rejects malformed headers or pickle payloads disguised as `.safetensors`.
* **GenericValidator**: Passthrough — accepts all data. Used for non-model files (configs, tokenizers, etc.).

### Future Validators

* `PickleValidator`: Warns or rejects Python Pickle files (security risk).
* `ONNXValidator`: Validates ONNX model format headers.
* `GGUFValidator`: Validates GGUF (llama.cpp) format headers.

## 10. Updated Tech Stack

| Component | Language | Key Dependencies | Role |
|---|---|---|---|
| Client (CLI + library) | Rust | `spake2`, `aes-gcm`, `reed-solomon-erasure`, `blake3`, `rusqlite`, `clap`, `reqwest` | Sender + receiver CLI |
| Storage Node | Go | `net/http`, `crypto/ed25519`, `sqlite` (optional) | Shard storage + TTL |
| Relay Server | Go | `net/http`, `database/sql`, `sqlite` | Manifest routing |
| DHT (future) | Go or Rust | Kademlia implementation | Node discovery |
| Protocol | — | — | Wire format spec |

### Rust Client Dependencies

```toml
[dependencies]
spake2 = "0.4"
aes-gcm = "0.10"
reed-solomon-erasure = "6.0"
blake3 = "1.5"
rusqlite = "0.31"
clap = { version = "4.5", features = ["derive"] }
reqwest = { version = "0.12", features = ["stream"] }
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hex = "0.4"
rand = "0.8"
```

### Go Server Dependencies

```
# relay/go.mod
require (
    github.com/mattn/go-sqlite3 v1.14.22
)

# storage-node/go.mod
require (
    github.com/google/uuid v1.6.0
)
```