# Help Peer

A free, decentralized system for asynchronously sharing large file dumps — mainly AI model weights — without requiring the sender to stay online.

Think "Wormhole meets BitTorrent, but the sender can leave."

## How It Works

1. **Sender** runs `helppeer send ./my-model/` and gets a code like `38-vortex-xenon`
2. The files are encrypted (AES-256-GCM), split into 64MB segments, erasure-coded (8+4 Reed-Solomon), and the 12 shards per segment are uploaded to volunteer storage nodes
3. The encrypted manifest is uploaded to a relay server
4. **Sender can go offline**
5. **Receiver** runs `helppeer receive 38-vortex-xenon` — the code derives the encryption keys, fetches the manifest from the relay, downloads shards from storage nodes, reconstructs, decrypts, and validates the files
6. Shards auto-expire after 24 hours (TTL)

## Quick Start

### Prerequisites

- Go 1.18+ (for relay and storage node)
- Rust 1.70+ (for Rust client)
- Python 3.9+ (for Python SDK)

### Build

```bash
# Build relay server
cd relay && go build -o relay-server .

# Build storage node
cd storage-node && go build -o storage-node .

# Build client
cd client && cargo build --release
```

### Run Servers

**Option 1: Docker Compose (easiest)**
```bash
docker compose up -d
# Relay on :7000, storage node on :7001
```

**Option 2: Docker (individual containers)**
```bash
# Relay server
docker run -d -p 7000:7000 -v relay-data:/data \
  $(docker build -q ./relay)

# Storage node (local disk)
docker run -d -p 7001:7001 -v storage-data:/data \
  -e STORAGE_DIR=/data -e STORAGE_CAPACITY=1073741824 \
  $(docker build -q ./storage-node)

# Storage node (S3 backend — works with AWS S3, MinIO, R2, B2)
docker run -d -p 7001:7001 \
  -e STORAGE_BACKEND=s3 \
  -e S3_BUCKET=my-helppeer-bucket \
  -e S3_REGION=us-east-1 \
  -e S3_ENDPOINT=https://s3.amazonaws.com \
  -e S3_ACCESS_KEY=AKIA... \
  -e S3_SECRET_KEY=... \
  -e STORAGE_CAPACITY=10737418240 \
  $(docker build -q ./storage-node)
```

**Option 3: Bare metal**
```bash
# Start relay server (default port 7000)
RELAY_DIR=/tmp/helppeer-relay ./relay/relay-server

# Start storage node (default port 7001, 1GB capacity)
STORAGE_DIR=/tmp/helppeer-storage STORAGE_CAPACITY=1073741824 ./storage-node/storage-node

# Storage node with S3 backend
STORAGE_BACKEND=s3 S3_BUCKET=my-bucket S3_ACCESS_KEY=... S3_SECRET_KEY=... \
  ./storage-node/storage-node
```

### Transfer Files

**Rust CLI:**
```bash
# Send a directory
./client/target/release/helppeer send ./my-model/ --name "Llama-3-70B"

# Receive with the code
./client/target/release/helppeer receive 38-vortex-xenon --output ./received/

# Machine-readable JSON output (for agents/scripts)
./client/target/release/helppeer --json send ./my-model/ --name "Llama-3-70B"
./client/target/release/helppeer --json receive 38-vortex-xenon --output ./received/
```

**Python SDK:**
```python
import helppeer

# Send a model directory
code = helppeer.send("./my-model", name="Llama-3-70B")
print(f"Transfer code: {code}")

# Receive a transfer
helppeer.receive("38-vortex-xenon", output_dir="./received")

# Get structured result (for agents)
result = helppeer.send("./my-model", name="Llama-3-70B", return_details=True)
# {"code": "38-vortex-xenon", "transfer_name": "Llama-3-70B", "files": 4, "total_bytes": 1056}

# Configure custom servers
helppeer.configure(
    relay="https://relay.helppeer.dev",
    storage_nodes=["https://node1.helppeer.dev", "https://node2.helppeer.dev"],
)
```

**Python CLI** (installed via `pip install helppeer`):
```bash
helppeer send ./my-model --name "Llama-3-70B"
helppeer receive 38-vortex-xenon --output ./received/
```

### Multiple Storage Nodes

```bash
# Start multiple storage nodes on different ports
STORAGE_PORT=7001 STORAGE_DIR=/tmp/node1 ./storage-node/storage-node &
STORAGE_PORT=7002 STORAGE_DIR=/tmp/node2 ./storage-node/storage-node &

# Send using multiple nodes
./client/target/release/helppeer send ./my-model/ --nodes http://127.0.0.1:7001,http://127.0.0.1:7002
```

## Architecture

```
┌─────────┐     ┌─────────┐     ┌──────────────┐
│  Sender  │────▶│  Relay   │◀────│  Receiver    │
│ (Rust)   │     │  (Go)    │     │  (Rust)      │
└─────────┘     └─────────┘     └──────────────┘
     │                               │
     │          ┌─────────────┐       │
     └─────────▶│ Storage Node│◀──────┘
         shards │   (Go)      │ shards
                └─────────────┘
```

- **Relay Server** (Go): Stores encrypted manifests indexed by `BLAKE3(K_index)`. One-time retrieval. Never sees plaintext.
- **Storage Node** (Go): Stores encrypted shards with TTL. Zero-knowledge — cannot decrypt shard contents.
- **Client** (Rust): Handles PAKE key derivation, AES-256-GCM encryption, Reed-Solomon erasure coding (8+4), manifest building, upload/download, and file validation.
- **Python SDK**: Pure Python implementation of the full protocol. `pip install helppeer` — zero external binaries required. Includes CLI, programmatic API, and agent-friendly structured output.

## Security

- **End-to-end encryption**: All data is encrypted with AES-256-GCM before leaving the sender's machine
- **Zero-knowledge storage**: Storage nodes and relays never see plaintext or encryption keys
- **Erasure coding**: 8 data + 4 parity shards — survives 4 node failures
- **Safetensors validation**: Files ending in `.safetensors` are validated in-memory before writing to disk
- **One-time manifest retrieval**: Relay deletes manifest after first download
- **TTL expiry**: All shards auto-expire after 24 hours

## Configuration

### Relay Server

| Env Var | Default | Description |
|---|---|---|
| `RELAY_PORT` | `7000` | Listen port |
| `RELAY_DIR` | `/tmp/helppeer-relay` | Data directory for manifests |

### Storage Node

| Env Var | Default | Description |
|---|---|---|
| `STORAGE_PORT` | `7001` | Listen port |
| `STORAGE_BACKEND` | `disk` | Storage backend: `disk` or `s3` |
| `STORAGE_DIR` | `/tmp/helppeer-storage` | Data directory for shards (disk backend) |
| `STORAGE_CAPACITY` | `1073741824` (1GB) | Max storage capacity in bytes |
| `STORAGE_TTL` | `86400` (24h) | Shard TTL in seconds |
| `S3_BUCKET` | — | S3 bucket name (s3 backend) |
| `S3_REGION` | `us-east-1` | S3 region (s3 backend) |
| `S3_ENDPOINT` | — | S3 endpoint URL for MinIO/R2/B2 (s3 backend) |
| `S3_ACCESS_KEY` | — | S3 access key (s3 backend) |
| `S3_SECRET_KEY` | — | S3 secret key (s3 backend) |
| `S3_PREFIX` | `shards` | Key prefix in bucket (s3 backend) |

### Client

| Flag | Default | Description |
|---|---|---|
| `--relay` | `http://127.0.0.1:7000` | Relay server URL |
| `--nodes` | `http://127.0.0.1:7001` | Comma-separated storage node URLs |
| `--json` | off | Machine-readable JSON output for agents/scripts |

### Python SDK

| Env Var | Default | Description |
|---|---|---|
| `HELPEER_RELAY_URL` | `http://127.0.0.1:7000` | Relay server URL |
| `HELPEER_STORAGE_NODES` | `http://127.0.0.1:7001` | Comma-separated storage node URLs |

## Project Structure

```
help-peer/
├── architecture_guide_ai_model_adaptation.md  # Full architecture document
├── protocol/SPEC.md                           # Wire protocol specification
├── docker-compose.yml                          # One-command local deployment
├── relay/                                     # Relay server (Go)
│   ├── go.mod
│   ├── main.go
│   └── Dockerfile
├── storage-node/                              # Storage node (Go)
│   ├── go.mod
│   ├── main.go                                # HTTP server + backend selection
│   ├── store.go                               # ShardStore interface
│   ├── disk_store.go                          # Local filesystem backend
│   ├── s3_store.go                            # S3-compatible backend (S3, R2, MinIO, B2)
│   └── Dockerfile
├── client/                                    # Client (Rust)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                            # CLI entry point (--json mode)
│       ├── crypto.rs                           # AES-GCM, HKDF, HMAC, BLAKE3
│       ├── erasure.rs                         # Reed-Solomon erasure coding
│       ├── manifest.rs                        # Multi-file manifest builder
│       ├── upload.rs                          # Shard upload pipeline
│       ├── download.rs                        # Shard download + reconstruction
│       └── validator.rs                       # Pluggable file validators
├── sdk/                                       # Python SDK (pip install helppeer)
│   ├── pyproject.toml
│   ├── src/helppeer/
│   │   ├── __init__.py                        # Public API: send(), receive(), configure()
│   │   ├── client.py                          # Upload/download pipelines
│   │   ├── crypto.py                           # AES-GCM, HKDF, HMAC, BLAKE3
│   │   ├── erasure.py                         # Reed-Solomon erasure coding
│   │   ├── manifest.py                        # Manifest builder & parser
│   │   ├── validator.py                       # Safetensors & pluggable validators
│   │   ├── config.py                          # Configuration & env vars
│   │   └── cli.py                             # CLI entry point
│   └── tests/test_sdk.py                      # 15 unit tests
└── README.md
```

## Running Tests

```bash
# Rust unit tests (15 tests)
cd client && cargo test

# Python SDK unit tests (15 tests)
cd sdk && python -m pytest tests/ -v

# End-to-end test (Rust client)
./relay/relay-server &
./storage-node/storage-node &
cd client && cargo run -- send /tmp/test-model --name "test"
cargo run -- receive <CODE> --output /tmp/received
diff -r /tmp/test-model /tmp/received

# End-to-end test (Python SDK)
python -c "import helppeer; r = helppeer.send('/tmp/test-model', return_details=True); helppeer.receive(r['code'], '/tmp/received-py')"
diff -r /tmp/test-model /tmp/received-py
```

## Roadmap

- [x] MVP: single relay, single storage node, HTTP transport
- [x] AES-256-GCM encryption with PAKE key derivation
- [x] Reed-Solomon erasure coding (8+4)
- [x] Safetensors validation
- [x] Multi-file directory transfer
- [x] BLAKE3 hash verification
- [x] Python SDK (pip install helppeer)
- [x] Rust CLI --json mode for agent integration
- [ ] DHT-based node discovery (Kademlia)
- [ ] NAT traversal (UDP hole-punching)
- [ ] QUIC transport
- [ ] Resumable downloads (SQLite state tracking)
- [ ] SPAKE2 proper key exchange (currently uses HKDF of code)
- [ ] Multiple relay federation
- [ ] Node reputation system
- [ ] Additional validators (ONNX, GGUF, Pickle)

## License

MIT
