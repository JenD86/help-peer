# Help Peer

A free, decentralized system for asynchronously sharing large file dumps — mainly AI model weights — without requiring the sender to stay online.

Think "Wormhole meets BitTorrent, but the sender can leave."

## How It Works

1. **Sender** runs `helppeer send ./my-model/` and gets a code like `orbit-velvet-zoom-candle-harbor-ember`
2. The files are encrypted (AES-256-GCM), split into 64MB segments, erasure-coded (8+4 Reed-Solomon), and the 12 shards per segment are uploaded to volunteer storage nodes
3. The encrypted manifest is uploaded to a relay server
4. **Sender can go offline**
5. **Receiver** runs `helppeer receive orbit-velvet-zoom-candle-harbor-ember` — the code derives the encryption keys, fetches the manifest from the relay, downloads shards from storage nodes (checking each against its BLAKE3 hash), reconstructs, decrypts, and verifies each file against the sender's BLAKE3 hash
6. Once everything is verified, the receiver confirms with the relay, which deletes the manifest. If the download fails partway, just run the same command again: the CLI and Python SDK resume where they stopped (progress is kept in `<output>/.helppeer/` until the download completes)
7. Shards and manifests auto-expire after 24 hours (TTL)

The Rust CLI, Python SDK and web UI implement the same protocol, so a code from any one of them can be received with any other.

## Quick Start

### Prerequisites

- Go 1.18+ (for relay and storage node; 1.21+ for the web backend)
- Rust 1.70+ (for Rust client)
- Python 3.9+ (for Python SDK)
- Node.js 20+ (to build the web frontend)

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
cp .env.example .env   # then fill in SMTP settings, or delete them for dev mode
docker compose up -d
# Web UI on :8080, relay on :7000, storage node on :7001
```

Without SMTP settings the web backend runs in dev mode and logs login links and notification emails instead of sending them. For a public deployment set `WEB_BASE_URL` in `.env` to the URL users visit.

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
./client/target/release/helppeer receive orbit-velvet-zoom-candle-harbor-ember --output ./received/

# Send a single file
./client/target/release/helppeer send ./model.safetensors

# Cancel a transfer before it expires (removes it from the relay and deletes its shards)
./client/target/release/helppeer cancel orbit-velvet-zoom-candle-harbor-ember

# Machine-readable JSON output (for agents/scripts)
./client/target/release/helppeer --json send ./my-model/ --name "Llama-3-70B"
./client/target/release/helppeer --json receive orbit-velvet-zoom-candle-harbor-ember --output ./received/
```

**Python SDK:**
```python
import helppeer

# Send a model directory
code = helppeer.send("./my-model", name="Llama-3-70B")
print(f"Transfer code: {code}")

# Receive a transfer
helppeer.receive("orbit-velvet-zoom-candle-harbor-ember", output_dir="./received")

# Cancel a transfer before it expires
helppeer.cancel("orbit-velvet-zoom-candle-harbor-ember")

# Get structured result (for agents)
result = helppeer.send("./my-model", name="Llama-3-70B", return_details=True)
# {"code": "orbit-velvet-zoom-candle-harbor-ember", "transfer_name": "Llama-3-70B", "files": 4, "total_bytes": 1056}

# Configure custom servers
helppeer.configure(
    relay="https://relay.helppeer.dev",
    storage_nodes=["https://node1.helppeer.dev", "https://node2.helppeer.dev"],
)
```

**Python CLI** (installed via `pip install helppeer`):
```bash
helppeer send ./my-model --name "Llama-3-70B"
helppeer receive orbit-velvet-zoom-candle-harbor-ember --output ./received/
helppeer --json receive orbit-velvet-zoom-candle-harbor-ember   # JSON output
python -m helppeer --help                                       # also works
```

**Web UI:**
Open `http://localhost:8080` in your browser. Drag & drop files to send, or enter a code to receive. Files are encrypted in the browser and uploaded 64MB at a time; the backend only ever sees ciphertext, which it erasure-codes and stores. In Chromium-based browsers, received files stream straight into a folder you pick; other browsers assemble each file in memory, so use the CLI for very large transfers there. A failed browser download can be retried with the same code but starts over, whereas the CLI and Python SDK resume. After sending, the "Cancel transfer" button withdraws the transfer and deletes its stored data (or use `helppeer cancel <code>` later). Log in with email for transfer history and to email the code to recipients (the code then passes through the server and the recipients' mail providers).

### Multiple Storage Nodes

```bash
# Start multiple storage nodes on different ports
STORAGE_PORT=7001 STORAGE_DIR=/tmp/node1 ./storage-node/storage-node &
STORAGE_PORT=7002 STORAGE_DIR=/tmp/node2 ./storage-node/storage-node &

# Send using multiple nodes
./client/target/release/helppeer send ./my-model/ --nodes http://127.0.0.1:7001,http://127.0.0.1:7002,http://127.0.0.1:7003
```

Shards are assigned round-robin, so the number of nodes decides how many node failures a transfer survives: with 3+ nodes each holds at most 4 of a segment's 12 shards, so any one node can be lost; with 12+ nodes any four can. Clients warn when fewer than 3 nodes are configured.

If a node fails while sending, its shards are stored on the remaining nodes instead (with a warning, since the transfer then tolerates fewer node failures).

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

- **Relay Server** (Go): Stores encrypted manifests indexed by `BLAKE3(K_index)` until receivers confirm or they expire. Never sees plaintext.
- **Storage Node** (Go): Stores encrypted shards with TTL. Zero-knowledge — cannot decrypt shard contents.
- **Client** (Rust): Handles key derivation from the transfer code, AES-256-GCM encryption, Reed-Solomon erasure coding (8+4), manifest building, upload/download, and file validation.
- **Python SDK**: Pure Python implementation of the full protocol (with numpy for fast erasure coding). `pip install helppeer` — zero external binaries required. Includes CLI, programmatic API, and agent-friendly structured output.
- **Web** (React + Go): The browser derives keys and encrypts; the Go backend erasure-codes ciphertext, talks to the relay and storage nodes, and handles login and email notifications.

`protocol/test-vectors.json` holds key-derivation and erasure-coding vectors that the Rust, Python and Go test suites all check, so the implementations can't drift apart.

## Security

- **End-to-end encryption**: All data is encrypted with AES-256-GCM before leaving the sender's machine
- **High-entropy transfer codes**: 6 words from the EFF long wordlist (~77 bits), drawn from the OS CSPRNG. Because sender and receiver are never online together there is no PAKE — the code is the key — so it must be long enough to resist offline guessing and relay enumeration
- **Argon2id key stretching**: Keys are derived from the code with Argon2id (64 MiB, 3 passes) before HKDF, so each guess costs real memory and time on top of the code's entropy
- **Safe extraction**: receivers reject manifest paths that are absolute or contain `..`, so a sender cannot write outside the chosen output directory
- **Zero-knowledge storage**: Storage nodes and relays never see plaintext or encryption keys
- **Integrity checks**: Storage nodes refuse shards whose content doesn't match their BLAKE3 name; receivers discard shards that fail their hash and rebuild from parity, then check every file against the sender's BLAKE3 hash
- **Erasure coding**: 8 data + 4 parity shards — any 8 of 12 rebuild a segment (see [Multiple Storage Nodes](#multiple-storage-nodes) for what that means per node)
- **Manifest validation**: Receivers check the manifest's sizes, indexes and paths before allocating or writing anything
- **Safetensors validation**: The header of each `.safetensors` file is validated when its first segment arrives
- **Confirmed retrieval**: The relay deletes a manifest once the receiver confirms a verified download, using a secret from inside the encrypted manifest (or once each recipient has, for multi-recipient transfers via `X-Max-Retrievals`). Until then, failed downloads can be retried with the same code
- **Delete tokens**: Shards can only be deleted early with a token from the encrypted manifest (used by `helppeer cancel`); otherwise they expire by TTL
- **Rate limiting**: The relay and web backend throttle clients that make repeated failed manifest lookups (code guessing) and limit manifest uploads per client; the relay also caps its total storage. The web backend limits login and notification emails. Limits are saved to `ratelimits.json` in each service's data directory (every 10 seconds and on shutdown), so restarting doesn't reset them
- **TTL expiry**: Shards and manifests auto-expire after 24 hours, including across restarts
- **Web trust model**: The web backend serves the page that does the encryption, so web users trust the server operator not to tamper with it. The server never stores transfer codes

## Configuration

### Relay Server

| Env Var | Default | Description |
|---|---|---|
| `RELAY_PORT` | `7000` | Listen port |
| `RELAY_DIR` | `/tmp/helppeer-relay` | Data directory for manifests |
| `RELAY_MAX_RETRIEVALS` | `1` | Default max retrievals per manifest (override via `X-Max-Retrievals` header, max 1000) |
| `RELAY_TTL` | `86400` (24h) | Manifest TTL in seconds |
| `RELAY_MAX_MANIFEST_BYTES` | `33554432` (32MB) | Largest manifest accepted |
| `RELAY_MISS_LIMIT` | `30` | Failed lookups/confirmations allowed per client IP per minute before returning 429 |
| `RELAY_PUT_LIMIT` | `120` | Manifest uploads allowed per client IP per minute (`0` = unlimited) |
| `RELAY_MAX_TOTAL_BYTES` | `1073741824` (1GB) | Total manifest storage; uploads get 507 when full |

A web backend reaches the relay from a single address for all its users, so it applies its own per-user limits; raise `RELAY_PUT_LIMIT` if a busy web backend hits the relay's limit.

### Storage Node

| Env Var | Default | Description |
|---|---|---|
| `STORAGE_PORT` | `7001` | Listen port |
| `STORAGE_BACKEND` | `disk` | Storage backend: `disk` or `s3` |
| `STORAGE_DIR` | `/tmp/helppeer-storage` | Data directory for shards (disk backend) |
| `STORAGE_CAPACITY` | `1073741824` (1GB) | Max storage capacity in bytes |
| `STORAGE_TTL` | `86400` (24h) | Shard TTL in seconds |
| `STORAGE_MAX_SHARD_BYTES` | `16777216` (16MB) | Largest shard accepted |
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

The Python CLI takes the same `--relay`, `--nodes` and `--json` flags as the Rust CLI.

### Web Backend

| Env Var | Default | Description |
|---|---|---|
| `WEB_PORT` | `8080` | Listen port |
| `RELAY_URL` | `http://127.0.0.1:7000` | Relay server URL |
| `STORAGE_NODES` | `http://127.0.0.1:7001` | Comma-separated storage node URLs, as the backend reaches them |
| `STORAGE_NODES_PUBLIC` | `STORAGE_NODES` | The same nodes (same order) as other clients reach them; written into manifests so CLI users can receive web transfers |
| `WEB_TRUST_PROXY` | off | Set to `1` behind a reverse proxy so rate limits use `X-Forwarded-For`. Leave off otherwise, or clients can spoof their address |
| `WEB_BASE_URL` | `http://localhost:{WEB_PORT}` | Public URL used in login emails. **Required when SMTP is configured** |
| `WEB_DATA_DIR` | `/tmp/helppeer-web` | Data directory for user DB |
| `SMTP_HOST` | — | SMTP server hostname (e.g. `smtp.gmail.com`) |
| `SMTP_PORT` | — | SMTP port (`465` for TLS, `587` for STARTTLS) |
| `SMTP_USER` | — | SMTP username (e.g. your Gmail address) |
| `SMTP_PASS` | — | SMTP password (use an app password for Gmail) |
| `SMTP_FROM` | `SMTP_USER` | From email address |

## Project Structure

```
help-peer/
├── architecture_guide_ai_model_adaptation.md  # Full architecture document
├── protocol/
│   ├── SPEC.md                                # Wire protocol specification
│   ├── test-vectors.json                      # Cross-implementation test vectors
│   └── wordlist.txt                           # EFF long wordlist for transfer codes
├── docker-compose.yml                          # One-command local deployment
├── relay/                                     # Relay server (Go)
│   ├── go.mod
│   ├── main.go
│   ├── main_test.go
│   └── Dockerfile
├── storage-node/                              # Storage node (Go)
│   ├── go.mod
│   ├── main.go                                # HTTP server + backend selection
│   ├── store.go                               # ShardStore interface
│   ├── disk_store.go                          # Local filesystem backend
│   ├── s3_store.go                            # S3-compatible backend (S3, R2, MinIO, B2)
│   ├── main_test.go
│   └── Dockerfile
├── client/                                    # Client (Rust)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                            # CLI entry point (--json mode)
│       ├── cancel.rs                          # Cancel a transfer early
│       ├── crypto.rs                          # AES-GCM, HKDF, BLAKE3
│       ├── http.rs                            # Shared HTTP client with timeouts + retries
│       ├── resume.rs                          # Progress log for resuming downloads
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
│   │   ├── crypto.py                          # AES-GCM, HKDF, BLAKE3
│   │   ├── erasure.py                         # Reed-Solomon erasure coding
│   │   ├── manifest.py                        # Manifest builder & parser
│   │   ├── resume.py                          # Progress log for resuming downloads
│   │   ├── validator.py                       # Safetensors & pluggable validators
│   │   ├── config.py                          # Configuration & env vars
│   │   └── cli.py                             # CLI entry point
│   └── tests/test_sdk.py                      # Unit tests
├── web/                                       # Web frontend + backend
│   ├── Dockerfile                             # Multi-stage: Node + Go -> single container
│   ├── backend/                               # Go web backend (serves API + static files)
│   │   ├── go.mod
│   │   ├── main.go                             # HTTP server, routes, static embedding
│   │   ├── auth.go                             # Magic link auth, sessions
│   │   ├── db.go                               # File-based store for users, sessions
│   │   ├── upload.go                           # Erasure coding + shard upload, manifest upload
│   │   ├── download.go                         # Shard download + reconstruction
│   │   ├── notify.go                           # SMTP email notifications
│   │   ├── cancel.go                           # Cancel a transfer sent from the browser
│   │   ├── ratelimit.go                        # Per-client rate limiting
│   │   └── *_test.go
│   └── frontend/                               # React frontend (Vite + Tailwind)
│       ├── package.json
│       ├── vite.config.ts
│       └── src/
│           ├── App.tsx                         # Router + layout
│           ├── pages/                          # Landing, Login, Verify, Upload, Download, History
│           └── lib/                            # crypto.ts (WebCrypto + BLAKE3), api.ts (API client)
└── README.md
```

## Running Tests

```bash
# Rust unit tests
cd client && cargo test

# Python SDK unit tests
cd sdk && python -m pytest tests/ -v

# Go tests (relay, storage node, web backend)
(cd relay && go test ./...)
(cd storage-node && go test ./...)
(cd web/backend && go test ./...)

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
- [x] AES-256-GCM encryption with code-based key derivation
- [x] Reed-Solomon erasure coding (8+4)
- [x] Safetensors validation
- [x] Multi-file directory transfer
- [x] BLAKE3 hash verification
- [x] Python SDK (pip install helppeer)
- [x] Rust CLI --json mode for agent integration
- [x] Web frontend (React + Go, browser-side encryption, email notifications, multi-recipient)
- [x] Cross-client compatibility (CLI, Python and web share codes, with shared test vectors)
- [ ] DHT-based node discovery (Kademlia)
- [ ] NAT traversal (UDP hole-punching)
- [ ] QUIC transport
- [x] Resumable downloads in the CLI and Python SDK (the web UI retries from the beginning)
- [x] Argon2id key stretching of transfer codes
- [x] Retry-safe retrieval (manifest deleted on confirmation, not on fetch)
- [ ] Multiple relay federation
- [ ] Node reputation system
- [ ] Additional validators (ONNX, GGUF, Pickle)

## License

MIT
