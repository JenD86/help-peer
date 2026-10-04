# Help Peer Python SDK

A Python SDK for asynchronously sharing large file dumps (AI model weights) via the Help Peer network.

**Agents:** every CLI command takes `--json` (one JSON object on stdout, exit code 0/1), and `receive` is safe to retry. The output fields and retry rules are in the [main README](https://github.com/JenD86/help-peer#for-ai-agents).

## Installation

```bash
pip install helppeer
```

## Quick Start

```python
import helppeer

# Send a model directory
code = helppeer.send("./my-model", name="Llama-3-70B")
print(f"Transfer code: {code}")
# Share this code with the recipient. Data lives for 24 hours.

# Receive a transfer
helppeer.receive("orbit-velvet-zoom-candle-harbor-ember", output_dir="./received")
```

## Configuration

```python
import helppeer

# Use custom relay and storage nodes
helppeer.configure(
    relay="https://relay.helppeer.dev",
    storage_nodes=["https://node1.helppeer.dev", "https://node2.helppeer.dev"],
)

# Or use environment variables:
# HELPEER_RELAY_URL, HELPEER_STORAGE_NODES (comma-separated)
```

## Agent Integration

```python
import helppeer
import json

# Send and get structured result
result = helppeer.send("./model-weights", name="my-model", return_details=True)
# result = {"code": "orbit-velvet-zoom-candle-harbor-ember", "transfer_name": "my-model", "files": 4, "total_bytes": 1056}

# Receive with progress callback
def on_progress(file_path, segment, total_segments):
    print(f"  {file_path}: {segment}/{total_segments} segments")

helppeer.receive("orbit-velvet-zoom-candle-harbor-ember", output_dir="./received", progress=on_progress)
```

## CLI

The SDK also installs a `helppeer` CLI:

```bash
helppeer send ./my-model --name "Llama-3-70B"
helppeer send ./model.safetensors --message "Checkpoint from step 12k"   # single file, with a note
helppeer info orbit-velvet-zoom-candle-harbor-ember   # preview name, message and files without downloading
helppeer receive orbit-velvet-zoom-candle-harbor-ember --output ./received
helppeer cancel orbit-velvet-zoom-candle-harbor-ember   # withdraw a transfer before it expires

# Global flags go before the subcommand
helppeer --relay https://relay.example.com --nodes https://n1.example.com,https://n2.example.com,https://n3.example.com send ./my-model
helppeer --json receive orbit-velvet-zoom-candle-harbor-ember   # machine-readable output
```

`python -m helppeer` works the same way.

## Usernames and inbox

On a Help Peer website, create an API token on the Account page, then:

```python
import helppeer

helppeer.login("https://helppeer.example.com", "hp_...")      # saved for the SDK and CLI
helppeer.send("./my-model", to=["alice", "bob@example.com"])  # usernames go to their inbox
for item in helppeer.inbox():                                 # transfers sent to you
    helppeer.receive(item["code"], output_dir="./received")   # also clears the inbox item
helppeer.logout()
```

The CLI equivalents are `helppeer login --server ... --token ...`, `helppeer send PATH --to alice,bob@example.com`, `helppeer inbox` and `helppeer logout`. While logged in, the SDK uses the website's relay and storage nodes unless you `configure()` others.

Transfers are fully compatible with the Rust CLI and the web UI: a code from any of them can be received with any other. Every shard and every received file is checked against its BLAKE3 hash.

If a download fails partway (e.g. a storage node is briefly unreachable), run `receive` again with the same code: the relay keeps the transfer until a receiver confirms it was fully received. `receive()` returns `"acknowledged": True` once that confirmation succeeds. Retries resume where the previous attempt stopped: progress is kept in `<output_dir>/.helppeer/` (and removed on success), segments already on disk are re-checked against their hashes, and `"resumed_segments"` in the result says how many were reused. The Rust CLI uses the same format, so either can finish a download the other started.
