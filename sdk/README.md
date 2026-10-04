# Help Peer Python SDK

A Python SDK for asynchronously sharing large file dumps (AI model weights) via the Help Peer network.

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
helppeer send ./model.safetensors          # single files work too
helppeer receive orbit-velvet-zoom-candle-harbor-ember --output ./received

# Global flags go before the subcommand
helppeer --relay https://relay.example.com --nodes https://n1.example.com,https://n2.example.com,https://n3.example.com send ./my-model
helppeer --json receive orbit-velvet-zoom-candle-harbor-ember   # machine-readable output
```

`python -m helppeer` works the same way.

Transfers are fully compatible with the Rust CLI and the web UI: a code from any of them can be received with any other. Every shard and every received file is checked against its BLAKE3 hash.

If a download fails partway (e.g. a storage node is briefly unreachable), run `receive` again with the same code: the relay keeps the transfer until a receiver confirms it was fully received. `receive()` returns `"acknowledged": True` once that confirmation succeeds.
