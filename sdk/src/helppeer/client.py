"""Help Peer client — send and receive file transfers."""
import os
import random
import requests
from typing import Optional, Callable, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import get_config
from . import crypto
from . import erasure
from .manifest import (
    Manifest, ManifestFile, ManifestSegment, ManifestShard,
    build_manifest, read_file_segment,
)
from .validator import ValidatorRegistry


def send(
    path: str,
    name: str = "untitled-transfer",
    *,
    return_details: bool = False,
) -> str | Dict[str, Any]:
    """Send a file or directory. Returns the transfer code.

    Args:
        path: Path to the file or directory to send.
        name: Human-readable name for the transfer.
        return_details: If True, return a dict with full transfer details.

    Returns:
        Transfer code string (e.g., "38-vortex-xenon"), or a dict if return_details=True.
    """
    config = get_config()
    code = _generate_code()
    k_data, k_index = crypto.derive_keys(code)
    r_hash = crypto.relay_hash(k_index)

    if os.path.isfile(path):
        # Single file: wrap in a temporary directory structure
        manifest = _send_single_file(path, name, k_data, config)
    else:
        manifest = _send_directory(path, name, k_data, config)

    # Encrypt and upload manifest
    manifest_json = manifest.to_json()
    encrypted_manifest = crypto.encrypt_segment(k_data, manifest_json)
    _upload_manifest(config.relay_url, r_hash, encrypted_manifest)

    if return_details:
        return {
            "code": code,
            "transfer_name": name,
            "files": len(manifest.files),
            "total_bytes": manifest.total_bytes,
        }
    return code


def receive(
    code: str,
    output_dir: str = "./received",
    *,
    progress: Optional[Callable[[str, int, int], None]] = None,
) -> Dict[str, Any]:
    """Receive a transfer using a code.

    Args:
        code: The transfer code (e.g., "38-vortex-xenon").
        output_dir: Directory to save received files.
        progress: Optional callback(file_path, segment_index, total_segments).

    Returns:
        Dict with transfer details: transfer_name, files, total_bytes, file_hashes.
    """
    config = get_config()
    k_data, k_index = crypto.derive_keys(code)
    r_hash = crypto.relay_hash(k_index)

    # Download encrypted manifest from relay
    encrypted_manifest = _download_manifest(config.relay_url, r_hash)
    manifest_json = crypto.decrypt_segment(k_data, encrypted_manifest)
    manifest = Manifest.from_json(manifest_json)

    # Pre-allocate files
    os.makedirs(output_dir, exist_ok=True)
    for f in manifest.files:
        file_path = os.path.join(output_dir, f.path)
        os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
        with open(file_path, "wb") as fh:
            fh.truncate(f.size)

    # Download and reconstruct each file
    registry = ValidatorRegistry()
    file_hashes = {}

    for f in manifest.files:
        file_path = os.path.join(output_dir, f.path)
        total_segments = len(f.segments)

        for seg_idx, segment in enumerate(f.segments):
            # Download shards
            shard_data = _download_shards(segment)

            # Reconstruct encrypted segment
            encrypted = erasure.decode_segment(shard_data, segment.encrypted_size)

            # Decrypt
            plaintext = crypto.decrypt_segment(k_data, encrypted)

            # Validate first segment
            if seg_idx == 0:
                validator = registry.validator_for(f.path)
                validator.validate_first_segment(plaintext)

            # Write to file at offset
            offset = seg_idx * config.segment_size
            with open(file_path, "r+b") as fh:
                fh.seek(offset)
                fh.write(plaintext)

            if progress:
                progress(f.path, seg_idx + 1, total_segments)

        # Compute file hash
        file_hashes[f.path] = _compute_file_hash(file_path)

    return {
        "transfer_name": manifest.transfer_name,
        "files": len(manifest.files),
        "total_bytes": manifest.total_bytes,
        "file_hashes": file_hashes,
    }


def _send_directory(dir_path: str, name: str, k_data: bytes, config) -> Manifest:
    """Send a directory."""
    manifest = build_manifest(dir_path, name, config.segment_size)
    manifest.erasure_data_shards = config.data_shards
    manifest.erasure_parity_shards = config.parity_shards

    for f in manifest.files:
        file_path = os.path.join(dir_path, f.path)
        for seg in f.segments:
            seg_idx = int(seg.id.split("_")[1])
            plaintext = read_file_segment(file_path, seg_idx, config.segment_size)
            encrypted = crypto.encrypt_segment(k_data, plaintext)
            shards = erasure.encode_segment(encrypted)

            shard_infos = []
            for shard_idx, shard in enumerate(shards):
                h = crypto.content_hash(shard)
                node = config.storage_nodes[shard_idx % len(config.storage_nodes)]
                _upload_shard(node, h, shard)
                shard_infos.append(ManifestShard(
                    index=shard_idx, hash=h, node=node,
                ))

            seg.encrypted_size = len(encrypted)
            seg.shards = shard_infos

    return manifest


def _send_single_file(file_path: str, name: str, k_data: bytes, config) -> Manifest:
    """Send a single file by treating it as a one-file directory."""
    dir_path = os.path.dirname(file_path) or "."
    filename = os.path.basename(file_path)
    manifest = build_manifest(dir_path, name, config.segment_size)
    manifest.erasure_data_shards = config.data_shards
    manifest.erasure_parity_shards = config.parity_shards

    # Filter to only the requested file
    manifest.files = [f for f in manifest.files if f.path == filename]
    manifest.total_bytes = sum(f.size for f in manifest.files)

    for f in manifest.files:
        full_path = os.path.join(dir_path, f.path)
        for seg in f.segments:
            seg_idx = int(seg.id.split("_")[1])
            plaintext = read_file_segment(full_path, seg_idx, config.segment_size)
            encrypted = crypto.encrypt_segment(k_data, plaintext)
            shards = erasure.encode_segment(encrypted)

            shard_infos = []
            for shard_idx, shard in enumerate(shards):
                h = crypto.content_hash(shard)
                node = config.storage_nodes[shard_idx % len(config.storage_nodes)]
                _upload_shard(node, h, shard)
                shard_infos.append(ManifestShard(
                    index=shard_idx, hash=h, node=node,
                ))

            seg.encrypted_size = len(encrypted)
            seg.shards = shard_infos

    return manifest


def _upload_shard(node_url: str, hash_hex: str, data: bytes) -> None:
    """Upload a shard to a storage node."""
    url = f"{node_url}/shard/{hash_hex}"
    resp = requests.put(url, data=data, headers={"Content-Type": "application/octet-stream"})
    if not resp.status_code in (200, 201):
        raise RuntimeError(f"shard upload to {node_url} returned {resp.status_code}")


def _upload_manifest(relay_url: str, r_hash: str, data: bytes) -> None:
    """Upload encrypted manifest to relay."""
    url = f"{relay_url}/manifest/{r_hash}"
    resp = requests.put(url, data=data, headers={"Content-Type": "application/octet-stream"})
    if not resp.status_code in (200, 201):
        raise RuntimeError(f"manifest upload returned {resp.status_code}")


def _download_manifest(relay_url: str, r_hash: str) -> bytes:
    """Download encrypted manifest from relay (one-time retrieval)."""
    url = f"{relay_url}/manifest/{r_hash}"
    resp = requests.get(url)
    if resp.status_code != 200:
        raise RuntimeError(f"manifest download returned {resp.status_code}")
    return resp.content


def _download_shards(segment: ManifestSegment) -> List[Optional[bytes]]:
    """Download all shards for a segment concurrently."""
    config = get_config()
    total_shards = config.data_shards + config.parity_shards
    shards: List[Optional[bytes]] = [None] * total_shards

    def fetch_shard(shard: ManifestShard) -> tuple[int, Optional[bytes]]:
        url = f"{shard.node}/shard/{shard.hash}"
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                return shard.index, resp.content
        except Exception:
            pass
        return shard.index, None

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(fetch_shard, s) for s in segment.shards]
        for future in as_completed(futures):
            idx, data = future.result()
            if data is not None:
                shards[idx] = data

    return shards


def _compute_file_hash(filepath: str) -> str:
    """Compute BLAKE3 hash of a file."""
    import blake3
    h = blake3.blake3()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


_WORDS = [
    "orbit", "velvet", "guitar", "battery", "candle", "dragon", "ember",
    "falcon", "galaxy", "harbor", "iris", "jungle", "kettle", "lantern",
    "meadow", "nebula", "ocean", "phoenix", "quartz", "raven", "silver",
    "thunder", "umbra", "vortex", "willow", "xenon", "yonder", "zephyr",
    "amber", "breeze",
]


def _generate_code() -> str:
    """Generate a human-readable transfer code: number-word-word."""
    num = random.randint(1, 99)
    w1 = random.choice(_WORDS)
    w2 = random.choice(_WORDS)
    return f"{num}-{w1}-{w2}"
