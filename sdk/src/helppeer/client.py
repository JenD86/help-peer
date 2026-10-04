"""Help Peer client — send and receive file transfers."""
from __future__ import annotations

import functools
import os
import secrets
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import blake3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import get_config
from . import crypto
from . import erasure
from .manifest import (
    Manifest, ManifestSegment, ManifestShard,
    build_manifest, read_file_segment, safe_output_path,
)
from .validator import ValidatorRegistry

# (connect, read) timeouts in seconds for every request.
TIMEOUT = (10, 300)


def send(
    path: str,
    name: str = "untitled-transfer",
    *,
    return_details: bool = False,
) -> Union[str, Dict[str, Any]]:
    """Send a file or directory. Returns the transfer code.

    Args:
        path: Path to the file or directory to send.
        name: Human-readable name for the transfer.
        return_details: If True, return a dict with full transfer details.

    Returns:
        Transfer code string (e.g., "orbit-velvet-zoom-candle-harbor-ember"), or a dict if return_details=True.
    """
    config = get_config()
    if not config.storage_nodes:
        raise ValueError("no storage nodes configured")
    total_shards = config.data_shards + config.parity_shards
    _warn_if_too_few_nodes(len(config.storage_nodes), total_shards, config.parity_shards)

    code = _generate_code()
    k_data, k_index = crypto.derive_keys(code)
    r_hash = crypto.relay_hash(k_index)

    manifest, base_dir = build_manifest(path, name, config.segment_size)
    manifest.erasure_data_shards = config.data_shards
    manifest.erasure_parity_shards = config.parity_shards
    manifest.ack_secret = crypto.new_secret()
    manifest.delete_token = crypto.new_secret()
    uploader = _ShardUploader(config.storage_nodes, crypto.secret_hash(manifest.delete_token))

    with _session() as session, ThreadPoolExecutor(max_workers=total_shards) as pool:
        for f in manifest.files:
            file_path = os.path.join(base_dir, *f.path.split("/"))
            hasher = blake3.blake3()

            for seg_idx, seg in enumerate(f.segments):
                plaintext = read_file_segment(file_path, seg_idx, manifest.segment_size)
                if len(plaintext) != seg.original_size:
                    raise RuntimeError(f"{f.path} changed size while being sent")
                hasher.update(plaintext)

                encrypted = crypto.encrypt_segment(k_data, plaintext)
                shards = erasure.encode_segment(
                    encrypted, manifest.erasure_data_shards, manifest.erasure_parity_shards
                )

                # Upload the shards in parallel (round-robin node assignment)
                futures = [
                    pool.submit(uploader.upload, session, idx, shard)
                    for idx, shard in enumerate(shards)
                ]
                seg.shards = [fut.result() for fut in futures]
                seg.encrypted_size = len(encrypted)

            f.blake3 = hasher.hexdigest()

        if uploader.dead:
            failed = ", ".join(config.storage_nodes[i] for i in sorted(uploader.dead))
            print(
                f"warning: storage node(s) {failed} failed; their shards were stored on the "
                "remaining nodes, so this transfer tolerates fewer node failures",
                file=sys.stderr,
            )

        # Encrypt and upload manifest
        encrypted_manifest = crypto.encrypt_segment(k_data, manifest.to_json())
        _upload_manifest(
            session, config.relay_url, r_hash, encrypted_manifest,
            crypto.secret_hash(manifest.ack_secret),
        )

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
        code: The transfer code (e.g., "orbit-velvet-zoom-candle-harbor-ember").
        output_dir: Directory to save received files.
        progress: Optional callback(file_path, segment_index, total_segments).

    Returns:
        Dict with transfer details: transfer_name, files, total_bytes, file_hashes.
    """
    config = get_config()
    k_data, k_index = crypto.derive_keys(code)
    r_hash = crypto.relay_hash(k_index)

    with _session() as session:
        # Download encrypted manifest from relay. It stays there until we
        # confirm success below, so a failed download can be retried.
        encrypted_manifest = _download_manifest(session, config.relay_url, r_hash)
        manifest = Manifest.from_json(crypto.decrypt_segment(k_data, encrypted_manifest))
        manifest.validate()
        total_shards = manifest.erasure_data_shards + manifest.erasure_parity_shards

        # Validate every path before touching the filesystem.
        file_paths = {f.path: safe_output_path(output_dir, f.path) for f in manifest.files}

        # Pre-allocate files
        os.makedirs(output_dir, exist_ok=True)
        for f in manifest.files:
            file_path = file_paths[f.path]
            os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
            with open(file_path, "wb") as fh:
                fh.truncate(f.size)

        # Download and reconstruct each file
        registry = ValidatorRegistry()
        file_hashes = {}

        with ThreadPoolExecutor(max_workers=total_shards) as pool:
            for f in manifest.files:
                file_path = file_paths[f.path]
                total_segments = len(f.segments)

                for seg_idx, segment in enumerate(f.segments):
                    shard_data = _download_shards(
                        session, pool, segment,
                        manifest.erasure_data_shards, manifest.erasure_parity_shards,
                    )
                    encrypted = erasure.decode_segment(
                        shard_data, segment.encrypted_size,
                        manifest.erasure_data_shards, manifest.erasure_parity_shards,
                    )
                    plaintext = crypto.decrypt_segment(k_data, encrypted)

                    if seg_idx == 0:
                        registry.validator_for(f.path).validate_first_segment(plaintext)

                    with open(file_path, "r+b") as fh:
                        fh.seek(seg_idx * manifest.segment_size)
                        fh.write(plaintext)

                    if progress:
                        progress(f.path, seg_idx + 1, total_segments)

                # Check the reassembled file against the sender's hash, when provided
                file_hash = _compute_file_hash(file_path)
                if f.blake3 is not None and file_hash != f.blake3:
                    raise ValueError(
                        f"{f.path} is corrupt: BLAKE3 {file_hash} does not match sender's {f.blake3}"
                    )
                file_hashes[f.path] = file_hash

        # Everything verified: confirm, which uses up this recipient's retrieval.
        acknowledged = _acknowledge(session, config.relay_url, r_hash, manifest.ack_secret)

    return {
        "transfer_name": manifest.transfer_name,
        "files": len(manifest.files),
        "total_bytes": manifest.total_bytes,
        "file_hashes": file_hashes,
        "acknowledged": acknowledged,
    }


def _session() -> requests.Session:
    """A pooled session that retries transient failures (connection errors,
    5xx, 429) with backoff."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        # Not POST: a download confirmation isn't idempotent. urllib3 still
        # retries connection failures, where the request never arrived.
        allowed_methods=frozenset({"GET", "PUT"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _warn_if_too_few_nodes(nodes: int, total_shards: int, parity_shards: int) -> None:
    per_node = -(-total_shards // nodes)
    if per_node > parity_shards:
        print(
            f"warning: with {nodes} storage node(s), each holds up to {per_node} of "
            f"{total_shards} shards per segment; losing a single node makes the "
            f"transfer unrecoverable (use at least {-(-total_shards // parity_shards)} nodes)",
            file=sys.stderr,
        )


class _ShardUploader:
    """Uploads shards round-robin, moving a failed node's shards to the next
    healthy node for the rest of the transfer."""

    def __init__(self, nodes: List[str], delete_token_hash: str):
        self.nodes = nodes
        self.delete_token_hash = delete_token_hash
        self.dead: set = set()
        self._lock = threading.Lock()

    def upload(self, session: requests.Session, index: int, data: bytes) -> ManifestShard:
        h = crypto.content_hash(data)
        last_err: Exception = RuntimeError("all storage nodes have failed")
        for offset in range(len(self.nodes)):
            i = (index + offset) % len(self.nodes)
            with self._lock:
                if i in self.dead:
                    continue
            node = self.nodes[i]
            try:
                resp = session.put(
                    f"{node}/shard/{h}", data=data, timeout=TIMEOUT,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "X-Delete-Token-Hash": self.delete_token_hash,
                    },
                )
                if resp.status_code in (200, 201):
                    return ManifestShard(index=index, hash=h, node=node)
                last_err = RuntimeError(f"shard upload to {node} returned {resp.status_code}")
            except requests.RequestException as e:
                last_err = RuntimeError(f"shard upload to {node} failed: {e}")
            with self._lock:
                self.dead.add(i)
        raise last_err


def _upload_manifest(
    session: requests.Session, relay_url: str, r_hash: str, data: bytes, ack_hash: str,
) -> None:
    """Upload encrypted manifest to relay."""
    resp = session.put(
        f"{relay_url}/manifest/{r_hash}", data=data, timeout=TIMEOUT,
        headers={"Content-Type": "application/octet-stream", "X-Ack-Hash": ack_hash},
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"manifest upload returned {resp.status_code}")


def _acknowledge(session: requests.Session, relay_url: str, r_hash: str, ack_secret: str) -> bool:
    """Confirm a completed download with the relay. Failure isn't fatal: the
    manifest then just stays until it expires."""
    try:
        resp = session.post(f"{relay_url}/manifest/{r_hash}/ack", data=ack_secret, timeout=TIMEOUT)
        if resp.status_code == 204:
            return True
        err = f"status {resp.status_code}"
    except requests.RequestException as e:
        err = str(e)
    print(f"warning: could not confirm the download with the relay ({err}); "
          "it will expire on its own", file=sys.stderr)
    return False


def _download_manifest(session: requests.Session, relay_url: str, r_hash: str) -> bytes:
    """Download encrypted manifest from relay (one-time retrieval)."""
    resp = session.get(f"{relay_url}/manifest/{r_hash}", timeout=TIMEOUT)
    if resp.status_code == 404:
        raise RuntimeError(
            "transfer not found: the code is wrong, it expired, or it was already received"
        )
    if resp.status_code != 200:
        raise RuntimeError(f"manifest download returned {resp.status_code}")
    return resp.content


def _download_shards(
    session: requests.Session,
    pool: ThreadPoolExecutor,
    segment: ManifestSegment,
    data_shards: int,
    parity_shards: int,
) -> List[Optional[bytes]]:
    """Download enough shards to rebuild a segment, in parallel. Shards whose
    content doesn't match the manifest hash (corrupt or malicious node) are
    discarded, and we stop as soon as data_shards good shards have arrived."""
    shards: List[Optional[bytes]] = [None] * (data_shards + parity_shards)

    def fetch_shard(shard: ManifestShard) -> Optional[bytes]:
        try:
            resp = session.get(f"{shard.node}/shard/{shard.hash}", timeout=TIMEOUT)
        except requests.RequestException:
            return None
        if resp.status_code == 200 and crypto.content_hash(resp.content) == shard.hash:
            return resp.content
        return None

    futures = {pool.submit(fetch_shard, s): s.index for s in segment.shards}
    have = 0
    for future in as_completed(futures):
        data = future.result()
        if data is not None:
            shards[futures[future]] = data
            have += 1
            if have == data_shards:
                break
    for future in futures:
        future.cancel()  # skip any downloads that haven't started yet

    if have < data_shards:
        raise RuntimeError(
            f"segment {segment.id}: only {have} of {data_shards} needed shards are available"
        )
    return shards


def _compute_file_hash(filepath: str) -> str:
    """Compute BLAKE3 hash of a file."""
    h = blake3.blake3()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# Number of words in a transfer code. Each word from the 7776-word EFF list
# adds ~12.9 bits, so 6 words gives ~77 bits. The code is the only secret
# (there is no PAKE in an async transfer), so it must resist offline brute
# force and enumeration of the relay.
CODE_WORDS = 6


@functools.lru_cache(maxsize=1)
def _wordlist() -> List[str]:
    text = (Path(__file__).parent / "wordlist.txt").read_text(encoding="utf-8")
    return text.split()


def _generate_code() -> str:
    """Generate a human-readable transfer code: word-word-word-word-word-word."""
    words = _wordlist()
    return "-".join(secrets.choice(words) for _ in range(CODE_WORDS))
