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

from .account import current_api, is_email
from .config import get_config, resolve_servers
from . import crypto
from . import erasure
from .manifest import (
    Manifest, ManifestSegment, ManifestShard,
    MAX_MESSAGE_CHARS, build_manifest, read_file_segment, safe_output_path,
)
from .resume import ResumeLog
from .validator import ValidatorRegistry

# (connect, read) timeouts in seconds for every request.
TIMEOUT = (10, 300)


def send(
    path: str,
    name: str = "untitled-transfer",
    *,
    to: Optional[List[str]] = None,
    message: Optional[str] = None,
    return_details: bool = False,
) -> Union[str, Dict[str, Any]]:
    """Send a file or directory. Returns the transfer code.

    Args:
        path: Path to the file or directory to send.
        name: Human-readable name for the transfer.
        to: Optional recipients. Usernames ("alice" or "@alice") get the
            transfer in their inbox on the website; email addresses get the
            code by email. Requires helppeer.login().
        message: Optional note describing the transfer (up to 2000
            characters). Recipients see it with the files, in their inbox and
            in notification emails.
        return_details: If True, return a dict with full transfer details.

    Returns:
        Transfer code string (e.g., "orbit-velvet-zoom-candle-harbor-ember"), or a dict if return_details=True.
    """
    config = get_config()
    if message is not None and not message.strip():
        message = None
    if message is not None and len(message) > MAX_MESSAGE_CHARS:
        raise ValueError(f"message is longer than {MAX_MESSAGE_CHARS} characters")
    recipients = [r.strip() for r in (to or []) if r.strip()]
    api = current_api()
    # Check recipients before uploading anything.
    if recipients:
        if api is None:
            raise RuntimeError("sending to recipients needs a login: call helppeer.login() first")
        unknown = [r for r in recipients if not is_email(r) and not api.username_exists(r)]
        if unknown:
            raise ValueError(f"unknown username(s): {', '.join(unknown)}")

    relay_url, storage_nodes = resolve_servers()
    if not storage_nodes:
        raise ValueError("no storage nodes configured")
    total_shards = config.data_shards + config.parity_shards
    _warn_if_too_few_nodes(len(storage_nodes), total_shards, config.parity_shards)

    code = _generate_code()
    k_data, k_index = crypto.derive_keys(code)
    r_hash = crypto.relay_hash(k_index)

    manifest, base_dir = build_manifest(path, name, config.segment_size)
    manifest.erasure_data_shards = config.data_shards
    manifest.erasure_parity_shards = config.parity_shards
    manifest.ack_secret = crypto.new_secret()
    manifest.delete_token = crypto.new_secret()
    manifest.message = message
    uploader = _ShardUploader(storage_nodes, crypto.secret_hash(manifest.delete_token))

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
            failed = ", ".join(storage_nodes[i] for i in sorted(uploader.dead))
            print(
                f"warning: storage node(s) {failed} failed; their shards were stored on the "
                "remaining nodes, so this transfer tolerates fewer node failures",
                file=sys.stderr,
            )

        # Encrypt and upload manifest
        encrypted_manifest = crypto.encrypt_segment(k_data, manifest.to_json())
        _upload_manifest(
            session, relay_url, r_hash, encrypted_manifest,
            crypto.secret_hash(manifest.ack_secret),
        )

    # Tell the recipients. The upload already succeeded, so problems here are
    # reported rather than raised.
    notify_errors: List[str] = []
    if recipients:
        try:
            result = api.notify(r_hash, code, name, message, len(manifest.files), manifest.total_bytes, recipients)
            notify_errors = list(result.get("errors") or [])
        except Exception as e:
            notify_errors = [f"couldn't notify recipients ({e}); share the code yourself"]
        for err in notify_errors:
            print(f"warning: {err}", file=sys.stderr)

    if return_details:
        return {
            "code": code,
            "transfer_name": name,
            "files": len(manifest.files),
            "total_bytes": manifest.total_bytes,
            "recipients": recipients,
            "notify_errors": notify_errors,
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
        Dict with transfer_name, files (count), total_bytes, file_hashes
        ({path: blake3}), file_list ([{path, size, blake3}]), acknowledged
        and resumed_segments.
    """
    relay_url, _ = resolve_servers()
    k_data, k_index = crypto.derive_keys(code)
    r_hash = crypto.relay_hash(k_index)

    with _session() as session:
        # Download encrypted manifest from relay. It stays there until we
        # confirm success below, so a failed download can be retried.
        encrypted_manifest = _download_manifest(session, relay_url, r_hash)
        manifest_json = crypto.decrypt_segment(k_data, encrypted_manifest)
        manifest = Manifest.from_json(manifest_json)
        manifest.validate()
        total_shards = manifest.erasure_data_shards + manifest.erasure_parity_shards

        # Validate every path before touching the filesystem.
        file_paths = {f.path: safe_output_path(output_dir, f.path) for f in manifest.files}

        # Pick up where a previous attempt at this transfer left off, if any.
        os.makedirs(output_dir, exist_ok=True)
        log = ResumeLog(output_dir, crypto.content_hash(manifest_json))
        if log.previously_done:
            total = sum(len(f.segments) for f in manifest.files)
            print(f"Resuming: {log.previously_done} of {total} segments were downloaded "
                  "by a previous attempt", file=sys.stderr)

        # Pre-allocate files (keeping the contents of any partial download)
        for f in manifest.files:
            file_path = file_paths[f.path]
            os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
            with open(file_path, "a+b") as fh:
                fh.truncate(f.size)

        # Download and reconstruct each file
        registry = ValidatorRegistry()
        file_hashes = {}

        with ThreadPoolExecutor(max_workers=total_shards) as pool:
            for f in manifest.files:
                file_path = file_paths[f.path]
                total_segments = len(f.segments)

                for seg_idx, segment in enumerate(f.segments):
                    # Skip segments already on disk from a previous attempt, as
                    # long as the data there is still exactly what was written.
                    expected = log.completed(f.path, seg_idx)
                    if expected is not None:
                        on_disk = read_file_segment(file_path, seg_idx, manifest.segment_size)
                        if len(on_disk) == segment.original_size and crypto.content_hash(on_disk) == expected:
                            if progress:
                                progress(f.path, seg_idx + 1, total_segments)
                            continue

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
                        # Make sure the data is on disk before the log says it is.
                        fh.flush()
                        os.fsync(fh.fileno())
                    log.record(f.path, seg_idx, crypto.content_hash(plaintext))

                    if progress:
                        progress(f.path, seg_idx + 1, total_segments)

                # Check the reassembled file against the sender's hash, when provided
                file_hash = _compute_file_hash(file_path)
                if f.blake3 is not None and file_hash != f.blake3:
                    log.remove()  # don't let a retry trust any of this attempt's segments
                    raise ValueError(
                        f"{f.path} is corrupt: BLAKE3 {file_hash} does not match sender's {f.blake3}"
                    )
                file_hashes[f.path] = file_hash

        resumed = log.previously_done
        log.remove()

        # Everything verified: confirm, which uses up this recipient's retrieval.
        acknowledged = _acknowledge(session, relay_url, r_hash, manifest.ack_secret)

    # If it was sent to our username, clear it from the inbox.
    api = current_api()
    if api is not None:
        try:
            api.mark_received(r_hash)
        except Exception:
            pass

    return {
        "transfer_name": manifest.transfer_name,
        "message": manifest.message,
        "files": len(manifest.files),
        "total_bytes": manifest.total_bytes,
        "file_hashes": file_hashes,
        "file_list": [
            {"path": f.path, "size": f.size, "blake3": file_hashes[f.path]} for f in manifest.files
        ],
        "acknowledged": acknowledged,
        "resumed_segments": resumed,
    }


def info(code: str) -> Dict[str, Any]:
    """Preview a transfer without downloading or consuming it.

    Returns:
        Dict with transfer_name, message (or None), total_bytes and
        files ([{path, size}]).
    """
    relay_url, _ = resolve_servers()
    k_data, k_index = crypto.derive_keys(code)
    with _session() as session:
        encrypted_manifest = _download_manifest(session, relay_url, crypto.relay_hash(k_index))
    manifest = Manifest.from_json(crypto.decrypt_segment(k_data, encrypted_manifest))
    manifest.validate()
    return {
        "transfer_name": manifest.transfer_name,
        "message": manifest.message,
        "total_bytes": manifest.total_bytes,
        "files": [{"path": f.path, "size": f.size} for f in manifest.files],
    }


def cancel(code: str) -> Dict[str, Any]:
    """Cancel a transfer before it expires.

    Removes the manifest from the relay so nobody can start receiving it,
    then deletes its shards from the storage nodes using the manifest's
    delete token. Shards on unreachable nodes still expire with the TTL.

    Returns:
        Dict with transfer_name, shards_deleted, shards_already_gone, shards_failed.
    """
    relay_url, _ = resolve_servers()
    k_data, k_index = crypto.derive_keys(code)
    r_hash = crypto.relay_hash(k_index)
    manifest_url = f"{relay_url}/manifest/{r_hash}"

    with _session() as session:
        encrypted_manifest = _download_manifest(session, relay_url, r_hash)
        manifest = Manifest.from_json(crypto.decrypt_segment(k_data, encrypted_manifest))
        manifest.validate()

        # Withdraw the manifest first so no new download can start. (The
        # session doesn't retry DELETE after it may have reached the relay.)
        resp = session.delete(manifest_url, data=manifest.ack_secret, timeout=TIMEOUT)
        if resp.status_code != 204:
            raise RuntimeError(f"relay refused to cancel the transfer (status {resp.status_code})")

        def delete_shard(shard: ManifestShard) -> str:
            try:
                r = session.delete(
                    f"{shard.node}/shard/{shard.hash}",
                    headers={"X-Delete-Token": manifest.delete_token}, timeout=TIMEOUT,
                )
            except requests.RequestException:
                return "failed"
            return {204: "deleted", 404: "already_gone"}.get(r.status_code, "failed")

        shards = [sh for f in manifest.files for seg in f.segments for sh in seg.shards]
        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(delete_shard, shards))

    return {
        "transfer_name": manifest.transfer_name,
        "shards_deleted": outcomes.count("deleted"),
        "shards_already_gone": outcomes.count("already_gone"),
        "shards_failed": outcomes.count("failed"),
    }


def _session() -> requests.Session:
    """A pooled session that retries transient failures (connection errors,
    5xx, 429) with backoff."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        # Not POST or DELETE: confirming or cancelling a transfer isn't
        # idempotent. urllib3 still retries connection failures, where the
        # request never arrived.
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
