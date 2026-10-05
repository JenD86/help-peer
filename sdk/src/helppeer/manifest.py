"""Manifest building and parsing for Help Peer."""
from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Version 2 introduced Argon2id key derivation, ack_secret and delete_token.
MANIFEST_VERSION = 2

# Longest message a sender may attach, in characters.
MAX_MESSAGE_CHARS = 2000

NONCE_SIZE = 12
TAG_SIZE = 16
# Largest segment size a receiver will accept, to bound memory use.
MAX_SEGMENT_SIZE = 256 * 1024 * 1024

# File extensions blocked to reduce abuse risk (media sharing).
# Not a security boundary — just a deterrent.
BLOCKED_MEDIA_EXTENSIONS = {
    # Images
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "tiff", "tif",
    "ico", "heic", "heif", "avif", "raw", "cr2", "nef", "arw", "psd",
    # Video
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg",
    "mpeg", "3gp", "ts", "vob", "ogv",
    # Audio
    "mp3", "wav", "flac", "aac", "ogg", "oga", "wma", "m4a", "alac",
    "aiff", "aif", "opus", "ac3", "amr", "au",
}

def _is_blocked_media(path: str) -> bool:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return ext in BLOCKED_MEDIA_EXTENSIONS


_HEX_HASH = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class ManifestShard:
    index: int
    hash: str
    node: str


@dataclass
class ManifestSegment:
    id: str
    original_size: int
    encrypted_size: int
    shards: List[ManifestShard] = field(default_factory=list)


@dataclass
class ManifestFile:
    path: str
    size: int
    segments: List[ManifestSegment] = field(default_factory=list)
    # BLAKE3 of the whole plaintext file, checked by the receiver after
    # reconstruction. Optional so manifests from older senders still parse.
    blake3: Optional[str] = None


@dataclass
class Manifest:
    version: int = MANIFEST_VERSION
    transfer_name: str = ""
    # Hex secret the receiver presents to the relay to confirm a completed
    # download (the relay only stores its BLAKE3).
    ack_secret: str = ""
    # Hex token that authorizes deleting this transfer's shards from storage
    # nodes (they only store its BLAKE3).
    delete_token: str = ""
    # Optional note from the sender describing the transfer.
    message: Optional[str] = None
    total_bytes: int = 0
    segment_size: int = 67108864
    erasure_data_shards: int = 8
    erasure_parity_shards: int = 4
    files: List[ManifestFile] = field(default_factory=list)

    def to_json(self) -> bytes:
        files = []
        for f in self.files:
            entry = {
                "path": f.path,
                "size": f.size,
                "segments": [
                    {
                        "id": s.id,
                        "original_size": s.original_size,
                        "encrypted_size": s.encrypted_size,
                        "shards": [
                            {"index": sh.index, "hash": sh.hash, "node": sh.node}
                            for sh in s.shards
                        ],
                    }
                    for s in f.segments
                ],
            }
            if f.blake3 is not None:
                entry["blake3"] = f.blake3
            files.append(entry)

        out = {
            "version": self.version,
            "transfer_name": self.transfer_name,
            "ack_secret": self.ack_secret,
            "delete_token": self.delete_token,
            "total_bytes": self.total_bytes,
            "segment_size": self.segment_size,
            "erasure_data_shards": self.erasure_data_shards,
            "erasure_parity_shards": self.erasure_parity_shards,
            "files": files,
        }
        if self.message is not None:
            out["message"] = self.message
        return json.dumps(out).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "Manifest":
        d = json.loads(data)
        manifest = cls(
            version=d["version"],
            transfer_name=d["transfer_name"],
            ack_secret=d.get("ack_secret", ""),
            delete_token=d.get("delete_token", ""),
            message=d.get("message"),
            total_bytes=d["total_bytes"],
            segment_size=d["segment_size"],
            erasure_data_shards=d["erasure_data_shards"],
            erasure_parity_shards=d["erasure_parity_shards"],
        )
        for f in d["files"]:
            mf = ManifestFile(path=f["path"], size=f["size"], blake3=f.get("blake3"))
            for s in f["segments"]:
                ms = ManifestSegment(
                    id=s["id"],
                    original_size=s["original_size"],
                    encrypted_size=s["encrypted_size"],
                )
                for sh in s["shards"]:
                    ms.shards.append(ManifestShard(
                        index=sh["index"], hash=sh["hash"], node=sh["node"]
                    ))
                mf.segments.append(ms)
            manifest.files.append(mf)
        return manifest

    def validate(self) -> None:
        """Check a received manifest is internally consistent before acting on
        it. It comes from the sender, so sizes and indexes are untrusted and
        would otherwise drive allocations, file offsets and list indexing."""
        if self.version != MANIFEST_VERSION:
            raise ValueError(f"unsupported manifest version {self.version}")
        if not (_HEX_HASH.match(self.ack_secret or "") and _HEX_HASH.match(self.delete_token or "")):
            raise ValueError("manifest has an invalid ack secret or delete token")
        if self.message is not None and (not isinstance(self.message, str) or len(self.message) > MAX_MESSAGE_CHARS):
            raise ValueError("manifest message is invalid or too long")
        k, m = self.erasure_data_shards, self.erasure_parity_shards
        if not (isinstance(k, int) and isinstance(m, int) and k >= 1 and m >= 0 and k + m <= 256):
            raise ValueError(f"invalid erasure coding {k}+{m}")
        seg_size = self.segment_size
        if not isinstance(seg_size, int) or not 0 < seg_size <= MAX_SEGMENT_SIZE:
            raise ValueError(f"invalid segment size {seg_size}")

        total = 0
        for f in self.files:
            def bad(what: str) -> ValueError:
                return ValueError(f"invalid manifest entry for {f.path!r}: {what}")

            if not isinstance(f.size, int) or f.size < 0:
                raise bad("invalid size")
            total += f.size
            if len(f.segments) != (f.size + seg_size - 1) // seg_size:
                raise bad("wrong number of segments")
            if f.blake3 is not None and not _HEX_HASH.match(f.blake3):
                raise bad("invalid file hash")

            for i, seg in enumerate(f.segments):
                if seg.original_size != min(seg_size, f.size - i * seg_size):
                    raise bad("wrong segment size")
                if seg.encrypted_size != seg.original_size + NONCE_SIZE + TAG_SIZE:
                    raise bad("wrong encrypted segment size")
                seen = set()
                for sh in seg.shards:
                    if not isinstance(sh.index, int) or not 0 <= sh.index < k + m or sh.index in seen:
                        raise bad("invalid shard index")
                    seen.add(sh.index)
                    if not isinstance(sh.hash, str) or not _HEX_HASH.match(sh.hash):
                        raise bad("invalid shard hash")

        if total != self.total_bytes:
            raise ValueError("manifest total_bytes does not match its files")


def _new_file_entry(rel_path: str, size: int, segment_size: int) -> ManifestFile:
    num_segments = (size + segment_size - 1) // segment_size
    segments = [
        ManifestSegment(
            id=f"seg_{i:06d}",
            original_size=min(segment_size, size - i * segment_size),
            encrypted_size=0,
        )
        for i in range(num_segments)
    ]
    return ManifestFile(path=rel_path, size=size, segments=segments)


def build_manifest(path: str, transfer_name: str, segment_size: int) -> Tuple[Manifest, str]:
    """Build a manifest for a file or a directory.

    Returns the manifest and the directory its paths are relative to.
    """
    manifest = Manifest(transfer_name=transfer_name, segment_size=segment_size)

    if os.path.isfile(path):
        base_dir = os.path.dirname(path) or "."
        basename = os.path.basename(path)
        if _is_blocked_media(basename):
            raise ValueError(f"media files (images, video, audio) are not allowed: {basename}")
        manifest.files.append(
            _new_file_entry(basename, os.path.getsize(path), segment_size)
        )
    elif os.path.isdir(path):
        base_dir = path
        # os.walk doesn't descend into symlinked directories (which could loop
        # or escape the tree), but symlinked files are followed and sent, e.g.
        # Hugging Face cache snapshots that link to blobs.
        for root, dirs, files in os.walk(path):
            for d in dirs:
                if os.path.islink(os.path.join(root, d)):
                    print(f"warning: skipping symlinked directory {os.path.join(root, d)}",
                          file=sys.stderr)
            for filename in files:
                filepath = os.path.join(root, filename)
                if not os.path.isfile(filepath):
                    print(f"warning: skipping {filepath} (broken symlink or special file)",
                          file=sys.stderr)
                    continue
                if _is_blocked_media(filename):
                    print(f"warning: skipping media file {filepath} (images, video and audio are not allowed)",
                          file=sys.stderr)
                    continue
                # Manifest paths always use '/' so receivers on any OS parse them the same way.
                rel_path = os.path.relpath(filepath, path).replace(os.sep, "/")
                manifest.files.append(
                    _new_file_entry(rel_path, os.path.getsize(filepath), segment_size)
                )
    else:
        raise FileNotFoundError(f"no such file or directory: {path}")

    manifest.files.sort(key=lambda f: f.path)
    manifest.total_bytes = sum(f.size for f in manifest.files)
    return manifest, base_dir


def read_file_segment(filepath: str, segment_index: int, segment_size: int) -> bytes:
    """Read a specific segment from a file."""
    with open(filepath, "rb") as f:
        f.seek(segment_index * segment_size)
        return f.read(segment_size)


def printable(text: str) -> str:
    """Make sender-supplied text safe to print to a terminal: drop control
    characters (which could inject escape sequences) except newlines and tabs."""
    return "".join(c for c in text if c in "\n\t" or unicodedata.category(c)[0] != "C")


def safe_output_path(output_dir: str, rel_path: str) -> str:
    """Resolve a manifest path under output_dir, rejecting anything that could
    escape it. The manifest comes from the sender, who must not be able to
    write outside the directory the receiver chose (e.g. "../../.bashrc" or
    an absolute path, which os.path.join would otherwise honour)."""
    if not rel_path:
        raise ValueError(f"unsafe path in manifest: {rel_path!r}")

    parts = rel_path.split("/")
    for part in parts:
        # Reject empty / dot segments, and anything another OS could treat
        # as a separator, drive letter or special name.
        if part in ("", ".", "..") or any(c in part for c in "\\:\0"):
            raise ValueError(f"unsafe path in manifest: {rel_path!r}")

    return os.path.join(output_dir, *parts)
