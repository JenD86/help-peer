"""Manifest building and parsing for Help Peer."""
import os
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional


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


@dataclass
class Manifest:
    version: int = 1
    transfer_name: str = ""
    total_bytes: int = 0
    segment_size: int = 67108864
    erasure_data_shards: int = 8
    erasure_parity_shards: int = 4
    files: List[ManifestFile] = field(default_factory=list)

    def to_json(self) -> bytes:
        return json.dumps({
            "version": self.version,
            "transfer_name": self.transfer_name,
            "total_bytes": self.total_bytes,
            "segment_size": self.segment_size,
            "erasure_data_shards": self.erasure_data_shards,
            "erasure_parity_shards": self.erasure_parity_shards,
            "files": [
                {
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
                for f in self.files
            ],
        }).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "Manifest":
        d = json.loads(data)
        manifest = cls(
            version=d["version"],
            transfer_name=d["transfer_name"],
            total_bytes=d["total_bytes"],
            segment_size=d["segment_size"],
            erasure_data_shards=d["erasure_data_shards"],
            erasure_parity_shards=d["erasure_parity_shards"],
        )
        for f in d["files"]:
            mf = ManifestFile(path=f["path"], size=f["size"])
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


def build_manifest(dir_path: str, transfer_name: str, segment_size: int) -> Manifest:
    """Build a manifest by crawling a directory."""
    manifest = Manifest(
        transfer_name=transfer_name,
        segment_size=segment_size,
    )

    for root, dirs, files in os.walk(dir_path):
        dirs.sort()
        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, dir_path)

            size = os.path.getsize(filepath)
            manifest.total_bytes += size

            num_segments = 0
            if size > 0:
                num_segments = (size + segment_size - 1) // segment_size

            segments = []
            for i in range(num_segments):
                seg_size = min(segment_size, size - i * segment_size)
                segments.append(ManifestSegment(
                    id=f"seg_{i:06d}",
                    original_size=seg_size,
                    encrypted_size=0,
                ))

            manifest.files.append(ManifestFile(
                path=rel_path,
                size=size,
                segments=segments,
            ))

    return manifest


def read_file_segment(filepath: str, segment_index: int, segment_size: int) -> bytes:
    """Read a specific segment from a file."""
    with open(filepath, "rb") as f:
        f.seek(segment_index * segment_size)
        return f.read(segment_size)
