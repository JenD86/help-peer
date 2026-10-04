"""Resume state for interrupted downloads (protocol/SPEC.md §8).

Progress is an append-only log at ``<output>/.helppeer/<manifest_id>.partial``,
where ``manifest_id`` is the BLAKE3 of the decrypted manifest. The first line
is a header; each further line records one segment that was fully written,
with the BLAKE3 of its plaintext so a resumed download can check the data on
disk is still intact before skipping it::

    {"version":1,"manifest_id":"<hex>"}
    {"file":"sub/model.safetensors","segment":3,"blake3":"<hex>"}

The log holds no secrets, and the format is shared with the Rust client, so
either can resume the other's partial download.
"""
from __future__ import annotations

import json
import os
from typing import Dict, Optional, Tuple

STATE_DIR = ".helppeer"


class ResumeLog:
    def __init__(self, output_dir: str, manifest_id: str):
        state_dir = os.path.join(output_dir, STATE_DIR)
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, f"{manifest_id}.partial")
        self.done: Dict[Tuple[str, int], str] = _load(self.path, manifest_id)

        if self.done:
            self._fh = open(self.path, "a", encoding="utf-8")
            # A killed run may have left a partial last line; start ours on a
            # new line so it isn't glued onto it. Blank lines are skipped.
            self._fh.write("\n")
        else:
            self._fh = open(self.path, "w", encoding="utf-8")
            self._fh.write(json.dumps({"version": 1, "manifest_id": manifest_id}) + "\n")
        self._fh.flush()

    @property
    def previously_done(self) -> int:
        return len(self.done)

    def completed(self, file: str, segment: int) -> Optional[str]:
        """The plaintext hash recorded for a segment, if completed before."""
        return self.done.get((file, segment))

    def record(self, file: str, segment: int, blake3_hex: str) -> None:
        """Record a segment as written. Call only after its data is on disk."""
        self._fh.write(json.dumps({"file": file, "segment": segment, "blake3": blake3_hex}) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        self._fh.close()

    def remove(self) -> None:
        """Delete the log (on success, or to make the next run start over)."""
        self._fh.close()
        try:
            os.remove(self.path)
            os.rmdir(os.path.dirname(self.path))  # only succeeds if empty
        except OSError:
            pass


def _load(path: str, manifest_id: str) -> Dict[Tuple[str, int], str]:
    """Parse a log, ignoring it entirely if the header doesn't match and
    skipping malformed lines (e.g. one cut short when the process was killed)."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return {}
    if not lines:
        return {}

    try:
        header = json.loads(lines[0])
    except ValueError:
        return {}
    if not isinstance(header, dict) or header.get("version") != 1 or header.get("manifest_id") != manifest_id:
        return {}

    done = {}
    for line in lines[1:]:
        try:
            e = json.loads(line)
            done[(str(e["file"]), int(e["segment"]))] = str(e["blake3"])
        except (ValueError, KeyError, TypeError):
            continue
    return done
