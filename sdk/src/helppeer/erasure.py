"""Reed-Solomon erasure coding for Help Peer.

Byte-for-byte compatible with the Rust client (reed-solomon-erasure) and the
web backend (klauspost/reedsolomon): GF(2^8) with polynomial 0x11D, and an
encoding matrix built from a Vandermonde matrix made systematic by
multiplying with the inverse of its top square. Shards are split the same way
(ceil(len / data_shards) bytes each, zero padded), so any implementation can
reconstruct shards produced by any other.
"""
from __future__ import annotations

import functools
from typing import List, Optional, Sequence

import numpy as np

DEFAULT_DATA_SHARDS = 8
DEFAULT_PARITY_SHARDS = 4

# --- GF(2^8) arithmetic -----------------------------------------------------

_POLY = 0x11D


def _build_tables():
    exp = [0] * 510
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _POLY
    for i in range(255, 510):
        exp[i] = exp[i - 255]
    return exp, log


_EXP, _LOG = _build_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(256) inverse of 0")
    return _EXP[255 - _LOG[a]]


def _gf_exp(a: int, n: int) -> int:
    if n == 0:
        return 1
    if a == 0:
        return 0
    return _EXP[(_LOG[a] * n) % 255]


# MUL_TABLE[c] maps every byte b to c*b, so multiplying a whole shard by a
# constant is a single numpy fancy-index.
_MUL_TABLE = np.array(
    [[_gf_mul(a, b) for b in range(256)] for a in range(256)], dtype=np.uint8
)


# --- Matrix helpers (tiny matrices; plain Python is fine) -------------------

def _mat_mul(a: List[List[int]], b: List[List[int]]) -> List[List[int]]:
    rows, inner, cols = len(a), len(b), len(b[0])
    out = [[0] * cols for _ in range(rows)]
    for r in range(rows):
        for c in range(cols):
            v = 0
            for k in range(inner):
                v ^= _gf_mul(a[r][k], b[k][c])
            out[r][c] = v
    return out


def _mat_invert(m: List[List[int]]) -> List[List[int]]:
    n = len(m)
    # Augment with the identity and run Gauss-Jordan elimination.
    work = [list(row) + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(m)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if work[r][col] != 0), None)
        if pivot is None:
            raise ValueError("matrix is singular")
        work[col], work[pivot] = work[pivot], work[col]
        inv = _gf_inv(work[col][col])
        work[col] = [_gf_mul(v, inv) for v in work[col]]
        for r in range(n):
            if r != col and work[r][col] != 0:
                f = work[r][col]
                work[r] = [v ^ _gf_mul(f, p) for v, p in zip(work[r], work[col])]
    return [row[n:] for row in work]


@functools.lru_cache(maxsize=None)
def _encoding_matrix(data_shards: int, parity_shards: int) -> tuple:
    total = data_shards + parity_shards
    if data_shards <= 0 or parity_shards < 0 or total > 256:
        raise ValueError(f"invalid erasure parameters {data_shards}+{parity_shards}")
    vm = [[_gf_exp(r, c) for c in range(data_shards)] for r in range(total)]
    top_inv = _mat_invert(vm[:data_shards])
    return tuple(tuple(row) for row in _mat_mul(vm, top_inv))


def _combine(coeffs: Sequence[int], inputs: Sequence[np.ndarray], size: int) -> np.ndarray:
    out = np.zeros(size, dtype=np.uint8)
    for c, shard in zip(coeffs, inputs):
        if c == 1:
            out ^= shard
        elif c != 0:
            out ^= _MUL_TABLE[c][shard]
    return out


# --- Public API -------------------------------------------------------------

def encode_segment(
    data: bytes,
    data_shards: int = DEFAULT_DATA_SHARDS,
    parity_shards: int = DEFAULT_PARITY_SHARDS,
) -> List[bytes]:
    """Split an encrypted segment into data_shards + parity_shards shards."""
    if not data:
        raise ValueError("cannot erasure-code empty data")
    matrix = _encoding_matrix(data_shards, parity_shards)

    shard_size = (len(data) + data_shards - 1) // data_shards
    padded = np.zeros(shard_size * data_shards, dtype=np.uint8)
    padded[: len(data)] = np.frombuffer(data, dtype=np.uint8)
    data_list = [padded[i * shard_size:(i + 1) * shard_size] for i in range(data_shards)]

    parity_list = [
        _combine(matrix[data_shards + j], data_list, shard_size)
        for j in range(parity_shards)
    ]
    return [s.tobytes() for s in data_list + parity_list]


def decode_segment(
    shards: Sequence[Optional[bytes]],
    original_len: int,
    data_shards: int = DEFAULT_DATA_SHARDS,
    parity_shards: int = DEFAULT_PARITY_SHARDS,
) -> bytes:
    """Reconstruct the original segment from any data_shards of the shards.
    Missing shards should be None."""
    total = data_shards + parity_shards
    if len(shards) != total:
        raise ValueError(f"expected {total} shards, got {len(shards)}")

    present = [i for i, s in enumerate(shards) if s is not None]
    if len(present) < data_shards:
        raise ValueError(f"insufficient shards: have {len(present)}, need {data_shards}")

    shard_size = len(shards[present[0]])
    if any(len(shards[i]) != shard_size for i in present):
        raise ValueError("shards have different sizes")

    arrays = {i: np.frombuffer(shards[i], dtype=np.uint8) for i in present}
    missing_data = [i for i in range(data_shards) if shards[i] is None]

    if missing_data:
        matrix = _encoding_matrix(data_shards, parity_shards)
        use = present[:data_shards]
        decode = _mat_invert([list(matrix[i]) for i in use])
        inputs = [arrays[i] for i in use]
        for i in missing_data:
            arrays[i] = _combine(decode[i], inputs, shard_size)

    result = b"".join(arrays[i].tobytes() for i in range(data_shards))
    if original_len > len(result):
        raise ValueError("original length exceeds reconstructed data")
    return result[:original_len]
