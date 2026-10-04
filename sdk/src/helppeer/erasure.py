"""Reed-Solomon erasure coding for Help Peer."""
from reedsolo import RSCodec

from .config import get_config


def encode_segment(data: bytes) -> list[bytes]:
    """Split an encrypted segment into (8 data + 4 parity) shards."""
    config = get_config()
    return _encode_interleaved(data, config.data_shards, config.parity_shards)


def _encode_interleaved(data: bytes, data_shards: int, parity_shards: int) -> list[bytes]:
    """Encode data using interleaved Reed-Solomon: split into data_shards pieces,
    compute parity_shards parity pieces, return data_shards + parity_shards shards."""
    shard_size = (len(data) + data_shards - 1) // data_shards
    # Pad data to fill all data shards
    padded = data + b"\x00" * (shard_size * data_shards - len(data))

    # Split into data shards
    data_shards_list = [
        padded[i * shard_size:(i + 1) * shard_size]
        for i in range(data_shards)
    ]

    # For each byte position, compute parity across data_shards bytes
    rs = RSCodec(parity_shards, nsize=data_shards + parity_shards)

    parity_shards_list = [bytearray(shard_size) for _ in range(parity_shards)]

    for pos in range(shard_size):
        # Gather one byte from each data shard
        data_bytes = bytes(data_shards_list[i][pos] for i in range(data_shards))
        # Encode: produces data_bytes + parity_bytes
        encoded = rs.encode(data_bytes)
        # Extract parity bytes
        for j in range(parity_shards):
            parity_shards_list[j][pos] = encoded[data_shards + j]

    return data_shards_list + [bytes(p) for p in parity_shards_list]


def decode_segment(shards: list[bytes | None], original_len: int) -> bytes:
    """Reconstruct the original segment from at least data_shards of total_shards shards.
    Missing shards should be None."""
    config = get_config()
    data_shards = config.data_shards
    parity_shards = config.parity_shards
    total_shards = data_shards + parity_shards

    if len(shards) != total_shards:
        raise ValueError(f"expected {total_shards} shards, got {len(shards)}")

    # Find shard size from available shards
    shard_size = None
    for s in shards:
        if s is not None:
            shard_size = len(s)
            break

    if shard_size is None:
        raise ValueError("no shards available")

    # Count available shards
    available = sum(1 for s in shards if s is not None)
    if available < data_shards:
        raise ValueError(f"insufficient shards: have {available}, need {data_shards}")

    rs = RSCodec(parity_shards, nsize=data_shards + parity_shards)

    # For each byte position, reconstruct missing bytes
    data_shards_list = [None] * data_shards
    parity_shards_list = [None] * parity_shards

    for i in range(total_shards):
        if shards[i] is not None:
            if i < data_shards:
                data_shards_list[i] = shards[i]
            else:
                parity_shards_list[i - data_shards] = shards[i]

    result_shards = [bytearray(shard_size) for _ in range(data_shards)]

    for pos in range(shard_size):
        # Build the received codeword for this byte position
        received = [None] * total_shards
        for i in range(data_shards):
            if data_shards_list[i] is not None:
                received[i] = data_shards_list[i][pos]
        for j in range(parity_shards):
            if parity_shards_list[j] is not None:
                received[data_shards + j] = parity_shards_list[j][pos]

        # Convert to list with 0 for missing (erasure positions)
        codeword = []
        erasure_pos = []
        for i in range(total_shards):
            if received[i] is not None:
                codeword.append(received[i])
            else:
                codeword.append(0)
                erasure_pos.append(i)

        if erasure_pos:
            # Decode with erasures
            try:
                decoded = rs.decode(bytearray(codeword), erase_pos=erasure_pos)
                # reedsolo returns (msg, full_corrected_codeword) when there are erasures
                if isinstance(decoded, tuple):
                    full_codeword = decoded[1]
                else:
                    full_codeword = decoded
                # Extract corrected data bytes
                for i in range(data_shards):
                    result_shards[i][pos] = full_codeword[i]
            except Exception:
                # If decode fails, use available data bytes directly
                for i in range(data_shards):
                    if data_shards_list[i] is not None:
                        result_shards[i][pos] = data_shards_list[i][pos]
                    else:
                        result_shards[i][pos] = 0
        else:
            # No erasures, just copy data bytes
            for i in range(data_shards):
                result_shards[i][pos] = codeword[i]

    # Concatenate data shards and trim to original length
    result = b"".join(bytes(s) for s in result_shards)
    return result[:original_len]
