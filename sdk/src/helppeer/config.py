"""Configuration for Help Peer SDK."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Config:
    """SDK configuration. Modify via helppeer.configure()."""
    relay_url: str = os.environ.get("HELPEER_RELAY_URL", "http://127.0.0.1:7000")
    storage_nodes: List[str] = field(default_factory=lambda: [
        n.strip() for n in os.environ.get(
            "HELPEER_STORAGE_NODES", "http://127.0.0.1:7001"
        ).split(",") if n.strip()
    ])
    segment_size: int = 64 * 1024 * 1024  # 64 MB
    data_shards: int = 8
    parity_shards: int = 4


_default_config = Config()


def get_config() -> Config:
    return _default_config


def configure(
    relay: str = None,
    storage_nodes: List[str] = None,
    segment_size: int = None,
    data_shards: int = None,
    parity_shards: int = None,
):
    """Configure the SDK. Only provided values are updated."""
    if relay is not None:
        _default_config.relay_url = relay
    if storage_nodes is not None:
        _default_config.storage_nodes = storage_nodes
    if segment_size is not None:
        _default_config.segment_size = segment_size
    if data_shards is not None:
        _default_config.data_shards = data_shards
    if parity_shards is not None:
        _default_config.parity_shards = parity_shards
