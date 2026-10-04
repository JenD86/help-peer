"""Configuration for Help Peer SDK."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
import sys
from typing import List, Optional, Tuple


DEFAULT_RELAY = "http://127.0.0.1:7000"
DEFAULT_NODES = ["http://127.0.0.1:7001"]


def _env_nodes() -> Optional[List[str]]:
    raw = os.environ.get("HELPEER_STORAGE_NODES")
    return [n.strip() for n in raw.split(",") if n.strip()] if raw else None


@dataclass
class Config:
    """SDK configuration. Modify via helppeer.configure().

    relay_url / storage_nodes left as None are taken from the logged-in
    website (see helppeer.login()), else local defaults.
    """
    relay_url: Optional[str] = field(default_factory=lambda: os.environ.get("HELPEER_RELAY_URL"))
    storage_nodes: Optional[List[str]] = field(default_factory=_env_nodes)
    segment_size: int = 64 * 1024 * 1024  # 64 MB
    data_shards: int = 8
    parity_shards: int = 4


_default_config = Config()


def get_config() -> Config:
    return _default_config


def resolve_servers() -> Tuple[str, List[str]]:
    """The relay URL and storage nodes to use: configure() / environment
    variables, then the logged-in website's settings, then local defaults."""
    relay, nodes = _default_config.relay_url, _default_config.storage_nodes
    if relay is None or nodes is None:
        from .account import current_api
        api = current_api()
        if api is not None:
            try:
                server = api.server_config()
                relay = relay or server.get("relay_url")
                nodes = nodes or server.get("storage_nodes")
            except Exception as e:
                print(f"warning: couldn't get server settings from the website ({e}); using defaults",
                      file=sys.stderr)
    return (relay or DEFAULT_RELAY).rstrip("/"), nodes or list(DEFAULT_NODES)


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
