"""Which storage nodes a receiver will contact.

Shard URLs come from the manifest, which the sender wrote (and, for transfers
sent to a username, the website relayed). Without checks a malicious manifest
could make a receiver send requests to its own network: localhost services,
the router, cloud metadata endpoints. So shards are only fetched from the
storage nodes the receiver itself configured, or from nodes that resolve to
public addresses, checked when each connection is made so a hostname can't
switch to an internal address later.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlsplit

from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import MaxRetryError, NewConnectionError
from urllib3.util.retry import Retry


class PrivateAddressError(NewConnectionError):
    """The node resolved only to private or internal addresses."""


class NoRetryOnPrivateAddress(Retry):
    """Retry as usual, except a refused address, which won't change."""

    def increment(self, method=None, url=None, response=None, error=None, _pool=None, _stacktrace=None):
        if isinstance(error, PrivateAddressError):
            raise MaxRetryError(_pool, url, error) from error
        return super().increment(method, url, response, error, _pool, _stacktrace)


def check_node_url(node: str) -> None:
    """Raise ValueError unless `node` is a plain http(s) base URL. Where it
    may point is decided when connecting."""
    if not isinstance(node, str):
        raise ValueError("not a URL")
    u = urlsplit(node)
    if u.scheme not in ("http", "https"):
        raise ValueError("not an http(s) URL")
    u.port  # raises ValueError for an invalid port
    if not u.hostname or u.username is not None or u.password is not None:
        raise ValueError("invalid host")
    if u.query or u.fragment:
        raise ValueError("unexpected query or fragment")


def origin(node: str) -> str:
    u = urlsplit(node)
    port = u.port or {"http": 80, "https": 443}.get(u.scheme)
    return f"{u.scheme}://{(u.hostname or '').lower()}:{port}"


def is_public_ip(ip: str) -> bool:
    """Whether `ip` is a globally routable unicast address."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])  # drop any IPv6 zone
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.version == 6 and (addr in _NAT64 or addr.packed[:12] == bytes(12)):
        return False  # embeds an IPv4 address; ::/96 is reserved
    return addr.is_global and not addr.is_multicast


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class _PublicOnly:
    """Resolve the host ourselves, keep only public addresses, and connect to
    one of them. urllib3 connects to `_dns_host` but still uses `host` for TLS
    certificate checks, so HTTPS works as usual."""

    def _new_conn(self):
        host = self._dns_host
        try:
            infos = socket.getaddrinfo(host, self.port, type=socket.SOCK_STREAM)
        except OSError as e:
            raise NewConnectionError(self, f"failed to resolve {host}: {e}")
        public = [info[4][0] for info in infos if is_public_ip(info[4][0])]
        if not public:
            raise PrivateAddressError(self, f"refusing to connect to {host}: not a public address")
        self._dns_host = public[0]
        try:
            return super()._new_conn()
        finally:
            self._dns_host = host


class _PublicHTTPConnection(_PublicOnly, HTTPConnection):
    pass


class _PublicHTTPSConnection(_PublicOnly, HTTPSConnection):
    pass


class _PublicHTTPPool(HTTPConnectionPool):
    ConnectionCls = _PublicHTTPConnection


class _PublicHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _PublicHTTPSConnection


class PublicOnlyAdapter(HTTPAdapter):
    """An adapter that only connects to public addresses."""

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _PublicHTTPPool, "https": _PublicHTTPSPool}


class NodeSessions:
    """Picks the session to contact a manifest's storage node with.

    `trusted` is a normal session, used for the receiver's own configured
    nodes (which may be on a private network). `public` must be built with
    PublicOnlyAdapter and trust_env=False (a proxy would make the connection
    itself, skipping the check)."""

    def __init__(self, configured: Iterable[str], trusted, public):
        self._trusted_origins = set()
        for n in configured:
            try:
                self._trusted_origins.add(origin(n))
            except ValueError:
                pass
        self.trusted, self.public = trusted, public

    def for_node(self, node: str):
        check_node_url(node)
        return self.trusted if origin(node) in self._trusted_origins else self.public
