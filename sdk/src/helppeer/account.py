"""Logging in to a Help Peer website with an API token, so the SDK can send
to usernames, read the inbox, and use the site's relay and storage nodes.

The login is stored in a config file shared with the Rust CLI:
``$HELPEER_CONFIG``, else ``$XDG_CONFIG_HOME/helppeer/config.json``
(``~/.config/...``), or ``%APPDATA%\\helppeer\\config.json`` on Windows.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

TIMEOUT = (10, 60)


def config_path() -> str:
    if os.environ.get("HELPEER_CONFIG"):
        return os.environ["HELPEER_CONFIG"]
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "helppeer", "config.json")


def load_login() -> Optional[Dict[str, str]]:
    """The saved login ({"server", "token"}), if any."""
    try:
        with open(config_path(), encoding="utf-8") as f:
            data = json.load(f)
        if data.get("server") and data.get("token"):
            return {"server": data["server"], "token": data["token"]}
    except (OSError, ValueError):
        pass
    return None


def is_email(recipient: str) -> bool:
    """An email address has an '@' after the first character; anything else
    is a username ("alice" or "@alice")."""
    return recipient.find("@") > 0


class Api:
    """Client for the website's API, authenticated with an API token."""

    def __init__(self, server: str, token: str):
        self.server = server.rstrip("/")
        self.token = token

    def _call(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        resp = requests.request(
            method, self.server + path, json=body, timeout=TIMEOUT,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if not resp.ok:
            raise RuntimeError(data.get("error") or f"{path} returned {resp.status_code}")
        return data

    def whoami(self) -> Dict[str, str]:
        me = self._call("GET", "/api/auth/me")
        if not me.get("authenticated"):
            raise RuntimeError("the server didn't accept this token (it may have been revoked)")
        return {"email": me.get("email", ""), "username": me.get("username", "")}

    def server_config(self) -> Dict[str, Any]:
        return self._call("GET", "/api/config")

    def username_exists(self, username: str) -> bool:
        return bool(self._call("GET", f"/api/users/lookup?username={quote(username)}").get("exists"))

    def notify(self, relay_hash: str, code: str, transfer_name: str, message: Optional[str],
               files: int, total_bytes: int, recipients: List[str]) -> Dict[str, Any]:
        """Register a transfer sent from here, then notify recipients."""
        reg = self._call("POST", "/api/transfers", {
            "manifest_hash": relay_hash, "transfer_name": transfer_name, "message": message,
            "files": files, "total_bytes": total_bytes,
        })
        return self._call("POST", "/api/notify", {
            "transfer_id": reg["transfer_id"], "manifest_hash": relay_hash,
            "code": code, "recipients": recipients,
        })

    def inbox(self) -> List[Dict[str, Any]]:
        return self._call("GET", "/api/inbox").get("items", [])

    def mark_received(self, relay_hash: str) -> None:
        self._call("POST", "/api/inbox/received", {"manifest_hash": relay_hash})


def current_api() -> Optional[Api]:
    login = load_login()
    return Api(login["server"], login["token"]) if login else None


def login(server: str, token: str) -> Dict[str, str]:
    """Log in to a Help Peer website with an API token (create one on its
    Account page). Verifies the token, then saves it for the SDK and CLI."""
    api = Api(server, token)
    who = api.whoami()
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # The file holds a credential, so only the user may read it.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"server": api.server, "token": token}, f, indent=2)
    return {**who, "server": api.server, "config": path}


def logout() -> bool:
    """Forget the saved login. Returns whether there was one."""
    try:
        os.remove(config_path())
        return True
    except FileNotFoundError:
        return False


def inbox() -> List[Dict[str, Any]]:
    """Transfers sent to your username (requires login())."""
    api = current_api()
    if api is None:
        raise RuntimeError("not logged in: call helppeer.login() first")
    return api.inbox()
