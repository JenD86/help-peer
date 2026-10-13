# Changelog

Notable changes to Help Peer. Entries marked **Action required** need storage node operators or users to update.

## Unreleased

### Web backend: dev mode no longer logs login links and transfer codes

Without SMTP configured, the web backend used to write login links, and the transfer codes and messages it would have emailed, to its log, where anyone with access to `docker logs` could use them. It now logs only that an email wasn't sent. For local testing, set `WEB_DEV_LOG_SECRETS=1` to get the old behaviour.

### Web app: security headers

The web app now sends a strict Content-Security-Policy (scripts, styles and requests only to the site itself; WebAssembly allowed for Argon2id key derivation, but no `eval` or inline scripts), plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Cross-Origin-Opener-Policy` and `Permissions-Policy`. If you self-host behind a reverse proxy, enable HSTS there.

## 2026-10-13 — Python SDK 0.2.1 and CLI

### CLI and Python SDK: receivers could be made to request internal addresses — **Action required: update the CLI and SDK**

A transfer's manifest names the storage nodes its shards are on, and receivers fetched from whatever URLs it listed. A malicious sender (or, for transfers sent to a username, the website) could make a receiver's client send requests to its own network, such as `localhost` services, the router or a cloud metadata endpoint. The client never saw the responses unless they matched a shard's hash, but the requests themselves could have side effects.

Receivers (`receive` and `cancel`) now only contact a storage node if the receiver configured it (`--nodes`, `HELPEER_STORAGE_NODES` or the logged-in site's list) or it resolves to a public address, checked at connection time. Shard requests no longer follow redirects or go through proxies, and downloads stop once they exceed the size the manifest says to expect. The web app was not affected: its backend already only fetches from its own registered nodes.

To update: `pip install --upgrade "helppeer>=0.2.1"` for the Python SDK, or `git pull && cargo install --path client` for the Rust CLI.

If you receive from storage nodes on a private network, list them in `--nodes` or `HELPEER_STORAGE_NODES`.

## 2026-10-13

### Storage node: shard expiry could be extended without the shard's content — **Action required for node operators**

A storage node refreshed a shard's 24-hour expiry whenever it received an upload for a hash it already held, before reading the upload. Anyone who knew a shard's hash could therefore keep it stored indefinitely by sending empty uploads, using up the operator's disk. Shard contents stayed encrypted and unreadable throughout; this affected storage and expiry only.

Nodes now read and verify every upload against its hash before refreshing anything. Re-uploading the real content still refreshes the expiry, so client retries work as before.

**To update a node**, pull the latest code and recreate the container with the same data volume, which keeps your node key and stored shards:

```bash
cd help-peer && git pull
docker ps                      # find your node's container ID
docker stop <container-id> && docker rm <container-id>
# then run the same `docker run` command you used originally (see README → Contributing a node)
```

The node deregisters on stop and registers again on start with the same identity.

### Python SDK 0.2.0 — **Action required if you installed `helppeer` 0.1.0 from PyPI**

`helppeer` 0.1.0 on PyPI was built before Argon2id key stretching and 6-word codes from a cryptographic random source. Its transfer codes are weak enough to guess, and it can't exchange transfers with current clients. It has been yanked. Upgrade with:

```bash
pip install --upgrade "helppeer>=0.2"
```

Releases are now published from tagged commits (`sdk-v*`) via PyPI Trusted Publishing.

### Documentation

- The README's security section said the server never stores transfer codes. It does when you send to a username (the code waits in the recipient's inbox) and sees them when it emails codes. The section now says exactly when the server sees a code.
- The landing page links to the GitHub repository and welcomes contributors.
