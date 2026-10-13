# Changelog

Notable changes to Help Peer. Entries marked **Action required** need storage node operators or users to update.

## Unreleased

### Per-shard delete tokens (web)

Every shard of a transfer used to be stored with the same delete-token hash, so storage nodes, or anyone comparing several nodes' data, could tell which shards belonged to the same transfer. Web uploads now give each shard its own token, derived from the transfer's delete token and the shard's hash (SPEC 4.4), and mark the manifest with `shard_delete_tokens`. Storage nodes need no update, and every client can still receive these transfers. The CLI and Python SDK follow in the next release; until then, they can't cancel new web transfers early (the transfer is still withdrawn at once, and its shards expire within 24 hours).

### Relay: per-client rate limits behind a reverse proxy

The relay limits failed lookups (code guessing) and uploads per client address, but behind a reverse proxy every CLI and SDK user looked like the proxy, so one client could exhaust the limit for all of them. With `RELAY_TRUST_PROXY=1` the relay uses the address the proxy reports in `X-Forwarded-For`. Off by default; only enable it when the relay can't be reached except through the proxy.

### Python SDK: fewer dependencies

`reedsolo` (never imported) and `hkdf` (unmaintained since 2015) are no longer dependencies; key derivation uses the HKDF from `cryptography`, which the SDK already required. Keys are unchanged, as the shared test vectors confirm.

### Documentation

- README: a "Public Deployment" section on putting the services behind HTTPS, with a Caddy example.

## 2026-10-13 — Python SDK 0.2.2, CLI and web

To update: `pip install --upgrade "helppeer>=0.2.2"` for the Python SDK, or `git pull && cargo install --path client` for the Rust CLI. The web changes are live on help-peer.org; self-hosters update by pulling and rebuilding.

### CLI and Python SDK: less trust in the logged-in website

- After `receive`, the client only tells the website about the transfer if it's in your inbox there. Previously every receive by a logged-in client reported the transfer's relay key, including transfers the site never handled.
- Storage nodes from the website's settings are no longer trusted with private addresses when receiving. Only nodes you set yourself (`--nodes`, `HELPEER_STORAGE_NODES`, `configure()`) and the local default are; a site's own nodes are public, so nothing changes for normal use.
- The README's "Behaviour to rely on" now lists what logging in changes.

### Web: less metadata kept and shown

- **Sending to recipients now needs a username.** Recipients see `@username`; a sender's email address is no longer shown to them, and the inbox API no longer includes it (it previously did even for senders with a username). The web app, CLI and SDK check for a username before uploading.
- **File names no longer reach the server by default.** The web app used the first file's name as the transfer name and sent it to the server. Now the server only stores a name you type; otherwise it shows the number of files and total size. The real name stays in the encrypted manifest.
- **Transfer history is kept for 24 hours**, like the transfers themselves, instead of indefinitely. Older records, including those from before this change, are deleted.

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
