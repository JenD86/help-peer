# Changelog

Notable changes to Help Peer. Entries marked **Action required** need storage node operators or users to update.

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
