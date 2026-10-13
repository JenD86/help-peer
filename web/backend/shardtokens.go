package main

import (
	"encoding/hex"

	"lukechampine.com/blake3"
)

// Per-shard delete tokens (protocol/SPEC.md 2.3). Every shard of a transfer
// gets its own token, derived from the manifest's delete_token, so storage
// nodes can't group a transfer's shards by the token hash stored with them.
//
//	shard_delete_key = BLAKE3 derive_key(shardDeleteKeyContext, delete_token)
//	shard_token      = BLAKE3 keyed(shard_delete_key, shard hash bytes)
//
// Nodes store BLAKE3(shard_token) and need no changes. Manifests using this
// scheme carry "shard_delete_tokens": true.
const shardDeleteKeyContext = "help-peer 2026-10-13 shard delete key"

// shardDeleteKey derives the per-transfer key from the manifest's delete token.
func shardDeleteKey(deleteToken []byte) []byte {
	key := make([]byte, 32)
	blake3.DeriveKey(key, shardDeleteKeyContext, deleteToken)
	return key
}

// shardToken is the delete token for one shard, given its hex hash.
func shardToken(key []byte, shardHash string) []byte {
	h, _ := hex.DecodeString(shardHash)
	m := blake3.New(32, key)
	m.Write(h)
	return m.Sum(nil)
}

// shardTokenHash is what a storage node stores for the shard at upload.
func shardTokenHash(key []byte, shardHash string) string {
	return blake3Hex(shardToken(key, shardHash))
}
