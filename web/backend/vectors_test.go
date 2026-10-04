package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/klauspost/reedsolomon"
	"lukechampine.com/blake3"
)

// Vectors shared with the Rust client and Python SDK.
func TestSharedErasureVectors(t *testing.T) {
	raw, err := os.ReadFile("../../protocol/test-vectors.json")
	if err != nil {
		t.Skip("not running from the repo")
	}
	var v struct {
		Erasure struct {
			Data        string   `json:"data"`
			Shards      []string `json:"shards"`
			ShardBlake3 []string `json:"shard_blake3"`
		} `json:"erasure"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	data, _ := hex.DecodeString(v.Erasure.Data)
	enc, _ := reedsolomon.New(DataShards, ParityShards)
	shards, _ := enc.Split(data)
	if err := enc.Encode(shards); err != nil {
		t.Fatal(err)
	}
	for i, s := range shards {
		if got := hex.EncodeToString(s); got != v.Erasure.Shards[i] {
			t.Fatalf("shard %d: got %s want %s", i, got, v.Erasure.Shards[i])
		}
		sum := blake3.Sum256(s)
		if got := hex.EncodeToString(sum[:]); got != v.Erasure.ShardBlake3[i] {
			t.Fatalf("shard %d blake3: got %s", i, got)
		}
	}
}
