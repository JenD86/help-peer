package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"lukechampine.com/blake3"
)

func newTestNode(t *testing.T, capacity int64) (*StorageNode, *DiskStore, string) {
	t.Helper()
	store, err := NewDiskStore(t.TempDir(), 3600)
	if err != nil {
		t.Fatal(err)
	}
	node := &StorageNode{store: store, capacityBytes: capacity, maxShardBytes: 1024, started: time.Now(), ttlSeconds: 3600}
	srv := httptest.NewServer(node.routes())
	t.Cleanup(srv.Close)
	return node, store, srv.URL
}

func hashOf(data []byte) string {
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func put(t *testing.T, url string, body []byte) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestPutVerifiesHash(t *testing.T) {
	_, _, base := newTestNode(t, 1<<20)
	data := []byte("shard data")

	if code := put(t, base+"/shard/"+hashOf([]byte("other")), data); code != 400 {
		t.Fatalf("mismatched hash accepted: %d", code)
	}
	if code := put(t, base+"/shard/"+hashOf(data), data); code != 201 {
		t.Fatalf("valid put: %d", code)
	}
	if code := put(t, base+"/shard/"+hashOf(data), data); code != 200 {
		t.Fatalf("dedup put: %d", code)
	}

	resp, err := http.Get(base + "/shard/" + hashOf(data))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q", got)
	}
}

func TestPutRejectsBadInput(t *testing.T) {
	_, _, base := newTestNode(t, 1<<20)
	if code := put(t, base+"/shard/abc", []byte("x")); code != 400 {
		t.Errorf("short hash: %d", code)
	}
	big := make([]byte, 2048)
	if code := put(t, base+"/shard/"+hashOf(big), big); code != 413 {
		t.Errorf("oversized shard: %d", code)
	}
}

func TestCapacity(t *testing.T) {
	_, _, base := newTestNode(t, 100)
	a := bytes.Repeat([]byte("a"), 80)
	b := bytes.Repeat([]byte("b"), 80)
	if code := put(t, base+"/shard/"+hashOf(a), a); code != 201 {
		t.Fatalf("first put: %d", code)
	}
	if code := put(t, base+"/shard/"+hashOf(b), b); code != 507 {
		t.Fatalf("over capacity: %d", code)
	}
}

func TestDedupRefreshesTTL(t *testing.T) {
	_, store, base := newTestNode(t, 1<<20)
	data := []byte("refresh me")
	h := hashOf(data)
	put(t, base+"/shard/"+h, data)

	store.mu.Lock()
	store.shardIndex[h] = time.Now().Add(time.Second)
	store.mu.Unlock()

	put(t, base+"/shard/"+h, data)
	store.mu.Lock()
	expiry := store.shardIndex[h]
	store.mu.Unlock()
	if time.Until(expiry) < 50*time.Minute {
		t.Fatalf("TTL not refreshed: expires in %s", time.Until(expiry))
	}
}

func TestRestartKeepsOriginalExpiry(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewDiskStore(dir, 3600)
	data := []byte("old shard")
	h := hashOf(data)
	store.Put(h, bytes.NewReader(data), time.Hour)
	os.WriteFile(store.shardPath(h)+".tmp", []byte("partial"), 0644)

	// Pretend it was stored two hours ago.
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(store.shardPath(h), old, old)

	restarted, _ := NewDiskStore(dir, 3600)
	if _, err := restarted.Get(h); err == nil {
		t.Fatal("expired shard survived restart")
	}
	if _, err := os.Stat(store.shardPath(h) + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("stale .tmp file not cleaned up")
	}
}
