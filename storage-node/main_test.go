package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	_, key, _ := ed25519.GenerateKey(nil)
	node := &StorageNode{store: store, capacityBytes: capacity, maxShardBytes: 1024, started: time.Now(), ttlSeconds: 3600, key: key}
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
	store.Put(h, bytes.NewReader(data), time.Hour, "")
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

func send(t *testing.T, method, url string, body []byte, headers map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestDeleteRequiresToken(t *testing.T) {
	_, store, base := newTestNode(t, 1<<20)
	token := bytes.Repeat([]byte{9}, 32)
	data := []byte("deletable")
	url := base + "/shard/" + hashOf(data)

	if code := send(t, "PUT", url, data, map[string]string{"X-Delete-Token-Hash": hashOf(token)}); code != 201 {
		t.Fatalf("put: %d", code)
	}
	if code := send(t, "DELETE", url, nil, nil); code != 403 {
		t.Fatalf("delete without token: %d", code)
	}
	if code := send(t, "DELETE", url, nil, map[string]string{"X-Delete-Token": hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}); code != 403 {
		t.Fatalf("delete with wrong token: %d", code)
	}
	if code := send(t, "DELETE", url, nil, map[string]string{"X-Delete-Token": hex.EncodeToString(token)}); code != 204 {
		t.Fatalf("delete with token: %d", code)
	}
	if code := send(t, "DELETE", url, nil, map[string]string{"X-Delete-Token": hex.EncodeToString(token)}); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
	if _, err := os.Stat(store.shardPath(hashOf(data)) + deleteTokenSuffix); !os.IsNotExist(err) {
		t.Fatal("token sidecar left behind")
	}
}

func TestShardsWithoutTokenCannotBeDeleted(t *testing.T) {
	_, _, base := newTestNode(t, 1<<20)
	data := []byte("legacy shard")
	url := base + "/shard/" + hashOf(data)
	send(t, "PUT", url, data, nil)
	if code := send(t, "DELETE", url, nil, map[string]string{"X-Delete-Token": hex.EncodeToString(bytes.Repeat([]byte{9}, 32))}); code != 403 {
		t.Fatalf("expected 403, got %d", code)
	}
}

func TestTokenSidecarNotCountedAsShard(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewDiskStore(dir, 3600)
	data := []byte("with token")
	store.Put(hashOf(data), bytes.NewReader(data), time.Hour, strings.Repeat("ab", 32))

	restarted, _ := NewDiskStore(dir, 3600)
	if restarted.ShardCount() != 1 || restarted.UsedBytes() != int64(len(data)) {
		t.Fatalf("count=%d used=%d", restarted.ShardCount(), restarted.UsedBytes())
	}
}

func TestHealthReportsNodeIDAndAvailableSpace(t *testing.T) {
	node, _, base := newTestNode(t, 1000)
	data := bytes.Repeat([]byte("z"), 300)
	put(t, base+"/shard/"+hashOf(data), data)

	resp, err := http.Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	var h HealthResponse
	json.NewDecoder(resp.Body).Decode(&h)
	resp.Body.Close()
	if h.NodeID != nodeID(node.key.Public().(ed25519.PublicKey)) || !strings.HasPrefix(h.NodeID, "ed25519:") {
		t.Fatalf("node id %q", h.NodeID)
	}
	if h.AvailableBytes != 700 {
		t.Fatalf("available %d, want 700", h.AvailableBytes)
	}
}

func TestAvailableUsesRealDiskSpace(t *testing.T) {
	node, _, _ := newTestNode(t, 1<<62) // claims far more than any disk has
	node.dataDir = t.TempDir()
	free, ok := diskFreeBytes(node.dataDir)
	if !ok {
		t.Skip("disk free space not available on this platform")
	}
	if got := node.available(); got > free || got < free-(64<<20) {
		t.Fatalf("available %d, disk free %d", got, free)
	}
	// Uploads that won't fit on the disk are refused as "full" (507).
	node.diskReserve = free + 1
	if node.reserve(1) {
		t.Fatal("reserved space the disk doesn't have")
	}
}

func TestNodeKeyIsCreatedOnceAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "node_key")
	k1, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := loadOrCreateKey(path)
	if !k1.Equal(k2) {
		t.Fatal("key changed between starts")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Fatalf("key file mode %v", info.Mode().Perm())
	}
}

func TestSignedRequestsVerify(t *testing.T) {
	node, _, _ := newTestNode(t, 1<<20)
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Node-Signature")
	}))
	defer srv.Close()

	node.sendSigned(srv.URL, nodeRequest{Action: "register", URL: "https://node.example.com"})
	var r nodeRequest
	json.Unmarshal(gotBody, &r)
	pub, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(r.NodeID, "ed25519:"))
	sig, _ := base64.RawURLEncoding.DecodeString(gotSig)
	if !ed25519.Verify(pub, gotBody, sig) || r.Action != "register" || r.Timestamp == 0 {
		t.Fatalf("bad signed request %s", gotBody)
	}
}
