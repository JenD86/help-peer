package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"lukechampine.com/blake3"
)

const publicNode = "http://public-node.example:7001"

// fakeNode is a minimal content-addressed storage node.
type fakeNode struct {
	mu     sync.Mutex
	shards map[string][]byte
}

func (n *fakeNode) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	hash := strings.TrimPrefix(req.URL.Path, "/shard/")
	n.mu.Lock()
	defer n.mu.Unlock()
	switch req.Method {
	case http.MethodPut:
		data, _ := io.ReadAll(req.Body)
		sum := blake3.Sum256(data)
		if hex.EncodeToString(sum[:]) != hash {
			http.Error(w, "hash mismatch", http.StatusBadRequest)
			return
		}
		n.shards[hash] = data
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		data, ok := n.shards[hash]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(data)
	}
}

// fakeRelay stores manifests with one-time retrieval.
type fakeRelay struct {
	mu        sync.Mutex
	manifests map[string][]byte
}

func (r *fakeRelay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	hash := strings.TrimPrefix(req.URL.Path, "/manifest/")
	r.mu.Lock()
	defer r.mu.Unlock()
	switch req.Method {
	case http.MethodPut:
		if _, ok := r.manifests[hash]; ok {
			w.WriteHeader(http.StatusConflict)
			return
		}
		r.manifests[hash], _ = io.ReadAll(req.Body)
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		data, ok := r.manifests[hash]
		if !ok {
			http.NotFound(w, req)
			return
		}
		delete(r.manifests, hash)
		w.Write(data)
	}
}

type testEnv struct {
	s     *Server
	srv   *httptest.Server
	node  *fakeNode
	relay *fakeRelay
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	node := &fakeNode{shards: map[string][]byte{}}
	nodeSrv := httptest.NewServer(node)
	t.Cleanup(nodeSrv.Close)
	relay := &fakeRelay{manifests: map[string][]byte{}}
	relaySrv := httptest.NewServer(relay)
	t.Cleanup(relaySrv.Close)

	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	static := fstest.MapFS{
		"index.html":    {Data: []byte("<html>app shell</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	s := NewServer(db, relaySrv.URL,
		[]StorageNode{{Internal: nodeSrv.URL, Public: publicNode}},
		&SMTPConfig{}, "https://helppeer.example.com", static)
	srv := httptest.NewServer(s.routes())
	t.Cleanup(srv.Close)
	return &testEnv{s: s, srv: srv, node: node, relay: relay}
}

func (e *testEnv) post(t *testing.T, path string, body interface{}, cookie string) *http.Response {
	t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case []byte:
		r = bytes.NewReader(b)
	default:
		data, _ := json.Marshal(b)
		r = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, r)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "helppeer_session", Value: cookie})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyMagicLinkDoesNotDeadlock(t *testing.T) {
	e := newTestEnv(t)
	link, err := e.s.db.CreateMagicLink("a@example.com")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := e.s.db.VerifyMagicLink(link.Token)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("verify failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VerifyMagicLink deadlocked")
	}

	// The DB must still be usable afterwards.
	if _, ok := e.s.db.GetSession(e.s.db.CreateSession("a@example.com")); !ok {
		t.Fatal("session not found")
	}
}

func TestMagicLinkUsesConfiguredBaseURL(t *testing.T) {
	e := newTestEnv(t)

	// With SMTP unset the handler logs the link instead of emailing it.
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/request",
		strings.NewReader(`{"email":"victim@example.com"}`))
	req.Host = "evil.com"
	req.Header.Set("X-Forwarded-Proto", "javascript")
	w := httptest.NewRecorder()
	e.s.auth.authRequestHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	if !strings.Contains(logs.String(), "https://helppeer.example.com/verify?token=") {
		t.Fatalf("magic link does not use configured base URL: %s", logs.String())
	}
	if strings.Contains(logs.String(), "evil.com") {
		t.Fatalf("magic link uses request Host: %s", logs.String())
	}
}

func TestLoginRequestsAreRateLimited(t *testing.T) {
	e := newTestEnv(t)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	codes := []int{}
	for i := 0; i < 4; i++ {
		resp := e.post(t, "/api/auth/request", map[string]string{"email": "victim@example.com"}, "")
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[2] != 200 || codes[3] != 429 {
		t.Fatalf("expected 3 allowed then 429, got %v", codes)
	}
}

func TestRejectsHeaderInjectionInEmail(t *testing.T) {
	for _, bad := range []string{"a@b.com\r\nBcc: x@y.com", "Name <a@b.com>", "nope", ""} {
		if isValidEmail(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	if !isValidEmail("a.b+c@example.com") {
		t.Error("rejected a valid address")
	}
}

func TestSegmentRoundTrip(t *testing.T) {
	e := newTestEnv(t)

	// An odd size so the erasure-coding padding has to be trimmed.
	segment := make([]byte, 100003)
	rand.Read(segment)

	var up SegmentUploadResponse
	resp := e.post(t, "/api/upload/segment", segment, "")
	if resp.StatusCode != 200 {
		t.Fatalf("upload: %d", resp.StatusCode)
	}
	decode(t, resp, &up)
	if up.EncryptedSize != len(segment) || len(up.Shards) != TotalShards {
		t.Fatalf("unexpected response %+v", up)
	}
	for _, sh := range up.Shards {
		if sh.Node != publicNode {
			t.Fatalf("manifest should carry the public node URL, got %s", sh.Node)
		}
	}

	// Lose four shards (two data, two parity) and corrupt nothing: still recoverable.
	req := SegmentDownloadRequest{EncryptedSize: up.EncryptedSize, Shards: append(append([]ShardInfo{}, up.Shards[2:7]...), up.Shards[8:11]...)}
	resp = e.post(t, "/api/download/segment", req, "")
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, segment) {
		t.Fatalf("download: status %d, %d bytes, equal=%v", resp.StatusCode, len(got), bytes.Equal(got, segment))
	}

	// A node returning garbage for some shards is tolerated: bad shards are discarded.
	e.node.mu.Lock()
	for _, sh := range up.Shards[:4] {
		e.node.shards[sh.Hash] = bytes.Repeat([]byte{0xff}, len(e.node.shards[sh.Hash]))
	}
	e.node.mu.Unlock()
	resp = e.post(t, "/api/download/segment", SegmentDownloadRequest{EncryptedSize: up.EncryptedSize, Shards: up.Shards}, "")
	got, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, segment) {
		t.Fatalf("download with corrupt shards: status %d", resp.StatusCode)
	}
}

func TestSegmentUploadRejectsOversized(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, "/api/upload/segment", make([]byte, maxEncryptedSegment+1), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}
}

func TestSegmentDownloadRejectsUntrustedInput(t *testing.T) {
	e := newTestEnv(t)
	hash := strings.Repeat("ab", 32)

	cases := map[string]SegmentDownloadRequest{
		"unknown node":    {EncryptedSize: 100, Shards: []ShardInfo{{Index: 0, Hash: hash, Node: "http://169.254.169.254/latest/meta-data#"}}},
		"index too big":   {EncryptedSize: 100, Shards: []ShardInfo{{Index: 99, Hash: hash, Node: publicNode}}},
		"negative index":  {EncryptedSize: 100, Shards: []ShardInfo{{Index: -1, Hash: hash, Node: publicNode}}},
		"duplicate index": {EncryptedSize: 100, Shards: []ShardInfo{{Index: 0, Hash: hash, Node: publicNode}, {Index: 0, Hash: hash, Node: publicNode}}},
		"short hash":      {EncryptedSize: 100, Shards: []ShardInfo{{Index: 0, Hash: "ab", Node: publicNode}}},
		"path in hash":    {EncryptedSize: 100, Shards: []ShardInfo{{Index: 0, Hash: "../../health", Node: publicNode}}},
		"huge erasure":    {EncryptedSize: 100, DataShards: 1 << 30, ParityShards: 4},
		"huge size":       {EncryptedSize: 1 << 40},
		"missing size":    {},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp := e.post(t, "/api/download/segment", body, "")
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", resp.StatusCode)
			}
		})
	}
}

func TestDownloadManifest(t *testing.T) {
	e := newTestEnv(t)
	hash := strings.Repeat("cd", 32)
	e.relay.manifests[hash] = []byte("encrypted")

	resp := e.post(t, "/api/download", map[string]string{"manifest_hash": "../health"}, "")
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("invalid hash: %d", resp.StatusCode)
	}

	var got struct {
		ManifestData []byte `json:"manifest_data"`
	}
	resp = e.post(t, "/api/download", map[string]string{"manifest_hash": hash}, "")
	decode(t, resp, &got)
	if string(got.ManifestData) != "encrypted" {
		t.Fatalf("got %q", got.ManifestData)
	}
}

func TestManifestLookupsAreRateLimited(t *testing.T) {
	e := newTestEnv(t)
	last := 0
	for i := 0; i < 31; i++ {
		resp := e.post(t, "/api/download", map[string]string{"manifest_hash": strings.Repeat("ef", 32)}, "")
		resp.Body.Close()
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated misses, got %d", last)
	}
}

func TestManifestUploadHistoryAndNotify(t *testing.T) {
	e := newTestEnv(t)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	alice := e.s.db.CreateSession("alice@example.com")
	bob := e.s.db.CreateSession("bob@example.com")
	hash := strings.Repeat("12", 32)

	var up map[string]string
	resp := e.post(t, "/api/upload/manifest", map[string]interface{}{
		"manifest_hash": hash, "manifest_data": []byte("enc"), "max_retrievals": 2,
		"transfer_name": "weights", "files": 3, "total_bytes": 1234,
	}, alice)
	decode(t, resp, &up)
	id := up["transfer_id"]
	if id == "" || string(e.relay.manifests[hash]) != "enc" {
		t.Fatalf("manifest not stored: %v", up)
	}

	code := "orbit-velvet-zoom-candle-harbor-ember"
	notify := func(session string, body map[string]interface{}) int {
		resp := e.post(t, "/api/notify", body, session)
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := notify(alice, map[string]interface{}{"transfer_id": id, "code": "Buy cheap pills!", "recipients": []string{"x@example.com"}}); c != 400 {
		t.Errorf("arbitrary code text accepted: %d", c)
	}
	if c := notify(bob, map[string]interface{}{"transfer_id": id, "code": code, "recipients": []string{"x@example.com"}}); c != 404 {
		t.Errorf("notify for someone else's transfer: %d", c)
	}
	if c := notify(alice, map[string]interface{}{"transfer_id": id, "code": code, "recipients": make([]string, 21)}); c != 400 {
		t.Errorf("too many recipients accepted: %d", c)
	}
	if c := notify(alice, map[string]interface{}{"transfer_id": id, "code": code, "recipients": []string{"x@example.com"}}); c != 200 {
		t.Errorf("valid notify: %d", c)
	}

	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/api/history", nil)
	req.AddCookie(&http.Cookie{Name: "helppeer_session", Value: alice})
	resp, _ = http.DefaultClient.Do(req)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(raw), code) || !strings.Contains(string(raw), "x@example.com") {
		t.Fatalf("history should list recipients but never the code: %s", raw)
	}

	// The code must not reach disk either.
	files, _ := filepath.Glob(filepath.Join(e.s.db.dataDir, "*.json"))
	for _, f := range files {
		data, _ := os.ReadFile(f)
		if strings.Contains(string(data), code) {
			t.Fatalf("%s contains the transfer code", f)
		}
	}
}

func TestLegacyTransfersAreRekeyed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "transfers.json"),
		[]byte(`{"orbit-velvet-zoom":{"code":"orbit-velvet-zoom","sender_email":"a@example.com"}}`), 0600)
	os.WriteFile(filepath.Join(dir, "sessions.json"), []byte(`{"tok":"a@example.com"}`), 0600)

	db, _ := NewDB(dir)
	data, _ := os.ReadFile(filepath.Join(dir, "transfers.json"))
	if strings.Contains(string(data), "orbit-velvet-zoom") {
		t.Fatalf("legacy code still on disk: %s", data)
	}
	if got := db.GetTransfersByEmail("a@example.com"); len(got) != 1 {
		t.Fatalf("legacy record lost: %v", got)
	}
	if _, ok := db.GetSession("tok"); ok {
		t.Fatal("legacy session without expiry accepted")
	}
}

func TestSessionsExpire(t *testing.T) {
	e := newTestEnv(t)
	tok := e.s.db.CreateSession("a@example.com")
	e.s.db.mu.Lock()
	e.s.db.sessions[tok].Expires = time.Now().Add(-time.Second)
	e.s.db.mu.Unlock()
	if _, ok := e.s.db.GetSession(tok); ok {
		t.Fatal("expired session accepted")
	}
}

func TestSPAFallback(t *testing.T) {
	e := newTestEnv(t)
	get := func(path string) (int, string) {
		resp, err := http.Get(e.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	if code, body := get("/verify?token=abc"); code != 200 || !strings.Contains(body, "app shell") {
		t.Errorf("/verify: %d %q", code, body)
	}
	if code, body := get("/assets/app.js"); code != 200 || !strings.Contains(body, "console.log") {
		t.Errorf("asset: %d %q", code, body)
	}
	if code, _ := get("/api/nope"); code != 404 {
		t.Errorf("/api/nope: %d", code)
	}
}
