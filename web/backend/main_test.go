package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	tokens map[string]string // shard hash -> delete-token hash
}

func (n *fakeNode) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	hash := strings.TrimPrefix(req.URL.Path, "/shard/")
	n.mu.Lock()
	defer n.mu.Unlock()
	switch req.Method {
	case http.MethodPut:
		if !isHexHash(req.Header.Get("X-Delete-Token-Hash")) {
			http.Error(w, "missing delete token hash", http.StatusBadRequest)
			return
		}
		data, _ := io.ReadAll(req.Body)
		sum := blake3.Sum256(data)
		if hex.EncodeToString(sum[:]) != hash {
			http.Error(w, "hash mismatch", http.StatusBadRequest)
			return
		}
		n.shards[hash] = data
		if n.tokens != nil {
			n.tokens[hash] = req.Header.Get("X-Delete-Token-Hash")
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if _, ok := n.shards[hash]; !ok {
			http.NotFound(w, req)
			return
		}
		token, _ := hex.DecodeString(req.Header.Get("X-Delete-Token"))
		sum := blake3.Sum256(token)
		if n.tokens == nil || hex.EncodeToString(sum[:]) != n.tokens[hash] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		delete(n.shards, hash)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		data, ok := n.shards[hash]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(data)
	}
}

// fakeRelay stores manifests until they're acknowledged.
type fakeRelay struct {
	mu        sync.Mutex
	manifests map[string][]byte
	ackHashes map[string]string
}

func (r *fakeRelay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	hash := strings.TrimPrefix(req.URL.Path, "/manifest/")
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.HasSuffix(hash, "/ack") || req.Method == http.MethodDelete {
		hash = strings.TrimSuffix(hash, "/ack")
		secret, _ := io.ReadAll(req.Body)
		raw, _ := hex.DecodeString(string(secret))
		sum := blake3.Sum256(raw)
		if _, ok := r.manifests[hash]; !ok {
			http.NotFound(w, req)
		} else if hex.EncodeToString(sum[:]) != r.ackHashes[hash] {
			w.WriteHeader(http.StatusForbidden)
		} else {
			delete(r.manifests, hash)
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	switch req.Method {
	case http.MethodHead:
		if _, ok := r.manifests[hash]; !ok {
			w.WriteHeader(http.StatusNotFound)
		}
	case http.MethodPut:
		if _, ok := r.manifests[hash]; ok {
			w.WriteHeader(http.StatusConflict)
			return
		}
		r.manifests[hash], _ = io.ReadAll(req.Body)
		r.ackHashes[hash] = req.Header.Get("X-Ack-Hash")
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		data, ok := r.manifests[hash]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(data)
	}
}

type testEnv struct {
	s     *Server
	srv   *httptest.Server
	node  *fakeNode
	relay *fakeRelay
}

func newTestEnv(t *testing.T, extraNodes ...StorageNode) *testEnv {
	t.Helper()
	node := &fakeNode{shards: map[string][]byte{}, tokens: map[string]string{}}
	nodeSrv := httptest.NewServer(node)
	t.Cleanup(nodeSrv.Close)
	relay := &fakeRelay{manifests: map[string][]byte{}, ackHashes: map[string]string{}}
	relaySrv := httptest.NewServer(relay)
	t.Cleanup(relaySrv.Close)

	dataDir := t.TempDir()
	db, err := NewDB(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	static := fstest.MapFS{
		"index.html":    {Data: []byte("<html>app shell</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	s := NewServer(db, relaySrv.URL,
		append(extraNodes, StorageNode{Internal: nodeSrv.URL, Public: publicNode}),
		&SMTPConfig{}, "https://helppeer.example.com", static, dataDir)
	srv := httptest.NewServer(s.routes())
	t.Cleanup(srv.Close)
	return &testEnv{s: s, srv: srv, node: node, relay: relay}
}

var testDeleteTokenHash = strings.Repeat("de", 32)

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
	if path == "/api/upload/segment" {
		req.Header.Set("X-Delete-Token-Hash", testDeleteTokenHash)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "helppeer_session", Value: cookie})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// sessionForEmail creates a user (if needed) and returns a session token.
func (e *testEnv) sessionForEmail(email string) string {
	u := e.s.db.GetOrCreateUserByEmail(email)
	return e.s.db.CreateSession(u.ID)
}

// userIDForEmail returns the user ID for an email, creating the user if needed.
func (e *testEnv) userIDForEmail(email string) string {
	u := e.s.db.GetOrCreateUserByEmail(email)
	return u.ID
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
	if _, ok := e.s.db.GetSession(e.sessionForEmail("a@example.com")); !ok {
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

func TestSegmentDownloadSurvivesRemovedNode(t *testing.T) {
	e := newTestEnv(t)
	segment := make([]byte, 100003)
	rand.Read(segment)

	var up SegmentUploadResponse
	resp := e.post(t, "/api/upload/segment", segment, "")
	if resp.StatusCode != 200 {
		t.Fatalf("upload: %d", resp.StatusCode)
	}
	decode(t, resp, &up)

	// Pretend `lost` shards live on a node that has since left the list.
	withGone := func(lost int) SegmentDownloadRequest {
		shards := append([]ShardInfo{}, up.Shards...)
		for i := 0; i < lost; i++ {
			shards[i].Node = "http://gone.example:7001"
		}
		return SegmentDownloadRequest{EncryptedSize: up.EncryptedSize, Shards: shards}
	}

	// Four shards on the removed node: 8 remain, which is enough.
	resp = e.post(t, "/api/download/segment", withGone(4), "")
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, segment) {
		t.Fatalf("download with 4 shards on a removed node: status %d", resp.StatusCode)
	}

	// Five lost: only 7 remain, so it fails as insufficient, not as a bad request.
	resp = e.post(t, "/api/download/segment", withGone(5), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 with 5 shards lost, got %d", resp.StatusCode)
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

	alice := e.sessionForEmail("alice@example.com")
	bob := e.sessionForEmail("bob@example.com")
	hash := strings.Repeat("12", 32)

	var up map[string]string
	resp := e.post(t, "/api/upload/manifest", map[string]interface{}{
		"manifest_hash": hash, "manifest_data": []byte("enc"), "max_retrievals": 2, "ack_hash": strings.Repeat("ac", 32),
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
	if c := notify(alice, map[string]interface{}{"transfer_id": id, "manifest_hash": hash, "code": "Buy cheap pills!", "recipients": []string{"x@example.com"}}); c != 400 {
		t.Errorf("arbitrary code text accepted: %d", c)
	}
	if c := notify(bob, map[string]interface{}{"transfer_id": id, "manifest_hash": hash, "code": code, "recipients": []string{"x@example.com"}}); c != 404 {
		t.Errorf("notify for someone else's transfer: %d", c)
	}
	if c := notify(alice, map[string]interface{}{"transfer_id": id, "manifest_hash": hash, "code": code, "recipients": make([]string, 21)}); c != 400 {
		t.Errorf("too many recipients accepted: %d", c)
	}
	if c := notify(alice, map[string]interface{}{"transfer_id": id, "manifest_hash": hash, "code": code, "recipients": []string{"x@example.com"}}); c != 200 {
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

	os.WriteFile(filepath.Join(dir, "users.json"),
		[]byte(`{"a@example.com":{"email":"a@example.com","created_at":"2020-01-01T00:00:00Z"}}`), 0600)
	db, _ := NewDB(dir)
	data, _ := os.ReadFile(filepath.Join(dir, "transfers.json"))
	if strings.Contains(string(data), "orbit-velvet-zoom") {
		t.Fatalf("legacy code still on disk: %s", data)
	}
	u, _ := db.GetUserByEmail("a@example.com")
	if got := db.GetTransfersByUserID(u.ID); len(got) != 1 {
		t.Fatalf("legacy record lost: %v", got)
	}
	if _, ok := db.GetSession("tok"); ok {
		t.Fatal("legacy session without expiry accepted")
	}
}

func TestSessionsExpire(t *testing.T) {
	e := newTestEnv(t)
	tok := e.sessionForEmail("a@example.com")
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

func TestSegmentUploadRequiresDeleteToken(t *testing.T) {
	e := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/upload/segment", bytes.NewReader(make([]byte, 100)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSegmentUploadFailsOver(t *testing.T) {
	// The first configured node is down; its shards must go to the other one.
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()
	e := newTestEnv(t, StorageNode{Internal: downURL, Public: "http://down.example:7001"})
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	segment := make([]byte, 5000)
	rand.Read(segment)
	var up SegmentUploadResponse
	resp := e.post(t, "/api/upload/segment", segment, "")
	if resp.StatusCode != 200 {
		t.Fatalf("upload: %d", resp.StatusCode)
	}
	decode(t, resp, &up)
	for _, sh := range up.Shards {
		if sh.Node != publicNode {
			t.Fatalf("shard %d recorded on %s", sh.Index, sh.Node)
		}
	}
	if len(e.node.shards) != TotalShards {
		t.Fatalf("healthy node holds %d shards", len(e.node.shards))
	}

	// The next segment skips the failed node instead of retrying it.
	start := time.Now()
	resp = e.post(t, "/api/upload/segment", segment[:4000], "")
	resp.Body.Close()
	if resp.StatusCode != 200 || time.Since(start) > time.Second {
		t.Fatalf("second segment: status %d after %s", resp.StatusCode, time.Since(start))
	}
}

func TestAck(t *testing.T) {
	e := newTestEnv(t)
	hash := strings.Repeat("ab", 32)
	secret := bytes.Repeat([]byte{5}, 32)
	sum := blake3.Sum256(secret)
	e.relay.manifests[hash] = []byte("enc")
	e.relay.ackHashes[hash] = hex.EncodeToString(sum[:])

	// Fetching doesn't consume the manifest...
	for i := 0; i < 2; i++ {
		resp := e.post(t, "/api/download", map[string]string{"manifest_hash": hash}, "")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("fetch %d: %d", i, resp.StatusCode)
		}
	}
	// ...a wrong secret is refused...
	resp := e.post(t, "/api/download/ack", map[string]string{"manifest_hash": hash, "ack_secret": strings.Repeat("00", 32)}, "")
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("wrong secret: %d", resp.StatusCode)
	}
	// ...and the right one consumes it.
	resp = e.post(t, "/api/download/ack", map[string]string{"manifest_hash": hash, "ack_secret": hex.EncodeToString(secret)}, "")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("ack: %d", resp.StatusCode)
	}
	if _, ok := e.relay.manifests[hash]; ok {
		t.Fatal("manifest not consumed")
	}
}

func TestRateLimitsSurviveRestart(t *testing.T) {
	e := newTestEnv(t)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	path := filepath.Join(t.TempDir(), "ratelimits.json")

	// Use up the per-email login allowance, then "restart".
	for i := 0; i < 3; i++ {
		resp := e.post(t, "/api/auth/request", map[string]string{"email": "victim@example.com"}, "")
		resp.Body.Close()
	}
	if err := newLimiterStore(path, e.s.limiters()...).Save(); err != nil {
		t.Fatal(err)
	}

	restarted := newTestEnv(t)
	newLimiterStore(path, restarted.s.limiters()...).Load()
	resp := restarted.post(t, "/api/auth/request", map[string]string{"email": "victim@example.com"}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after restart, got %d", resp.StatusCode)
	}
	resp = restarted.post(t, "/api/auth/request", map[string]string{"email": "someone-else@example.com"}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("other email: %d", resp.StatusCode)
	}
}

func TestCancel(t *testing.T) {
	e := newTestEnv(t)
	token := bytes.Repeat([]byte{3}, 32)
	tokenSum := blake3.Sum256(token)
	ackSecret := bytes.Repeat([]byte{4}, 32)
	ackSum := blake3.Sum256(ackSecret)

	// Upload a segment registered with the real delete-token hash. (Random
	// data: an all-zero segment would give 12 identical shards.)
	segment := make([]byte, 5000)
	rand.Read(segment)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/upload/segment", bytes.NewReader(segment))
	req.Header.Set("X-Delete-Token-Hash", hex.EncodeToString(tokenSum[:]))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var up SegmentUploadResponse
	decode(t, resp, &up)

	hash := strings.Repeat("ab", 32)
	e.relay.manifests[hash] = []byte("enc")
	e.relay.ackHashes[hash] = hex.EncodeToString(ackSum[:])

	shards := []map[string]string{}
	for _, sh := range up.Shards {
		shards = append(shards, map[string]string{"hash": sh.Hash, "node": sh.Node})
	}
	// One shard on a node this server doesn't manage is skipped, not fetched.
	shards = append(shards, map[string]string{"hash": strings.Repeat("cd", 32), "node": "http://169.254.169.254"})
	body := map[string]interface{}{
		"manifest_hash": hash,
		"ack_secret":    hex.EncodeToString(ackSecret),
		"delete_token":  hex.EncodeToString(token),
		"shards":        shards,
	}

	var got map[string]interface{}
	resp = e.post(t, "/api/cancel", body, "")
	if resp.StatusCode != 200 {
		t.Fatalf("cancel: %d", resp.StatusCode)
	}
	decode(t, resp, &got)
	if got["shards_deleted"] != float64(TotalShards) || got["shards_failed"] != float64(1) {
		t.Fatalf("unexpected result %v", got)
	}
	if len(e.node.shards) != 0 {
		t.Fatalf("%d shards left", len(e.node.shards))
	}
	if _, ok := e.relay.manifests[hash]; ok {
		t.Fatal("manifest not removed")
	}

	// A second cancel finds nothing.
	resp = e.post(t, "/api/cancel", body, "")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("second cancel: %d", resp.StatusCode)
	}
}

// --- Directory, inbox and API tokens ----------------------------------------

func (e *testEnv) do(t *testing.T, method, path string, body interface{}, session, bearer string) (int, map[string]interface{}) {
	t.Helper()
	var r io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "helppeer_session", Value: session})
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]interface{}{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestProfileAndSearch(t *testing.T) {
	e := newTestEnv(t)
	alice := e.sessionForEmail("alice@example.com")
	bob := e.sessionForEmail("bob@example.com")
	carol := e.sessionForEmail("carol@example.com")

	if code, _ := e.do(t, "GET", "/api/profile", nil, "", ""); code != 401 {
		t.Fatalf("anonymous profile: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/profile", map[string]interface{}{"username": "@Alice_W", "listed": true}, alice, ""); code != 200 {
		t.Fatalf("set username: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/profile", map[string]interface{}{"username": "alice_w"}, bob, ""); code != 409 {
		t.Fatalf("taken username: %d", code)
	}
	for _, bad := range []string{"ab", "admin", "has space", "-dash", strings.Repeat("x", 31)} {
		if code, _ := e.do(t, "POST", "/api/profile", map[string]interface{}{"username": bad}, bob, ""); code != 400 {
			t.Errorf("username %q accepted: %d", bad, code)
		}
	}
	e.do(t, "POST", "/api/profile", map[string]interface{}{"username": "alicorn", "listed": false}, bob, "")
	e.do(t, "POST", "/api/profile", map[string]interface{}{"username": "alien", "listed": true}, carol, "")

	// Only listed users are found, and emails never appear.
	code, out := e.do(t, "GET", "/api/users/search?q=ali", nil, bob, "")
	users := fmt.Sprint(out["users"])
	if code != 200 || users != "[alice_w alien]" {
		t.Fatalf("search: %d %v", code, out)
	}
	if code, _ := e.do(t, "GET", "/api/users/search?q=al", nil, bob, ""); code != 400 {
		t.Fatalf("short query: %d", code)
	}
	if code, _ := e.do(t, "GET", "/api/users/search?q=ali", nil, "", ""); code != 401 {
		t.Fatalf("anonymous search: %d", code)
	}
	// Unlisted users can still be found by exact name.
	if _, out := e.do(t, "GET", "/api/users/lookup?username=@alicorn", nil, alice, ""); out["exists"] != true {
		t.Fatalf("lookup unlisted: %v", out)
	}
	if _, out := e.do(t, "GET", "/api/users/lookup?username=nobody", nil, alice, ""); out["exists"] != false {
		t.Fatalf("lookup missing: %v", out)
	}
	// Changing a username frees the old one.
	e.do(t, "POST", "/api/profile", map[string]interface{}{"username": "alice2", "listed": true}, alice, "")
	if _, out := e.do(t, "GET", "/api/users/lookup?username=alice_w", nil, bob, ""); out["exists"] != false {
		t.Fatal("old username still resolves")
	}
}

// sendToUsers uploads a fake transfer as `sender` and notifies recipients.
func sendToUsers(t *testing.T, e *testEnv, sender, hash string, recipients []string) (int, map[string]interface{}) {
	t.Helper()
	e.relay.manifests[hash] = []byte("enc")
	// The history record comes from a (separate) manifest upload; give each
	// one a fresh hash so repeated sends don't collide on the fake relay.
	uploadHash := make([]byte, 32)
	rand.Read(uploadHash)
	_, up := e.do(t, "POST", "/api/upload/manifest", map[string]interface{}{
		"manifest_hash": hex.EncodeToString(uploadHash), "manifest_data": []byte("x"), "ack_hash": strings.Repeat("ac", 32),
		"transfer_name": "weights", "files": 2, "total_bytes": 2048,
	}, sender, "")
	return e.do(t, "POST", "/api/notify", map[string]interface{}{
		"transfer_id": up["transfer_id"], "manifest_hash": hash,
		"code": "orbit-velvet-zoom-candle-harbor-ember", "recipients": recipients,
	}, sender, "")
}

func TestSendToUsernameUsesInbox(t *testing.T) {
	e := newTestEnv(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	alice := e.sessionForEmail("alice@example.com")
	bob := e.sessionForEmail("bob@example.com")
	e.s.db.SetProfile(e.userIDForEmail("alice@example.com"), "alice", true)
	e.s.db.SetProfile(e.userIDForEmail("bob@example.com"), "bob", false)
	hash := strings.Repeat("ab", 32)

	if code, out := sendToUsers(t, e, alice, hash, []string{"@bob", "nobody"}); code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "nobody") {
		t.Fatalf("unknown recipient: %d %v", code, out)
	}
	code, out := sendToUsers(t, e, alice, hash, []string{"@bob", "carol@example.com"})
	if code != 200 || out["inboxed"] != float64(1) || out["sent"] != float64(1) {
		t.Fatalf("notify: %d %v", code, out)
	}
	// The alert to Bob doesn't include the code; the email to Carol does.
	var bobAlert, carolEmail string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "Inbox alert to bob@example.com") {
			bobAlert = line
		}
		if strings.Contains(line, "Email to carol@example.com") {
			carolEmail = line
		}
	}
	if bobAlert == "" || strings.Contains(bobAlert, "orbit-velvet") {
		t.Fatalf("bob's alert missing or contains the code: %q", bobAlert)
	}
	if !strings.Contains(carolEmail, "orbit-velvet-zoom-candle-harbor-ember") {
		t.Fatalf("carol's email: %q", carolEmail)
	}

	// Bob sees it, with the code; Alice doesn't.
	_, inbox := e.do(t, "GET", "/api/inbox", nil, bob, "")
	items := inbox["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("bob's inbox: %v", inbox)
	}
	item := items[0].(map[string]interface{})
	if item["code"] != "orbit-velvet-zoom-candle-harbor-ember" || item["sender_username"] != "alice" {
		t.Fatalf("item: %v", item)
	}
	if _, inbox := e.do(t, "GET", "/api/inbox", nil, alice, ""); len(inbox["items"].([]interface{})) != 0 {
		t.Fatal("alice can see bob's inbox")
	}

	// Alice can't dismiss Bob's item; Bob can.
	id := item["id"].(string)
	if code, _ := e.do(t, "DELETE", "/api/inbox/"+id, nil, alice, ""); code != 404 {
		t.Fatalf("alice dismissed bob's item: %d", code)
	}
	if code, _ := e.do(t, "DELETE", "/api/inbox/"+id, nil, bob, ""); code != 200 {
		t.Fatalf("dismiss: %d", code)
	}
}

func TestInboxDropsGoneTransfers(t *testing.T) {
	e := newTestEnv(t)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	alice := e.sessionForEmail("alice@example.com")
	bob := e.sessionForEmail("bob@example.com")
	e.s.db.SetProfile(e.userIDForEmail("bob@example.com"), "bob", false)

	received := strings.Repeat("a1", 32)
	cancelled := strings.Repeat("b2", 32)
	marked := strings.Repeat("c3", 32)
	for _, h := range []string{received, cancelled, marked} {
		sendToUsers(t, e, alice, h, []string{"bob"})
	}

	// Received or cancelled elsewhere (e.g. from the CLI): gone from the relay.
	delete(e.relay.manifests, received)
	delete(e.relay.manifests, cancelled)
	// Received from the CLI by a logged-in recipient, which reports it.
	if code, out := e.do(t, "POST", "/api/inbox/received", map[string]string{"manifest_hash": marked}, bob, ""); code != 200 || out["removed"] != float64(1) {
		t.Fatalf("received: %d %v", code, out)
	}
	if _, inbox := e.do(t, "GET", "/api/inbox", nil, bob, ""); len(inbox["items"].([]interface{})) != 0 {
		t.Fatalf("stale items shown: %v", inbox)
	}
	if n := len(e.s.db.inbox); n != 0 {
		t.Fatalf("%d stale items kept (with codes)", n)
	}
}

func TestInboxItemsExpire(t *testing.T) {
	e := newTestEnv(t)
	e.s.db.AddInboxItem(&InboxItem{ID: "x", RecipientID: e.userIDForEmail("bob@example.com"), Code: "c", ExpiresAt: time.Now().Add(-time.Second)})
	bob := e.sessionForEmail("bob@example.com") // triggers cleanup
	if _, inbox := e.do(t, "GET", "/api/inbox", nil, bob, ""); len(inbox["items"].([]interface{})) != 0 {
		t.Fatal("expired item shown")
	}
	if _, ok := e.s.db.inbox["x"]; ok {
		t.Fatal("expired item (and its code) kept")
	}
}

func TestAPITokens(t *testing.T) {
	e := newTestEnv(t)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	alice := e.sessionForEmail("alice@example.com")

	code, out := e.do(t, "POST", "/api/tokens", map[string]string{"name": "laptop"}, alice, "")
	token, _ := out["token"].(string)
	if code != 200 || !strings.HasPrefix(token, "hp_") {
		t.Fatalf("create token: %d %v", code, out)
	}
	// The token works for API calls...
	if _, me := e.do(t, "GET", "/api/auth/me", nil, "", token); me["email"] != "alice@example.com" {
		t.Fatalf("auth/me with token: %v", me)
	}
	// ...but can't manage tokens, and isn't stored in the clear.
	if code, _ := e.do(t, "POST", "/api/tokens", nil, "", token); code != 401 {
		t.Fatalf("token minted a token: %d", code)
	}
	raw, _ := os.ReadFile(filepath.Join(e.s.db.dataDir, "tokens.json"))
	if strings.Contains(string(raw), token) {
		t.Fatal("token stored in plaintext")
	}

	// A CLI can register its transfer (only if it's really on the relay) and notify.
	hash := strings.Repeat("dd", 32)
	if code, _ := e.do(t, "POST", "/api/transfers", map[string]interface{}{"manifest_hash": hash, "transfer_name": "cli"}, "", token); code != 404 {
		t.Fatalf("register missing transfer: %d", code)
	}
	e.relay.manifests[hash] = []byte("enc")
	code, reg := e.do(t, "POST", "/api/transfers", map[string]interface{}{"manifest_hash": hash, "transfer_name": "cli", "files": 1}, "", token)
	if code != 200 || reg["transfer_id"] == "" {
		t.Fatalf("register: %d %v", code, reg)
	}
	e.s.db.SetProfile(e.userIDForEmail("bob@example.com"), "bob", false)
	if code, out := e.do(t, "POST", "/api/notify", map[string]interface{}{
		"transfer_id": reg["transfer_id"], "manifest_hash": hash,
		"code": "orbit-velvet-zoom-candle-harbor-ember", "recipients": []string{"bob"},
	}, "", token); code != 200 || out["inboxed"] != float64(1) {
		t.Fatalf("notify via token: %d %v", code, out)
	}

	// Revoked tokens stop working.
	_, list := e.do(t, "GET", "/api/tokens", nil, alice, "")
	id := list["tokens"].([]interface{})[0].(map[string]interface{})["id"].(string)
	e.do(t, "DELETE", "/api/tokens/"+id, nil, alice, "")
	if _, me := e.do(t, "GET", "/api/auth/me", nil, "", token); me["authenticated"] != false {
		t.Fatal("revoked token still works")
	}
}

func TestConfigEndpoint(t *testing.T) {
	e := newTestEnv(t)
	e.s.relayPublicURL = "https://relay.example.com"
	_, cfg := e.do(t, "GET", "/api/config", nil, "", "")
	if cfg["relay_url"] != "https://relay.example.com" || fmt.Sprint(cfg["storage_nodes"]) != "["+publicNode+"]" {
		t.Fatalf("config: %v", cfg)
	}
}

func TestCancelClearsInbox(t *testing.T) {
	e := newTestEnv(t)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	alice := e.sessionForEmail("alice@example.com")
	e.s.db.SetProfile(e.userIDForEmail("bob@example.com"), "bob", false)
	hash := strings.Repeat("ee", 32)
	ackSecret := bytes.Repeat([]byte{4}, 32)
	ackSum := blake3.Sum256(ackSecret)
	sendToUsers(t, e, alice, hash, []string{"bob"})
	e.relay.ackHashes[hash] = hex.EncodeToString(ackSum[:])

	code, _ := e.do(t, "POST", "/api/cancel", map[string]interface{}{
		"manifest_hash": hash, "ack_secret": hex.EncodeToString(ackSecret), "delete_token": strings.Repeat("11", 32),
	}, "", "")
	if code != 200 || len(e.s.db.inbox) != 0 {
		t.Fatalf("cancel: %d, %d inbox items left", code, len(e.s.db.inbox))
	}
}

func TestMessageReachesInboxAndEmails(t *testing.T) {
	e := newTestEnv(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	alice := e.sessionForEmail("alice@example.com")
	bob := e.sessionForEmail("bob@example.com")
	e.s.db.SetProfile(e.userIDForEmail("bob@example.com"), "bob", false)
	hash := strings.Repeat("ab", 32)
	e.relay.manifests[hash] = []byte("enc")

	upload := func(msg string) (int, map[string]interface{}) {
		uploadHash := make([]byte, 32)
		rand.Read(uploadHash)
		return e.do(t, "POST", "/api/upload/manifest", map[string]interface{}{
			"manifest_hash": hex.EncodeToString(uploadHash), "manifest_data": []byte("x"),
			"ack_hash": strings.Repeat("ac", 32), "transfer_name": "weights", "message": msg,
		}, alice, "")
	}
	if code, _ := upload(strings.Repeat("x", 2001)); code != 400 {
		t.Fatalf("too-long message accepted: %d", code)
	}
	_, up := upload("  Fine-tuned on run 42.\nUse tokenizer v3.\x1b[2J  ")

	code, _ := e.do(t, "POST", "/api/notify", map[string]interface{}{
		"transfer_id": up["transfer_id"], "manifest_hash": hash,
		"code": "orbit-velvet-zoom-candle-harbor-ember", "recipients": []string{"bob", "carol@example.com"},
	}, alice, "")
	if code != 200 {
		t.Fatalf("notify: %d", code)
	}

	want := "Fine-tuned on run 42.\nUse tokenizer v3.[2J"
	_, inbox := e.do(t, "GET", "/api/inbox", nil, bob, "")
	item := inbox["items"].([]interface{})[0].(map[string]interface{})
	if item["message"] != want {
		t.Fatalf("inbox message %q", item["message"])
	}
	_, hist := e.do(t, "GET", "/api/history", nil, alice, "")
	if !strings.Contains(fmt.Sprint(hist), "Fine-tuned on run 42.") {
		t.Fatalf("history lacks message: %v", hist)
	}
	for _, who := range []string{"Inbox alert to bob@example.com", "Email to carol@example.com"} {
		if !strings.Contains(logs.String(), who) || !strings.Contains(logs.String(), `Fine-tuned on run 42.\nUse tokenizer v3.`) {
			t.Fatalf("%s missing message in logs: %s", who, logs.String())
		}
	}
}

func TestEmailMessageBlock(t *testing.T) {
	if got := emailMessageBlock("alice", ""); got != "" {
		t.Fatalf("empty message: %q", got)
	}
	got := emailMessageBlock("alice", "line one\nline two")
	if !strings.Contains(got, "Message from alice:") || !strings.Contains(got, "  > line one\n  > line two") {
		t.Fatalf("got %q", got)
	}
}

// loginByEmail creates (or finds) the account for an email through the normal
// magic-link login and returns its ID.
func loginByEmail(t *testing.T, db *DB, email string) string {
	t.Helper()
	link, err := db.CreateMagicLink(email)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.VerifyMagicLink(link.Token)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestLinkEmailRefusesAddressOwnedByAnotherAccount(t *testing.T) {
	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	victimID := loginByEmail(t, db, "victim@example.com")

	// Someone with a username-only account asks to link the victim's address,
	// in any letter case, and the victim opens the link.
	attacker := db.CreateUser()
	for _, addr := range []string{"victim@example.com", "Victim@Example.com"} {
		link, err := db.CreateMagicLinkForUser(addr, attacker.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.VerifyMagicLink(link.Token); err != errEmailTaken {
			t.Fatalf("linking %q: expected errEmailTaken, got %v", addr, err)
		}
	}

	// The address still belongs to the victim, and the attacker gained nothing.
	owner, _ := db.GetUserByEmail("victim@example.com")
	if owner.ID != victimID {
		t.Fatalf("owner of the email is %q, expected the victim %q", owner.ID, victimID)
	}
	if a, _ := db.GetUser(attacker.ID); a.Email != "" {
		t.Fatalf("attacker account got the email %q", a.Email)
	}
	// The victim's next email login still lands in the victim's own account.
	if again := loginByEmail(t, db, "victim@example.com"); again != victimID {
		t.Fatalf("a later login went to %q instead of %q", again, victimID)
	}
	// The same must hold after a restart.
	db2, _ := NewDB(db.dataDir)
	if o, _ := db2.GetUserByEmail("victim@example.com"); o.ID != victimID {
		t.Fatalf("after reload the owner is %q", o.ID)
	}
}

func TestLinkEmailRejectedOverHTTP(t *testing.T) {
	e := newTestEnv(t)
	victimID := loginByEmail(t, e.s.db, "victim@example.com")
	attacker := e.s.db.CreateUser()
	link, _ := e.s.db.CreateMagicLinkForUser("victim@example.com", attacker.ID)

	resp := e.post(t, "/api/auth/verify", map[string]string{"token": link.Token}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
	if sessionFrom(resp) != "" {
		t.Fatal("a rejected link must not create a session")
	}
	if o, _ := e.s.db.GetUserByEmail("victim@example.com"); o.ID != victimID {
		t.Fatalf("the email moved to %q", o.ID)
	}
}

func TestLinkEmailAllowsOwnAddressAndReplacesOldOne(t *testing.T) {
	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	u := db.CreateUser()

	link := func(addr string) error {
		l, _ := db.CreateMagicLinkForUser(addr, u.ID)
		_, err := db.VerifyMagicLink(l.Token)
		return err
	}
	if err := link("me@example.com"); err != nil {
		t.Fatalf("first link: %v", err)
	}
	// Linking the address the account already owns is fine.
	if err := link("ME@example.com"); err != nil {
		t.Fatalf("relinking own address: %v", err)
	}
	// Changing to a new address frees the old one, even if it was stored
	// with capital letters (accounts migrated from older versions).
	db.mu.Lock()
	db.users[u.ID].Email = "Me@Example.com"
	db.mu.Unlock()
	if err := link("new@example.com"); err != nil {
		t.Fatalf("changing address: %v", err)
	}
	if _, ok := db.GetUserByEmail("me@example.com"); ok {
		t.Fatal("the old address still resolves to an account")
	}
	if o, _ := db.GetUserByEmail("new@example.com"); o.ID != u.ID {
		t.Fatalf("new address owned by %q", o.ID)
	}
}

// sessionFrom returns the session cookie set by a response, if any.
func sessionFrom(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "helppeer_session" && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

func TestLinkEmailRequestAnswersWhenAddressIsInUse(t *testing.T) {
	e := newTestEnv(t)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	victimID := loginByEmail(t, e.s.db, "victim@example.com")
	asker := e.s.db.CreateUser()
	session := e.s.db.CreateSession(asker.ID)
	linksBefore := len(e.s.db.links)

	request := func(addr string) (int, map[string]string) {
		resp := e.post(t, "/api/auth/link-email", map[string]string{"email": addr}, session)
		var out map[string]string
		decode(t, resp, &out)
		return resp.StatusCode, out
	}

	// An address owned by someone else is refused right away, in any letter
	// case, and no link is created (so no email is sent).
	for _, addr := range []string{"victim@example.com", "VICTIM@Example.com", "victim@example.com"} {
		code, out := request(addr)
		if code != http.StatusConflict || out["error"] != "That email address is already in use." {
			t.Fatalf("%q: got %d %v", addr, code, out)
		}
	}
	if len(e.s.db.links) != linksBefore {
		t.Fatal("a refused request must not create a link")
	}

	// Those probes did not use up the owner's own login budget.
	resp := e.post(t, "/api/auth/request", map[string]string{"email": "victim@example.com"}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's login request got %d after probes", resp.StatusCode)
	}

	// A free address still gets a link.
	if code, out := request("free@example.com"); code != http.StatusOK || out["status"] != "sent" {
		t.Fatalf("free address: got %d %v", code, out)
	}

	// An account's own address is answered without sending anything.
	own := e.s.db.CreateUser()
	if err := e.s.db.LinkEmail(own.ID, "mine@example.com"); err != nil {
		t.Fatal(err)
	}
	ownSession := e.s.db.CreateSession(own.ID)
	before := len(e.s.db.links)
	resp = e.post(t, "/api/auth/link-email", map[string]string{"email": "mine@example.com"}, ownSession)
	var out map[string]string
	decode(t, resp, &out)
	if resp.StatusCode != http.StatusOK || out["status"] != "linked" || len(e.s.db.links) != before {
		t.Fatalf("own address: got %d %v", resp.StatusCode, out)
	}
	_ = victimID
}

func TestLoadKeepsOneOwnerPerEmail(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	dir := t.TempDir()
	users := `{
	  "bbb": {"id":"bbb","email":"Shared@Example.com","created_at":"2026-02-01T00:00:00Z"},
	  "aaa": {"id":"aaa","email":"shared@example.com","created_at":"2026-01-01T00:00:00Z"},
	  "ccc": {"id":"ccc","email":"shared@example.com","created_at":"2026-03-01T00:00:00Z"},
	  "ddd": {"id":"ddd","email":"other@example.com","created_at":"2026-03-01T00:00:00Z"}
	}`
	if err := os.WriteFile(filepath.Join(dir, "users.json"), []byte(users), 0600); err != nil {
		t.Fatal(err)
	}

	// The oldest account owns the address after every restart.
	for i := 0; i < 40; i++ {
		db, _ := NewDB(dir)
		if o, ok := db.GetUserByEmail("shared@example.com"); !ok || o.ID != "aaa" {
			t.Fatalf("load %d: owner is %q", i, o.ID)
		}
		if b, _ := db.GetUser("bbb"); b.Email != "" {
			t.Fatalf("load %d: the newer account still has an email: %q", i, b.Email)
		}
		if c, _ := db.GetUser("ccc"); c.Email != "" {
			t.Fatalf("load %d: the newest account still has an email", i)
		}
		// Unrelated accounts are not touched.
		if o, ok := db.GetUserByEmail("other@example.com"); !ok || o.ID != "ddd" {
			t.Fatalf("load %d: the other account lost its email", i)
		}
	}
}

func TestLoadBreaksTiesByID(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	dir := t.TempDir()
	users := `{
	  "zzz": {"id":"zzz","email":"x@example.com","created_at":"2026-01-01T00:00:00Z"},
	  "mmm": {"id":"mmm","email":"x@example.com","created_at":"2026-01-01T00:00:00Z"}
	}`
	os.WriteFile(filepath.Join(dir, "users.json"), []byte(users), 0600)
	for i := 0; i < 20; i++ {
		db, _ := NewDB(dir)
		if o, _ := db.GetUserByEmail("x@example.com"); o.ID != "mmm" {
			t.Fatalf("load %d: owner is %q", i, o.ID)
		}
	}
}

func TestRemoveEmailNeedsAUsername(t *testing.T) {
	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// An email-only account cannot drop its only way to log in.
	emailOnly := loginByEmail(t, db, "only@example.com")
	if err := db.RemoveEmail(emailOnly); err != errNeedUsername {
		t.Fatalf("expected errNeedUsername, got %v", err)
	}
	if o, _ := db.GetUserByEmail("only@example.com"); o.ID != emailOnly {
		t.Fatal("the email was removed anyway")
	}

	// With a username it works, and the address is free afterwards.
	if err := db.SetProfile(emailOnly, "someone", false); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveEmail(emailOnly); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.GetUserByEmail("only@example.com"); ok {
		t.Fatal("the address still resolves to an account")
	}
	if u, _ := db.GetUser(emailOnly); u.Email != "" || u.Username != "someone" {
		t.Fatalf("account after removal: %+v", u)
	}
	// Removing again is harmless.
	if err := db.RemoveEmail(emailOnly); err != nil {
		t.Fatal(err)
	}
	// And it is saved.
	db2, _ := NewDB(db.dataDir)
	if _, ok := db2.GetUserByEmail("only@example.com"); ok {
		t.Fatal("the removal was not saved")
	}
}

func TestUnlinkEmailOverHTTP(t *testing.T) {
	e := newTestEnv(t)

	// Not logged in.
	resp := e.post(t, "/api/auth/unlink-email", map[string]string{}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", resp.StatusCode)
	}

	// Email-only account: refused with a clear message.
	emailOnly := loginByEmail(t, e.s.db, "only@example.com")
	session := e.s.db.CreateSession(emailOnly)
	resp = e.post(t, "/api/auth/unlink-email", map[string]string{}, session)
	var out map[string]string
	decode(t, resp, &out)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(out["error"], "username") {
		t.Fatalf("email-only: %d %v", resp.StatusCode, out)
	}

	// With a username it works.
	e.s.db.SetProfile(emailOnly, "someone", false)
	resp = e.post(t, "/api/auth/unlink-email", map[string]string{}, session)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with username: %d", resp.StatusCode)
	}
	if _, ok := e.s.db.GetUserByEmail("only@example.com"); ok {
		t.Fatal("the address is still linked")
	}
}

func TestChangeEmailKeepsTheOldOneUntilConfirmed(t *testing.T) {
	e := newTestEnv(t)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	id := loginByEmail(t, e.s.db, "old@example.com")
	e.s.db.SetProfile(id, "changer", false)
	session := e.s.db.CreateSession(id)

	resp := e.post(t, "/api/auth/link-email", map[string]string{"email": "new@example.com"}, session)
	var out map[string]string
	decode(t, resp, &out)
	if resp.StatusCode != http.StatusOK || out["status"] != "sent" {
		t.Fatalf("request: %d %v", resp.StatusCode, out)
	}
	// Nothing changes until the new address is confirmed.
	if o, _ := e.s.db.GetUserByEmail("old@example.com"); o.ID != id {
		t.Fatal("the old address was dropped before confirmation")
	}
	if _, ok := e.s.db.GetUserByEmail("new@example.com"); ok {
		t.Fatal("the new address was linked before confirmation")
	}

	// Confirming switches the account to the new address and frees the old one.
	var token string
	e.s.db.mu.Lock()
	for tok, l := range e.s.db.links {
		if l.UserID == id && l.Email == "new@example.com" {
			token = tok
		}
	}
	e.s.db.mu.Unlock()
	if token == "" {
		t.Fatal("no confirmation link was created")
	}
	if _, err := e.s.db.VerifyMagicLink(token); err != nil {
		t.Fatal(err)
	}
	if o, _ := e.s.db.GetUserByEmail("new@example.com"); o.ID != id {
		t.Fatal("the new address is not linked")
	}
	if _, ok := e.s.db.GetUserByEmail("old@example.com"); ok {
		t.Fatal("the old address still resolves to an account")
	}
}

// postAs sends a JSON POST that appears to come from the given client address
// (the server runs behind a proxy, so it reads X-Forwarded-For).
func (e *testEnv) postAs(t *testing.T, ip, path string, body interface{}, session string) *http.Response {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(data))
	req.Header.Set("X-Forwarded-For", ip)
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "helppeer_session", Value: session})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// trustTheProxy makes the server use X-Forwarded-For for the test.
func trustTheProxy(t *testing.T) {
	t.Helper()
	old := trustProxy
	trustProxy = true
	t.Cleanup(func() { trustProxy = old })
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
}

func TestSignupsDoNotUseUpTheLoginBudget(t *testing.T) {
	e := newTestEnv(t)
	trustTheProxy(t)
	const busy = "198.51.100.1"

	for i := 1; i <= 10; i++ {
		resp := e.postAs(t, busy, "/api/auth/signup", map[string]string{"username": fmt.Sprintf("user-%d", i)}, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("signup %d: %d", i, resp.StatusCode)
		}
	}
	if resp := e.postAs(t, busy, "/api/auth/signup", map[string]string{"username": "user-11"}, ""); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the 11th signup from one client: %d", resp.StatusCode)
	}
	// That client can still ask for a login link, and another client can still sign up.
	if resp := e.postAs(t, busy, "/api/auth/request", map[string]string{"email": "real.user@example.com"}, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("login request after many signups: %d", resp.StatusCode)
	}
	if resp := e.postAs(t, "198.51.100.2", "/api/auth/signup", map[string]string{"username": "someone-else"}, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("signup from another client: %d", resp.StatusCode)
	}
}

func TestSomeoneElseCannotLockYouOutOfLogin(t *testing.T) {
	e := newTestEnv(t)
	trustTheProxy(t)
	victim := map[string]string{"email": "victim@example.com"}

	for i := 0; i < 3; i++ {
		if resp := e.postAs(t, "198.51.100.66", "/api/auth/request", victim, ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, resp.StatusCode)
		}
	}
	if resp := e.postAs(t, "198.51.100.66", "/api/auth/request", victim, ""); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the 4th request from the same client: %d", resp.StatusCode)
	}
	// The owner, from somewhere else, is not locked out.
	if resp := e.postAs(t, "198.51.100.99", "/api/auth/request", victim, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner was locked out: %d", resp.StatusCode)
	}
}

func TestOneAddressCannotBeFloodedFromManyClients(t *testing.T) {
	e := newTestEnv(t)
	trustTheProxy(t)
	target := map[string]string{"email": "target@example.com"}

	for i := 1; i <= 10; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		if resp := e.postAs(t, ip, "/api/auth/request", target, ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("client %d: %d", i, resp.StatusCode)
		}
	}
	if resp := e.postAs(t, "203.0.113.11", "/api/auth/request", target, ""); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the 11th client for one address: %d", resp.StatusCode)
	}
}

func TestLinkEmailRequestsHaveTheirOwnBudgets(t *testing.T) {
	e := newTestEnv(t)
	trustTheProxy(t)
	victimID := loginByEmail(t, e.s.db, "victim@example.com")
	_ = victimID
	asker := e.s.db.CreateUser()
	session := e.s.db.CreateSession(asker.ID)
	const ip = "192.0.2.10"
	link := func(addr string) int {
		return e.postAs(t, ip, "/api/auth/link-email", map[string]string{"email": addr}, session).StatusCode
	}

	// The same free address: 3 requests per client, then refused.
	for i := 0; i < 3; i++ {
		if code := link("free@example.com"); code != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, code)
		}
	}
	if code := link("free@example.com"); code != http.StatusTooManyRequests {
		t.Fatalf("the 4th request for one address: %d", code)
	}
	// A different address is still fine: 5 per account per hour, 4 used so far.
	if code := link("other@example.com"); code != http.StatusOK {
		t.Fatalf("another address: %d", code)
	}
	// The account has now used its 5 requests: even an address in use is refused.
	if code := link("victim@example.com"); code != http.StatusTooManyRequests {
		t.Fatalf("the 6th request from one account: %d", code)
	}
	// None of that used up the owner's login allowance.
	if resp := e.postAs(t, "192.0.2.77", "/api/auth/request", map[string]string{"email": "victim@example.com"}, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's login request: %d", resp.StatusCode)
	}
}
