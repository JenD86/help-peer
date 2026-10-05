package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeVolunteer is a volunteer storage node that can be told to misbehave.
type fakeVolunteer struct {
	mu       sync.Mutex
	key      ed25519.PrivateKey
	id       string
	shards   map[string][]byte
	puts     int
	full     bool   // refuse uploads with 507
	lose     bool   // accept uploads but don't keep them
	corrupt  bool   // return altered data
	healthID string // node_id to report instead of its own
	lastTS   int64
	srv      *httptest.Server
}

func newVolunteer(t *testing.T) *fakeVolunteer {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	v := &fakeVolunteer{key: key, shards: map[string][]byte{}}
	v.id = nodeIDPrefix + base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	v.srv = httptest.NewServer(v)
	t.Cleanup(v.srv.Close)
	return v
}

func (v *fakeVolunteer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if req.URL.Path == "/health" {
		id := v.id
		if v.healthID != "" {
			id = v.healthID
		}
		json.NewEncoder(w).Encode(map[string]string{"node_id": id})
		return
	}
	hash := strings.TrimPrefix(req.URL.Path, "/shard/")
	switch req.Method {
	case http.MethodPut:
		if v.full {
			w.WriteHeader(http.StatusInsufficientStorage)
			return
		}
		data, _ := io.ReadAll(req.Body)
		if blake3Hex(data) != hash {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		v.puts++
		if !v.lose {
			v.shards[hash] = data
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		data, ok := v.shards[hash]
		if !ok {
			http.NotFound(w, req)
			return
		}
		if v.corrupt {
			data = append([]byte{}, data...)
			data[0] ^= 0xff
		}
		w.Write(data)
	case http.MethodDelete:
		delete(v.shards, hash)
		w.WriteHeader(http.StatusNoContent)
	}
}

// signed builds a signed node request as this volunteer.
func (v *fakeVolunteer) signed(action, url string, available int64) ([]byte, string) {
	v.mu.Lock()
	ts := time.Now().UnixMilli()
	if ts <= v.lastTS {
		ts = v.lastTS + 1
	}
	v.lastTS = ts
	v.mu.Unlock()
	body, _ := json.Marshal(nodeRequest{
		Action: action, NodeID: v.id, URL: url, CapacityBytes: available,
		AvailableBytes: available, Timestamp: ts,
	})
	return body, base64.RawURLEncoding.EncodeToString(ed25519.Sign(v.key, body))
}

func (e *testEnv) nodeCall(t *testing.T, path string, body []byte, sig string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("X-Node-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(msg)
}

func (e *testEnv) register(t *testing.T, v *fakeVolunteer, available int64) (int, string) {
	t.Helper()
	body, sig := v.signed("register", v.srv.URL, available)
	return e.nodeCall(t, "/api/node/register", body, sig)
}

// newNodeEnv is a test server that accepts volunteer nodes on loopback and
// puts each in the network given by netOf (keyed by node URL).
func newNodeEnv(t *testing.T, netOf map[string]string) *testEnv {
	e := newTestEnv(t)
	e.s.nodes.SetAllowPrivate(true)
	e.s.nodes.networkOf = func(_ net.IP, url string) string {
		if n, ok := netOf[url]; ok {
			return n
		}
		return "net:" + url
	}
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return e
}

func TestNodeRequestsMustBeSignedAndFresh(t *testing.T) {
	e := newNodeEnv(t, nil)
	v := newVolunteer(t)

	body, sig := v.signed("register", v.srv.URL, 1<<30)
	tampered := bytes.Replace(body, []byte(v.srv.URL), []byte("http://elsewhere.example"), 1)
	if code, _ := e.nodeCall(t, "/api/node/register", tampered, sig); code != 401 {
		t.Errorf("tampered body: %d", code)
	}
	if code, _ := e.nodeCall(t, "/api/node/register", body, ""); code != 401 {
		t.Errorf("missing signature: %d", code)
	}
	dereg, dsig := v.signed("deregister", v.srv.URL, 0)
	if code, _ := e.nodeCall(t, "/api/node/register", dereg, dsig); code != 401 {
		t.Errorf("wrong action: %d", code)
	}
	old, _ := json.Marshal(nodeRequest{Action: "register", NodeID: v.id, URL: v.srv.URL, Timestamp: time.Now().Add(-time.Hour).UnixMilli()})
	if code, _ := e.nodeCall(t, "/api/node/register", old, base64.RawURLEncoding.EncodeToString(ed25519.Sign(v.key, old))); code != 401 {
		t.Errorf("old timestamp: %d", code)
	}

	if code, msg := e.nodeCall(t, "/api/node/register", body, sig); code != 200 {
		t.Fatalf("valid registration: %d %s", code, msg)
	}
	if code, _ := e.nodeCall(t, "/api/node/register", body, sig); code != 409 {
		t.Errorf("replayed registration: %d", code)
	}
}

func TestRegistrationProvesControlOfURL(t *testing.T) {
	e := newNodeEnv(t, nil)
	victim := newVolunteer(t)
	attacker := newVolunteer(t)

	// The attacker claims the victim's server (which reports the victim's key).
	body, sig := attacker.signed("register", victim.srv.URL, 1<<30)
	if code, msg := e.nodeCall(t, "/api/node/register", body, sig); code != 400 || !strings.Contains(msg, "does not identify") {
		t.Fatalf("registering someone else's node: %d %s", code, msg)
	}
	// An internal service with a /health but no node identity is refused too.
	relayLike := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer relayLike.Close()
	body, sig = attacker.signed("register", relayLike.URL, 1<<30)
	if code, _ := e.nodeCall(t, "/api/node/register", body, sig); code != 400 {
		t.Fatalf("registering a non-node service: %d", code)
	}
}

func TestRegistrationRunsStorageTest(t *testing.T) {
	e := newNodeEnv(t, nil)
	for name, setup := range map[string]func(*fakeVolunteer){
		"loses data": func(v *fakeVolunteer) { v.lose = true },
		"corrupts":   func(v *fakeVolunteer) { v.corrupt = true },
		"is full":    func(v *fakeVolunteer) { v.full = true },
	} {
		v := newVolunteer(t)
		setup(v)
		if code, msg := e.register(t, v, 1<<30); code != http.StatusBadGateway || !strings.Contains(msg, "storage test") {
			t.Errorf("node that %s: %d %s", name, code, msg)
		}
	}

	// A good node passes, and its heartbeats don't repeat the test.
	v := newVolunteer(t)
	for i := 0; i < 3; i++ {
		if code, msg := e.register(t, v, 1<<30); code != 200 {
			t.Fatalf("heartbeat %d: %d %s", i, code, msg)
		}
	}
	if v.puts != 1 {
		t.Fatalf("storage test ran %d times", v.puts)
	}
	if len(v.shards) != 0 {
		t.Fatal("test shard not cleaned up")
	}
}

func TestOnlyOwnerCanDeregister(t *testing.T) {
	e := newNodeEnv(t, nil)
	victim := newVolunteer(t)
	attacker := newVolunteer(t)
	e.register(t, victim, 1<<30)

	// The attacker can't sign as the victim...
	body, _ := json.Marshal(nodeRequest{Action: "deregister", NodeID: victim.id, Timestamp: time.Now().UnixMilli()})
	if code, _ := e.nodeCall(t, "/api/node/deregister", body, base64.RawURLEncoding.EncodeToString(ed25519.Sign(attacker.key, body))); code != 401 {
		t.Fatalf("forged deregistration: %d", code)
	}
	if _, _, ok := e.s.nodes.InternalURL(victim.srv.URL); !ok {
		t.Fatal("victim was removed")
	}
	// ...but the victim can leave.
	body, sig := victim.signed("deregister", victim.srv.URL, 0)
	if code, _ := e.nodeCall(t, "/api/node/deregister", body, sig); code != 200 {
		t.Fatalf("deregistration: %d", code)
	}
	if _, _, ok := e.s.nodes.InternalURL(victim.srv.URL); ok {
		t.Fatal("node still listed after deregistering")
	}
}

func TestPrivateAddressesRefused(t *testing.T) {
	e := newTestEnv(t) // ALLOW_PRIVATE_NODES not set
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	v := newVolunteer(t)
	if code, msg := e.register(t, v, 1<<30); code != 400 || !strings.Contains(msg, "private") {
		t.Fatalf("loopback node: %d %s", code, msg)
	}
	// Even a public-looking hostname is refused at connect time if it resolves internally.
	if _, err := newNodeClient(false, time.Second).Get(v.srv.URL + "/health"); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("node client connected to loopback: %v", err)
	}
	for ip, public := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true, "127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false,
		"192.168.1.1": false, "169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false,
		"fe80::1": false, "fd00::1": false, "::ffff:10.0.0.1": false,
	} {
		if got := isPublicIP(net.ParseIP(ip)); got != public {
			t.Errorf("isPublicIP(%s) = %v", ip, got)
		}
	}
}

// uploadSegment uploads a random segment and returns where its shards went.
func uploadSegment(t *testing.T, e *testEnv) (SegmentUploadResponse, int) {
	t.Helper()
	segment := make([]byte, 100003)
	rand.Read(segment)
	resp := e.post(t, "/api/upload/segment", segment, "")
	var up SegmentUploadResponse
	if resp.StatusCode == 200 {
		decode(t, resp, &up)
	} else {
		resp.Body.Close()
	}
	return up, resp.StatusCode
}

func TestPlacementLimitsShardsPerNetwork(t *testing.T) {
	vols := []*fakeVolunteer{newVolunteer(t), newVolunteer(t), newVolunteer(t), newVolunteer(t)}
	// Four volunteers, but only two networks: one operator's two machines each.
	netOf := map[string]string{vols[0].srv.URL: "A", vols[1].srv.URL: "A", vols[2].srv.URL: "B", vols[3].srv.URL: "B"}
	e := newNodeEnv(t, netOf)
	for _, v := range vols {
		if code, msg := e.register(t, v, 1<<30); code != 200 {
			t.Fatalf("register: %d %s", code, msg)
		}
	}
	for round := 0; round < 5; round++ {
		up, code := uploadSegment(t, e)
		if code != 200 {
			t.Fatalf("upload: %d", code)
		}
		perNet := map[string]int{}
		for _, sh := range up.Shards {
			if n, ok := netOf[sh.Node]; ok {
				perNet[n]++
			}
		}
		if perNet["A"] > maxShardsPerNetwork || perNet["B"] > maxShardsPerNetwork || perNet["A"] == 0 || perNet["B"] == 0 {
			t.Fatalf("round %d: shards per network %v", round, perNet)
		}
	}
}

func TestPlacementRespectsFreeSpaceAndFullIsNotPenalised(t *testing.T) {
	tiny, full := newVolunteer(t), newVolunteer(t)
	e := newNodeEnv(t, nil)
	e.register(t, tiny, 1000) // less than one shard
	e.register(t, full, 1<<30)
	full.mu.Lock()
	full.full = true // ran out of space after registering
	full.mu.Unlock()

	up, code := uploadSegment(t, e)
	if code != 200 {
		t.Fatalf("upload: %d", code)
	}
	for _, sh := range up.Shards {
		if sh.Node == tiny.srv.URL || sh.Node == full.srv.URL {
			t.Fatalf("shard placed on a node without room: %s", sh.Node)
		}
	}
	n := e.s.nodes.nodes[full.id]
	if n.AuditsFailed != 0 || time.Now().Before(n.SuspendedUntil) || time.Now().After(n.fullUntil) {
		t.Fatalf("full node penalised or not marked full: %+v", n)
	}
	// Its next heartbeat reports space again and it's back in use.
	full.mu.Lock()
	full.full = false
	full.mu.Unlock()
	e.register(t, full, 1<<30)
	got := false
	for i := 0; i < 3 && !got; i++ {
		up, _ = uploadSegment(t, e)
		for _, sh := range up.Shards {
			got = got || sh.Node == full.srv.URL
		}
	}
	if !got {
		t.Fatal("node not used after reporting space again")
	}
}

func TestAuditsSuspendNodeThatLosesData(t *testing.T) {
	good, bad := newVolunteer(t), newVolunteer(t)
	e := newNodeEnv(t, nil)
	e.s.nodes.sample = func() bool { return true }
	e.register(t, good, 1<<30)
	e.register(t, bad, 1<<30) // passes the registration test...
	bad.mu.Lock()
	bad.lose = true // ...then stops keeping data
	bad.mu.Unlock()

	for i := 0; i < 3; i++ {
		uploadSegment(t, e)
	}
	// Make every spot-check due now.
	e.s.nodes.mu.Lock()
	for i := range e.s.nodes.audits {
		e.s.nodes.audits[i].Due = time.Now()
	}
	e.s.nodes.mu.Unlock()
	for i := 0; i < 5; i++ {
		e.s.nodes.runDueAudits()
	}

	b, g := e.s.nodes.nodes[bad.id], e.s.nodes.nodes[good.id]
	if !time.Now().Before(b.SuspendedUntil) || b.AuditsFailed < auditFailLimit {
		t.Fatalf("bad node not suspended: %+v", b)
	}
	if g.AuditsFailed != 0 || g.AuditsPassed == 0 || time.Now().Before(g.SuspendedUntil) {
		t.Fatalf("good node penalised: %+v", g)
	}
	up, _ := uploadSegment(t, e)
	for _, sh := range up.Shards {
		if sh.Node == bad.srv.URL {
			t.Fatal("suspended node still receiving data")
		}
	}
	// Leaving and rejoining doesn't clear the suspension.
	body, sig := bad.signed("deregister", bad.srv.URL, 0)
	e.nodeCall(t, "/api/node/deregister", body, sig)
	bad.mu.Lock()
	bad.lose = false
	bad.mu.Unlock()
	e.register(t, bad, 1<<30)
	if !time.Now().Before(e.s.nodes.nodes[bad.id].SuspendedUntil) {
		t.Fatal("re-registering lifted the suspension")
	}
}

func TestPassiveAuditCountsOnlyCorruption(t *testing.T) {
	v := newVolunteer(t)
	e := newNodeEnv(t, nil)
	e.register(t, v, 1<<30)
	up, _ := uploadSegment(t, e)

	var mine []ShardInfo
	for _, sh := range up.Shards {
		if sh.Node == v.srv.URL {
			mine = append(mine, sh)
		}
	}
	if len(mine) == 0 {
		t.Fatal("no shards on the volunteer")
	}
	// A client lying about the size doesn't make an honest node look bad.
	resp := e.post(t, "/api/download/segment", SegmentDownloadRequest{EncryptedSize: 5000, Shards: mine}, "")
	resp.Body.Close()
	if n := e.s.nodes.nodes[v.id]; n.AuditsFailed != 0 || n.AuditsPassed != 0 {
		t.Fatalf("size lie counted: %+v", n)
	}
	// Returning altered data does count.
	v.mu.Lock()
	v.corrupt = true
	v.mu.Unlock()
	resp = e.post(t, "/api/download/segment", SegmentDownloadRequest{EncryptedSize: up.EncryptedSize, Shards: mine}, "")
	resp.Body.Close()
	if n := e.s.nodes.nodes[v.id]; n.AuditsFailed == 0 {
		t.Fatalf("corruption not counted: %+v", n)
	}
}

func TestAdminCanBanNodes(t *testing.T) {
	v := newVolunteer(t)
	e := newNodeEnv(t, nil)
	e.register(t, v, 1<<30)

	admin := func(token, method string, body interface{}) int {
		var r io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			r = bytes.NewReader(data)
		}
		req, _ := http.NewRequest(method, e.srv.URL+"/api/admin/nodes", r)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := admin("", "GET", nil); code != 404 {
		t.Fatalf("admin API exists without a token configured: %d", code)
	}
	e.s.adminToken = "op-secret"
	if code := admin("wrong", "GET", nil); code != 404 {
		t.Fatalf("wrong token: %d", code)
	}
	if code := admin("op-secret", "GET", nil); code != 200 {
		t.Fatalf("list: %d", code)
	}
	if code := admin("op-secret", "POST", map[string]string{"action": "ban", "node_id": v.id}); code != 200 {
		t.Fatalf("ban: %d", code)
	}
	if _, _, ok := e.s.nodes.InternalURL(v.srv.URL); ok {
		t.Fatal("banned node still listed")
	}
	if code, _ := e.register(t, v, 1<<30); code != 403 {
		t.Fatalf("banned node re-registered: %d", code)
	}
}

func TestConfigNodesKeepsCLISpreadSafe(t *testing.T) {
	vols := make([]*fakeVolunteer, 6)
	netOf := map[string]string{}
	for i := range vols {
		vols[i] = newVolunteer(t)
		netOf[vols[i].srv.URL] = fmt.Sprintf("net%d", i/2) // pairs share a network
	}
	e := newNodeEnv(t, netOf)
	register := func(n int) {
		for _, v := range vols[:n] {
			e.register(t, v, 1<<30)
		}
	}

	// 1 static + 2 volunteer networks: too few for the CLI's round-robin.
	register(4)
	if got := e.s.nodes.ConfigNodes(); len(got) != 1 {
		t.Fatalf("expected only the static node, got %v", got)
	}
	// 1 static + 3 networks, but still one volunteer per network: 4 < 6.
	register(6)
	if got := e.s.nodes.ConfigNodes(); len(got) != 1 {
		t.Fatalf("expected only the static node, got %v", got)
	}
	// More networks join: now volunteers are listed, one per network.
	more := make([]*fakeVolunteer, 3)
	for i := range more {
		more[i] = newVolunteer(t)
		netOf[more[i].srv.URL] = fmt.Sprintf("other%d", i)
		e.register(t, more[i], 1<<30)
	}
	got := e.s.nodes.ConfigNodes()
	if len(got) != 7 {
		t.Fatalf("expected static + 6 networks, got %d: %v", len(got), got)
	}
}
