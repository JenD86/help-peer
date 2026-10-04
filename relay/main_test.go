package main

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lukechampine.com/blake3"
)

var testHash = strings.Repeat("ab", 32)

func newTestRelay(t *testing.T) (*Relay, *httptest.Server) {
	t.Helper()
	r := &Relay{
		dataDir:          t.TempDir(),
		started:          time.Now(),
		ttl:              time.Hour,
		maxManifestBytes: 1024,
		maxTotalBytes:    4096,
		defaultRetrieval: 1,
		misses:           newRateLimiter("misses", 3, time.Minute),
		puts:             newRateLimiter("puts", 100, time.Minute),
	}
	srv := httptest.NewServer(r.routes())
	t.Cleanup(srv.Close)
	return r, srv
}

func do(t *testing.T, method, url string, body []byte, headers map[string]string) *http.Response {
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
	return resp
}

// Manifests without X-Ack-Hash (older clients) are consumed on fetch.
func TestLegacyPutGetOneTime(t *testing.T) {
	_, srv := newTestRelay(t)
	url := srv.URL + "/manifest/" + testHash

	if r := do(t, "PUT", url, []byte("data"), nil); r.StatusCode != 201 {
		t.Fatalf("put: %d", r.StatusCode)
	}
	if r := do(t, "PUT", url, []byte("data"), nil); r.StatusCode != 409 {
		t.Fatalf("second put: %d", r.StatusCode)
	}
	if r := do(t, "GET", url, nil, nil); r.StatusCode != 200 {
		t.Fatalf("get: %d", r.StatusCode)
	}
	if r := do(t, "GET", url, nil, nil); r.StatusCode != 404 {
		t.Fatalf("second get: %d", r.StatusCode)
	}
}

func TestMaxRetrievals(t *testing.T) {
	_, srv := newTestRelay(t)
	url := srv.URL + "/manifest/" + testHash
	do(t, "PUT", url, []byte("data"), map[string]string{"X-Max-Retrievals": "2"})
	for i, want := range []int{200, 200, 404} {
		if r := do(t, "GET", url, nil, nil); r.StatusCode != want {
			t.Fatalf("get %d: got %d want %d", i, r.StatusCode, want)
		}
	}
	if r := do(t, "PUT", url, []byte("x"), map[string]string{"X-Max-Retrievals": "100000"}); r.StatusCode != 400 {
		t.Fatalf("uncapped retrievals accepted: %d", r.StatusCode)
	}
}

func TestRejectsBadInput(t *testing.T) {
	_, srv := newTestRelay(t)
	for _, h := range []string{"abc", strings.Repeat("AB", 32), strings.Repeat("ab", 32) + "x"} {
		if r := do(t, "PUT", srv.URL+"/manifest/"+h, []byte("x"), nil); r.StatusCode != 400 {
			t.Errorf("hash %q: got %d", h, r.StatusCode)
		}
	}
	if r := do(t, "PUT", srv.URL+"/manifest/"+testHash, make([]byte, 2048), nil); r.StatusCode != 413 {
		t.Errorf("oversized manifest: got %d", r.StatusCode)
	}
	if r := do(t, "PUT", srv.URL+"/manifest/"+testHash, nil, nil); r.StatusCode != 400 {
		t.Errorf("empty manifest: got %d", r.StatusCode)
	}
}

func TestExpiry(t *testing.T) {
	relay, srv := newTestRelay(t)
	url := srv.URL + "/manifest/" + testHash
	do(t, "PUT", url, []byte("data"), nil)

	// Backdate the expiry.
	path := relay.manifestPath(testHash)
	writeMeta(path, manifestMeta{Remaining: 1, ExpiresAt: time.Now().Add(-time.Second).Unix()})

	relay.cleanupExpired()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expired manifest not removed")
	}
	if r := do(t, "GET", url, nil, nil); r.StatusCode != 404 {
		t.Fatalf("expired get: %d", r.StatusCode)
	}
}

func TestLegacyCountFile(t *testing.T) {
	relay, srv := newTestRelay(t)
	path := relay.manifestPath(testHash)
	os.MkdirAll(filepath.Dir(path), 0755)
	os.WriteFile(path, []byte("old"), 0644)
	os.WriteFile(path+".count", []byte("2"), 0644)

	url := srv.URL + "/manifest/" + testHash
	for i, want := range []int{200, 200, 404} {
		if r := do(t, "GET", url, nil, nil); r.StatusCode != want {
			t.Fatalf("get %d: got %d want %d", i, r.StatusCode, want)
		}
	}
}

func TestFailedLookupRateLimit(t *testing.T) {
	_, srv := newTestRelay(t)
	other := strings.Repeat("cd", 32)
	do(t, "PUT", srv.URL+"/manifest/"+other, []byte("data"), nil)

	for i := 0; i < 3; i++ {
		if r := do(t, "GET", srv.URL+"/manifest/"+testHash, nil, nil); r.StatusCode != 404 {
			t.Fatalf("miss %d: %d", i, r.StatusCode)
		}
	}
	// Even a correct guess is refused once the client is over the limit.
	if r := do(t, "GET", srv.URL+"/manifest/"+other, nil, nil); r.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", r.StatusCode)
	}
}

func TestHealthCountsManifestsOnly(t *testing.T) {
	relay, srv := newTestRelay(t)
	do(t, "PUT", srv.URL+"/manifest/"+testHash, []byte("data"), nil)
	count := 0
	relay.walkManifests(func(string) { count++ })
	if count != 1 {
		t.Fatalf("expected 1 manifest, counted %d", count)
	}
}

func ackHashOf(secret []byte) string {
	sum := blake3.Sum256(secret)
	return hex.EncodeToString(sum[:])
}

func TestAckConsumesManifest(t *testing.T) {
	_, srv := newTestRelay(t)
	url := srv.URL + "/manifest/" + testHash
	secret := bytes.Repeat([]byte{7}, 32)
	do(t, "PUT", url, []byte("data"), map[string]string{"X-Ack-Hash": ackHashOf(secret)})

	// Fetching doesn't consume it, so a failed download can be retried.
	for i := 0; i < 3; i++ {
		if r := do(t, "GET", url, nil, nil); r.StatusCode != 200 {
			t.Fatalf("get %d: %d", i, r.StatusCode)
		}
	}
	if r := do(t, "POST", url+"/ack", []byte(hex.EncodeToString(bytes.Repeat([]byte{8}, 32))), nil); r.StatusCode != 403 {
		t.Fatalf("wrong secret: %d", r.StatusCode)
	}
	if r := do(t, "POST", url+"/ack", []byte("not hex"), nil); r.StatusCode != 400 {
		t.Fatalf("malformed secret: %d", r.StatusCode)
	}
	if r := do(t, "POST", url+"/ack", []byte(hex.EncodeToString(secret)), nil); r.StatusCode != 204 {
		t.Fatalf("ack: %d", r.StatusCode)
	}
	if r := do(t, "GET", url, nil, nil); r.StatusCode != 404 {
		t.Fatalf("get after ack: %d", r.StatusCode)
	}
}

func TestAckCountsRetrievals(t *testing.T) {
	_, srv := newTestRelay(t)
	url := srv.URL + "/manifest/" + testHash
	secret := bytes.Repeat([]byte{7}, 32)
	do(t, "PUT", url, []byte("data"), map[string]string{"X-Ack-Hash": ackHashOf(secret), "X-Max-Retrievals": "2"})

	for i, want := range []int{204, 204, 404} {
		if r := do(t, "POST", url+"/ack", []byte(hex.EncodeToString(secret)), nil); r.StatusCode != want {
			t.Fatalf("ack %d: got %d want %d", i, r.StatusCode, want)
		}
	}
}

func TestPutRateLimit(t *testing.T) {
	relay, srv := newTestRelay(t)
	relay.puts = newRateLimiter("puts", 2, time.Minute)
	codes := []int{}
	for i := 0; i < 3; i++ {
		h := strings.Repeat(string("abc"[i]), 64)
		codes = append(codes, do(t, "PUT", srv.URL+"/manifest/"+h, []byte("x"), nil).StatusCode)
	}
	if codes[0] != 201 || codes[1] != 201 || codes[2] != 429 {
		t.Fatalf("got %v", codes)
	}
}

func TestTotalSizeCap(t *testing.T) {
	relay, srv := newTestRelay(t)
	big := make([]byte, 1000)
	codes := []int{}
	for i := 0; i < 5; i++ {
		h := strings.Repeat(string("abcde"[i]), 64)
		codes = append(codes, do(t, "PUT", srv.URL+"/manifest/"+h, big, nil).StatusCode)
	}
	if codes[3] != 201 || codes[4] != 507 {
		t.Fatalf("got %v", codes)
	}
	// Space is released when a manifest is consumed.
	do(t, "GET", srv.URL+"/manifest/"+strings.Repeat("a", 64), nil, nil)
	if relay.usedBytes != 3000 {
		t.Fatalf("usedBytes = %d", relay.usedBytes)
	}
	if r := do(t, "PUT", srv.URL+"/manifest/"+strings.Repeat("e", 64), big, nil); r.StatusCode != 201 {
		t.Fatalf("put after freeing space: %d", r.StatusCode)
	}
}

func TestRateLimitsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ratelimits.json")

	misses := newRateLimiter("misses", 3, time.Minute)
	puts := newRateLimiter("puts", 3, time.Minute)
	for i := 0; i < 3; i++ {
		misses.Hit("1.2.3.4")
	}
	puts.Allow("5.6.7.8")
	// An expired window must not come back.
	puts.counts["9.9.9.9"] = &rateWindow{start: time.Now().Add(-2 * time.Minute), n: 3}
	if err := newLimiterStore(path, misses, puts).Save(); err != nil {
		t.Fatal(err)
	}

	misses2 := newRateLimiter("misses", 3, time.Minute)
	puts2 := newRateLimiter("puts", 3, time.Minute)
	newLimiterStore(path, misses2, puts2).Load()
	if !misses2.Exceeded("1.2.3.4") {
		t.Fatal("exhausted client got a fresh allowance after restart")
	}
	if misses2.Exceeded("5.6.7.8") || puts2.counts["5.6.7.8"].n != 1 {
		t.Fatal("limiter state mixed up between limiters")
	}
	if _, ok := puts2.counts["9.9.9.9"]; ok {
		t.Fatal("expired window restored")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Fatalf("state file mode %v", info.Mode().Perm())
	}
}
