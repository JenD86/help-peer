package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testHash = strings.Repeat("ab", 32)

func newTestRelay(t *testing.T) (*Relay, *httptest.Server) {
	t.Helper()
	r := &Relay{
		dataDir:          t.TempDir(),
		started:          time.Now(),
		ttl:              time.Hour,
		maxManifestBytes: 1024,
		defaultRetrieval: 1,
		misses:           newRateLimiter(3, time.Minute),
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

func TestPutGetOneTime(t *testing.T) {
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
