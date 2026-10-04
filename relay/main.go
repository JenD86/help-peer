package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hard cap on X-Max-Retrievals so a single manifest can't be pinned open forever.
const maxRetrievalsCap = 1000

var hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Relay struct {
	mu               sync.Mutex
	dataDir          string
	started          time.Time
	ttl              time.Duration
	maxManifestBytes int64
	defaultRetrieval int
	misses           *rateLimiter
}

// manifestMeta is stored next to each manifest as {hash}.meta.
type manifestMeta struct {
	Remaining int   `json:"remaining"`
	ExpiresAt int64 `json:"expires_at"` // unix seconds
}

type HealthResponse struct {
	Status          string `json:"status"`
	ManifestsStored int    `json:"manifests_stored"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
}

func main() {
	port := envOr("RELAY_PORT", "7000")
	dataDir := envOr("RELAY_DIR", "/tmp/helppeer-relay")

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create relay data directory: %v", err)
	}

	relay := &Relay{
		dataDir:          dataDir,
		started:          time.Now(),
		ttl:              time.Duration(envInt("RELAY_TTL", 86400)) * time.Second,
		maxManifestBytes: int64(envInt("RELAY_MAX_MANIFEST_BYTES", 32<<20)),
		defaultRetrieval: envInt("RELAY_MAX_RETRIEVALS", 1),
		misses:           newRateLimiter(envInt("RELAY_MISS_LIMIT", 30), time.Minute),
	}

	go relay.cleanupLoop()

	addr := ":" + port
	log.Printf("Help Peer Relay Server listening on %s (ttl: %s)", addr, relay.ttl)
	log.Fatal(http.ListenAndServe(addr, relay.routes()))
}

func (r *Relay) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest/", r.manifestHandler)
	mux.HandleFunc("/health", r.healthHandler)
	return mux
}

func (r *Relay) manifestHandler(w http.ResponseWriter, req *http.Request) {
	hash := strings.TrimPrefix(req.URL.Path, "/manifest/")
	if !hashRe.MatchString(hash) {
		http.Error(w, "invalid hash", http.StatusBadRequest)
		return
	}

	switch req.Method {
	case http.MethodPut:
		r.putManifest(w, req, hash)
	case http.MethodGet:
		r.getManifest(w, req, hash)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *Relay) manifestPath(hash string) string {
	return filepath.Join(r.dataDir, hash[:2], hash[2:4], hash)
}

func (r *Relay) putManifest(w http.ResponseWriter, req *http.Request, hash string) {
	maxRetrievals := r.defaultRetrieval
	if hdr := req.Header.Get("X-Max-Retrievals"); hdr != "" {
		n, err := strconv.Atoi(hdr)
		if err != nil || n <= 0 || n > maxRetrievalsCap {
			http.Error(w, fmt.Sprintf("X-Max-Retrievals must be 1-%d", maxRetrievalsCap), http.StatusBadRequest)
			return
		}
		maxRetrievals = n
	}

	// Read the body before taking the lock so a slow client can't stall everyone.
	data, err := io.ReadAll(http.MaxBytesReader(w, req.Body, r.maxManifestBytes))
	if err != nil {
		// http.MaxBytesError needs Go 1.19; match the message to support 1.18.
		if strings.Contains(err.Error(), "request body too large") {
			http.Error(w, "manifest too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	if len(data) == 0 {
		http.Error(w, "empty manifest", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	manifestPath := r.manifestPath(hash)
	if _, err := os.Stat(manifestPath); err == nil {
		if !r.expireIfDue(manifestPath) {
			http.Error(w, "manifest already exists", http.StatusConflict)
			return
		}
	}

	if err := os.MkdirAll(filepath.Dir(manifestPath), 0755); err != nil {
		log.Printf("Failed to create manifest dir: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Write the metadata first: once the manifest itself is visible, readers
	// must already see the right retrieval count and expiry.
	meta := manifestMeta{Remaining: maxRetrievals, ExpiresAt: time.Now().Add(r.ttl).Unix()}
	if err := writeMeta(manifestPath, meta); err != nil {
		log.Printf("Failed to write manifest metadata: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := writeFileAtomic(manifestPath, data); err != nil {
		os.Remove(manifestPath + ".meta")
		log.Printf("Failed to write manifest: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("Stored manifest %s (%d bytes, max_retrievals=%d)", hash[:12], len(data), maxRetrievals)
	w.WriteHeader(http.StatusCreated)
}

func (r *Relay) getManifest(w http.ResponseWriter, req *http.Request, hash string) {
	// Codes are the only secret, so throttle clients that keep guessing.
	ip := clientIP(req)
	if r.misses.Exceeded(ip) {
		http.Error(w, "too many failed lookups", http.StatusTooManyRequests)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	manifestPath := r.manifestPath(hash)
	data, err := os.ReadFile(manifestPath)
	if err != nil || r.expireIfDue(manifestPath) {
		r.misses.Hit(ip)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	meta := r.readMeta(manifestPath)
	meta.Remaining--
	if meta.Remaining <= 0 {
		r.deleteManifest(manifestPath)
		log.Printf("Retrieved and deleted manifest %s (%d bytes, final retrieval)", hash[:12], len(data))
	} else {
		if err := writeMeta(manifestPath, meta); err != nil {
			log.Printf("Failed to update manifest metadata: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("Retrieved manifest %s (%d bytes, %d retrievals remaining)", hash[:12], len(data), meta.Remaining)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (r *Relay) healthHandler(w http.ResponseWriter, req *http.Request) {
	count := 0
	r.walkManifests(func(string) { count++ })

	resp := HealthResponse{
		Status:          "ok",
		ManifestsStored: count,
		UptimeSeconds:   int64(time.Since(r.started).Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// readMeta loads a manifest's metadata. Manifests written by older relays
// have a {hash}.count file instead; treat their file mtime as the store time.
func (r *Relay) readMeta(manifestPath string) manifestMeta {
	var meta manifestMeta
	if data, err := os.ReadFile(manifestPath + ".meta"); err == nil && json.Unmarshal(data, &meta) == nil {
		return meta
	}

	meta.Remaining = 1
	if data, err := os.ReadFile(manifestPath + ".count"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			meta.Remaining = n
		}
	}
	if info, err := os.Stat(manifestPath); err == nil {
		meta.ExpiresAt = info.ModTime().Add(r.ttl).Unix()
	}
	return meta
}

// expireIfDue deletes the manifest if its TTL has passed. Requires r.mu.
func (r *Relay) expireIfDue(manifestPath string) bool {
	if time.Now().Unix() < r.readMeta(manifestPath).ExpiresAt {
		return false
	}
	r.deleteManifest(manifestPath)
	return true
}

func (r *Relay) deleteManifest(manifestPath string) {
	os.Remove(manifestPath)
	os.Remove(manifestPath + ".meta")
	os.Remove(manifestPath + ".count")
}

// walkManifests calls fn with the path of every stored manifest.
func (r *Relay) walkManifests(fn func(path string)) {
	filepath.Walk(r.dataDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && hashRe.MatchString(info.Name()) {
			fn(path)
		}
		return nil
	})
}

func (r *Relay) cleanupLoop() {
	for range time.Tick(time.Minute) {
		r.cleanupExpired()
	}
}

func (r *Relay) cleanupExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()

	expired := 0
	r.walkManifests(func(path string) {
		if r.expireIfDue(path) {
			expired++
		}
	})
	if expired > 0 {
		log.Printf("TTL cleanup: removed %d expired manifests", expired)
	}
	r.misses.Prune()
}

func writeMeta(manifestPath string, meta manifestMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return writeFileAtomic(manifestPath+".meta", data)
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// rateLimiter allows `limit` hits per key per fixed window.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	counts map[string]*rateWindow
}

type rateWindow struct {
	start time.Time
	n     int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, counts: make(map[string]*rateWindow)}
}

func (l *rateLimiter) current(key string) *rateWindow {
	w, ok := l.counts[key]
	if !ok || time.Since(w.start) >= l.window {
		w = &rateWindow{start: time.Now()}
		l.counts[key] = w
	}
	return w
}

// Exceeded reports whether key has used up its allowance for this window.
func (l *rateLimiter) Exceeded(key string) bool {
	if l.limit <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.current(key).n >= l.limit
}

func (l *rateLimiter) Hit(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.current(key).n++
}

// Prune drops windows that have ended so the map doesn't grow without bound.
func (l *rateLimiter) Prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.counts {
		if time.Since(w.start) >= l.window {
			delete(l.counts, k)
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("%s must be an integer, got %q", key, v)
	}
	return n
}
