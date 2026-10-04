package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"lukechampine.com/blake3"
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
	maxTotalBytes    int64
	usedBytes        int64 // total size of stored manifests; guarded by mu
	defaultRetrieval int
	misses           *rateLimiter // failed lookups / acks per client
	puts             *rateLimiter // uploads per client
}

// manifestMeta is stored next to each manifest as {hash}.meta.
type manifestMeta struct {
	Remaining int   `json:"remaining"`
	ExpiresAt int64 `json:"expires_at"` // unix seconds
	// AckHash is BLAKE3 of the secret a receiver presents to confirm a
	// completed download. Fetching doesn't consume the manifest; confirming
	// does, so a receiver can retry a failed download. Manifests uploaded
	// without one (older clients) are consumed on fetch instead.
	AckHash string `json:"ack_hash,omitempty"`
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
		maxTotalBytes:    int64(envInt("RELAY_MAX_TOTAL_BYTES", 1<<30)),
		defaultRetrieval: envInt("RELAY_MAX_RETRIEVALS", 1),
		misses:           newRateLimiter("misses", envInt("RELAY_MISS_LIMIT", 30), time.Minute),
		puts:             newRateLimiter("puts", envInt("RELAY_PUT_LIMIT", 120), time.Minute),
	}
	relay.usedBytes = relay.measureUsage()

	go relay.cleanupLoop()

	// Keep rate limits across restarts, saving on shutdown as well.
	limits := newLimiterStore(filepath.Join(dataDir, "ratelimits.json"), relay.misses, relay.puts)
	limits.Load()
	go limits.Run()
	saveOnExit(limits)

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
	rest := strings.TrimPrefix(req.URL.Path, "/manifest/")
	hash, action := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hash, action = rest[:i], rest[i+1:]
	}
	if !hashRe.MatchString(hash) {
		http.Error(w, "invalid hash", http.StatusBadRequest)
		return
	}

	switch {
	case action == "" && req.Method == http.MethodPut:
		r.putManifest(w, req, hash)
	case action == "" && req.Method == http.MethodGet:
		r.getManifest(w, req, hash)
	case action == "" && req.Method == http.MethodDelete:
		r.cancelManifest(w, req, hash)
	case action == "ack" && req.Method == http.MethodPost:
		r.ackManifest(w, req, hash)
	case action == "" || action == "ack":
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	default:
		http.NotFound(w, req)
	}
}

func (r *Relay) manifestPath(hash string) string {
	return filepath.Join(r.dataDir, hash[:2], hash[2:4], hash)
}

func (r *Relay) putManifest(w http.ResponseWriter, req *http.Request, hash string) {
	if !r.puts.Allow(clientIP(req)) {
		http.Error(w, "too many uploads", http.StatusTooManyRequests)
		return
	}

	ackHash := req.Header.Get("X-Ack-Hash")
	if ackHash != "" && !hashRe.MatchString(ackHash) {
		http.Error(w, "invalid X-Ack-Hash", http.StatusBadRequest)
		return
	}

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

	if r.usedBytes+int64(len(data)) > r.maxTotalBytes {
		http.Error(w, "relay storage full", http.StatusInsufficientStorage)
		return
	}

	if err := os.MkdirAll(filepath.Dir(manifestPath), 0755); err != nil {
		log.Printf("Failed to create manifest dir: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Write the metadata first: once the manifest itself is visible, readers
	// must already see the right retrieval count and expiry.
	meta := manifestMeta{Remaining: maxRetrievals, ExpiresAt: time.Now().Add(r.ttl).Unix(), AckHash: ackHash}
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

	r.usedBytes += int64(len(data))
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

	// Manifests from older clients have no ack secret and are consumed here.
	if meta := r.readMeta(manifestPath); meta.AckHash == "" {
		if err := r.consume(manifestPath, meta); err != nil {
			log.Printf("Failed to update manifest metadata: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	log.Printf("Retrieved manifest %s (%d bytes)", hash[:12], len(data))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// ackManifest records a completed download. The body is the hex ack secret
// from inside the encrypted manifest, which proves the caller decrypted it.
func (r *Relay) ackManifest(w http.ResponseWriter, req *http.Request, hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	manifestPath, meta, ok := r.authorize(w, req, hash)
	if !ok {
		return
	}
	if err := r.consume(manifestPath, meta); err != nil {
		log.Printf("Failed to update manifest metadata: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// cancelManifest withdraws a transfer immediately, whatever retrievals are
// left. It takes the same proof as ackManifest: anyone who can decrypt the
// manifest (the sender or a recipient) can cancel it.
func (r *Relay) cancelManifest(w http.ResponseWriter, req *http.Request, hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	manifestPath, _, ok := r.authorize(w, req, hash)
	if !ok {
		return
	}
	r.deleteManifest(manifestPath)
	log.Printf("Manifest %s cancelled", hash[:12])
	w.WriteHeader(http.StatusNoContent)
}

// authorize checks the hex ack secret in the request body against the
// manifest's ack hash, writing an error response if it doesn't match.
// Requires r.mu.
func (r *Relay) authorize(w http.ResponseWriter, req *http.Request, hash string) (string, manifestMeta, bool) {
	ip := clientIP(req)
	if r.misses.Exceeded(ip) {
		http.Error(w, "too many failed requests", http.StatusTooManyRequests)
		return "", manifestMeta{}, false
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 256))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return "", manifestMeta{}, false
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(secret) != 32 {
		http.Error(w, "invalid ack secret", http.StatusBadRequest)
		return "", manifestMeta{}, false
	}

	manifestPath := r.manifestPath(hash)
	if _, err := os.Stat(manifestPath); err != nil || r.expireIfDue(manifestPath) {
		r.misses.Hit(ip)
		http.Error(w, "not found", http.StatusNotFound)
		return "", manifestMeta{}, false
	}

	meta := r.readMeta(manifestPath)
	sum := blake3.Sum256(secret)
	if meta.AckHash == "" || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(meta.AckHash)) != 1 {
		r.misses.Hit(ip)
		http.Error(w, "wrong ack secret", http.StatusForbidden)
		return "", manifestMeta{}, false
	}
	return manifestPath, meta, true
}

// consume uses up one retrieval, deleting the manifest after the last one.
// Requires r.mu.
func (r *Relay) consume(manifestPath string, meta manifestMeta) error {
	meta.Remaining--
	if meta.Remaining <= 0 {
		r.deleteManifest(manifestPath)
		log.Printf("Manifest %s fully retrieved and deleted", filepath.Base(manifestPath)[:12])
		return nil
	}
	log.Printf("Manifest %s: %d retrievals remaining", filepath.Base(manifestPath)[:12], meta.Remaining)
	return writeMeta(manifestPath, meta)
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
	if info, err := os.Stat(manifestPath); err == nil {
		r.usedBytes -= info.Size()
	}
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

// measureUsage totals the size of stored manifests (at startup).
func (r *Relay) measureUsage() int64 {
	var total int64
	r.walkManifests(func(path string) {
		if info, err := os.Stat(path); err == nil {
			total += info.Size()
		}
	})
	return total
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
	r.puts.Prune()
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

// saveOnExit saves rate limits when the process is asked to stop
// (Ctrl-C, or SIGTERM from `docker stop`).
func saveOnExit(limits *limiterStore) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		if err := limits.Save(); err != nil {
			log.Printf("Failed to save rate limits: %v", err)
		}
		os.Exit(0)
	}()
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
