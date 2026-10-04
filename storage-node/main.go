package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

var hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type StorageNode struct {
	store         ShardStore
	capacityBytes int64
	maxShardBytes int64
	started       time.Time
	ttlSeconds    int64

	mu       sync.Mutex
	reserved int64 // bytes claimed by uploads in progress
}

type HealthResponse struct {
	Status        string `json:"status"`
	CapacityBytes int64  `json:"capacity_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	ShardCount    int    `json:"shard_count"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	NodeID        string `json:"node_id"`
	Backend       string `json:"backend"`
}

func main() {
	port := os.Getenv("STORAGE_PORT")
	if port == "" {
		port = "7001"
	}

	capacityStr := os.Getenv("STORAGE_CAPACITY")
	if capacityStr == "" {
		capacityStr = "1073741824" // 1GB default
	}
	var capacityBytes int64
	fmt.Sscanf(capacityStr, "%d", &capacityBytes)

	ttlStr := os.Getenv("STORAGE_TTL")
	if ttlStr == "" {
		ttlStr = "86400" // 24 hours
	}
	var ttlSeconds int64
	fmt.Sscanf(ttlStr, "%d", &ttlSeconds)

	// A shard is 1/8 of a 64MB encrypted segment (~8MB); allow headroom.
	maxShardStr := os.Getenv("STORAGE_MAX_SHARD_BYTES")
	if maxShardStr == "" {
		maxShardStr = "16777216"
	}
	var maxShardBytes int64
	fmt.Sscanf(maxShardStr, "%d", &maxShardBytes)

	// Select storage backend
	backend := os.Getenv("STORAGE_BACKEND")
	if backend == "" {
		backend = "disk"
	}

	var store ShardStore
	var err error

	switch backend {
	case "s3":
		log.Printf("Using S3 backend (bucket: %s)", os.Getenv("S3_BUCKET"))
		store, err = NewS3Store(context.TODO(), time.Duration(ttlSeconds)*time.Second)
		if err != nil {
			log.Fatalf("Failed to create S3 store: %v", err)
		}
	case "disk":
		fallthrough
	default:
		dataDir := os.Getenv("STORAGE_DIR")
		if dataDir == "" {
			dataDir = "/tmp/helppeer-storage"
		}
		log.Printf("Using disk backend (dir: %s)", dataDir)
		store, err = NewDiskStore(dataDir, ttlSeconds)
		if err != nil {
			log.Fatalf("Failed to create disk store: %v", err)
		}
	}

	node := &StorageNode{
		store:         store,
		capacityBytes: capacityBytes,
		maxShardBytes: maxShardBytes,
		started:       time.Now(),
		ttlSeconds:    ttlSeconds,
	}

	// Start TTL cleanup goroutine
	go node.ttlCleanup()

	addr := ":" + port
	log.Printf("Help Peer Storage Node listening on %s (backend: %s, capacity: %d bytes, TTL: %ds)",
		addr, backend, capacityBytes, ttlSeconds)
	log.Fatal(http.ListenAndServe(addr, node.routes()))
}

func (s *StorageNode) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/shard/", s.shardHandler)
	mux.HandleFunc("/health", s.healthHandler)
	return mux
}

func (s *StorageNode) shardHandler(w http.ResponseWriter, req *http.Request) {
	hash := strings.TrimPrefix(req.URL.Path, "/shard/")
	if !hashRe.MatchString(hash) {
		http.Error(w, "invalid hash", http.StatusBadRequest)
		return
	}

	switch req.Method {
	case http.MethodPut:
		s.putShard(w, req, hash)
	case http.MethodGet:
		s.getShard(w, req, hash)
	case http.MethodDelete:
		s.deleteShard(w, req, hash)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *StorageNode) putShard(w http.ResponseWriter, req *http.Request, hash string) {
	// Parse TTL from header if provided (it can only shorten the node's TTL)
	ttl := time.Duration(s.ttlSeconds) * time.Second
	if ttlHeader := req.Header.Get("X-TTL-Seconds"); ttlHeader != "" {
		var customTTL int64
		if n, _ := fmt.Sscanf(ttlHeader, "%d", &customTTL); n == 1 {
			if customTTL > 0 && customTTL < int64(ttl.Seconds()) {
				ttl = time.Duration(customTTL) * time.Second
			}
		}
	}

	// Check if shard already exists (dedup). The hash is the content's BLAKE3,
	// so an identical upload just extends the TTL.
	if _, err := s.store.Exists(hash); err == nil {
		if err := s.store.Touch(hash, ttl); err != nil {
			log.Printf("Failed to refresh shard %s: %v", hash[:12], err)
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	contentLength := req.ContentLength
	if contentLength <= 0 {
		http.Error(w, "content length required", http.StatusBadRequest)
		return
	}
	if contentLength > s.maxShardBytes {
		http.Error(w, "shard too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Reserve the space up front so concurrent uploads can't overshoot capacity.
	if !s.reserve(contentLength) {
		http.Error(w, "insufficient storage", http.StatusInsufficientStorage)
		return
	}
	defer s.release(contentLength)

	data, err := io.ReadAll(http.MaxBytesReader(w, req.Body, contentLength))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}

	// Shards are content-addressed: refuse data that doesn't match its name,
	// so nobody can squat a hash with different content.
	sum := blake3.Sum256(data)
	if hex.EncodeToString(sum[:]) != hash {
		http.Error(w, "content does not match hash", http.StatusBadRequest)
		return
	}

	written, err := s.store.Put(hash, bytes.NewReader(data), ttl)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	log.Printf("Stored shard %s (%d bytes)", hash[:12], written)
	w.WriteHeader(http.StatusCreated)
}

// reserve claims n bytes of capacity for an in-flight upload.
func (s *StorageNode) reserve(n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store.UsedBytes()+s.reserved+n > s.capacityBytes {
		return false
	}
	s.reserved += n
	return true
}

func (s *StorageNode) release(n int64) {
	s.mu.Lock()
	s.reserved -= n
	s.mu.Unlock()
}

func (s *StorageNode) getShard(w http.ResponseWriter, req *http.Request, hash string) {
	reader, err := s.store.Get(hash)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.Copy(w, reader); err != nil {
		log.Printf("Error sending shard %s: %v", hash[:12], err)
	}
}

func (s *StorageNode) deleteShard(w http.ResponseWriter, req *http.Request, hash string) {
	s.store.Delete(hash)
	w.WriteHeader(http.StatusNoContent)
}

func (s *StorageNode) healthHandler(w http.ResponseWriter, req *http.Request) {
	backend := os.Getenv("STORAGE_BACKEND")
	if backend == "" {
		backend = "disk"
	}

	resp := HealthResponse{
		Status:        "ok",
		CapacityBytes: s.capacityBytes,
		UsedBytes:     s.store.UsedBytes(),
		ShardCount:    s.store.ShardCount(),
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		NodeID:        "ed25519:placeholder",
		Backend:       backend,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *StorageNode) ttlCleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		expired, err := s.store.CleanupExpired()
		if err != nil {
			log.Printf("TTL cleanup error: %v", err)
		}
		if len(expired) > 0 {
			log.Printf("TTL cleanup: removed %d expired shards", len(expired))
		}
	}
}
