package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type StorageNode struct {
	store         ShardStore
	capacityBytes int64
	started       time.Time
	ttlSeconds   int64
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
		store, err = NewS3Store(context.TODO())
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
		started:       time.Now(),
		ttlSeconds:    ttlSeconds,
	}

	// Start TTL cleanup goroutine
	go node.ttlCleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/shard/", node.shardHandler)
	mux.HandleFunc("/health", node.healthHandler)

	addr := ":" + port
	log.Printf("Help Peer Storage Node listening on %s (backend: %s, capacity: %d bytes, TTL: %ds)",
		addr, backend, capacityBytes, ttlSeconds)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (s *StorageNode) shardHandler(w http.ResponseWriter, req *http.Request) {
	hash := req.URL.Path[len("/shard/"):]
	if hash == "" {
		http.Error(w, "missing hash", http.StatusBadRequest)
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
	// Parse TTL from header if provided
	ttl := time.Duration(s.ttlSeconds) * time.Second
	if ttlHeader := req.Header.Get("X-TTL-Seconds"); ttlHeader != "" {
		var customTTL int64
		if n, _ := fmt.Sscanf(ttlHeader, "%d", &customTTL); n == 1 {
			if customTTL > 0 && customTTL < int64(ttl.Seconds()) {
				ttl = time.Duration(customTTL) * time.Second
			}
		}
	}

	// Check if shard already exists (dedup)
	if _, err := s.store.Exists(hash); err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Check capacity
	contentLength := req.ContentLength
	if contentLength <= 0 {
		http.Error(w, "content length required", http.StatusBadRequest)
		return
	}

	if s.store.UsedBytes()+contentLength > s.capacityBytes {
		http.Error(w, "insufficient storage", http.StatusInsufficientStorage)
		return
	}

	written, err := s.store.Put(hash, req.Body, ttl)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	log.Printf("Stored shard %s (%d bytes)", hash[:12], written)
	w.WriteHeader(http.StatusCreated)
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
