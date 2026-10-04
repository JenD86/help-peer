package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type StorageNode struct {
	mu           sync.Mutex
	dataDir      string
	capacityBytes int64
	usedBytes    int64
	started      time.Time
	ttlSeconds   int64
	shardIndex   map[string]time.Time // hash -> expiry time
}

type HealthResponse struct {
	Status        string `json:"status"`
	CapacityBytes int64  `json:"capacity_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	ShardCount    int    `json:"shard_count"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	NodeID        string `json:"node_id"`
}

func main() {
	port := os.Getenv("STORAGE_PORT")
	if port == "" {
		port = "7001"
	}

	dataDir := os.Getenv("STORAGE_DIR")
	if dataDir == "" {
		dataDir = "/tmp/helppeer-storage"
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

	shardDir := filepath.Join(dataDir, "shards")
	if err := os.MkdirAll(shardDir, 0755); err != nil {
		log.Fatalf("Failed to create shard directory: %v", err)
	}

	node := &StorageNode{
		dataDir:       dataDir,
		capacityBytes: capacityBytes,
		started:       time.Now(),
		ttlSeconds:    ttlSeconds,
		shardIndex:    make(map[string]time.Time),
	}

	// Calculate current usage
	node.calculateUsedBytes()

	// Start TTL cleanup goroutine
	go node.ttlCleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/shard/", node.shardHandler)
	mux.HandleFunc("/health", node.healthHandler)

	addr := ":" + port
	log.Printf("Help Peer Storage Node listening on %s (capacity: %d bytes, TTL: %ds)",
		addr, capacityBytes, ttlSeconds)
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
	ttl := s.ttlSeconds
	if ttlHeader := req.Header.Get("X-TTL-Seconds"); ttlHeader != "" {
		var customTTL int64
		if n, _ := fmt.Sscanf(ttlHeader, "%d", &customTTL); n == 1 {
			if customTTL > 0 && customTTL < ttl {
				ttl = customTTL
			}
		}
	}

	shardPath := s.shardPath(hash)

	// Check if shard already exists (dedup)
	if info, err := os.Stat(shardPath); err == nil {
		s.mu.Lock()
		s.shardIndex[hash] = time.Now().Add(time.Duration(ttl) * time.Second)
		s.mu.Unlock()
		log.Printf("Shard %s already exists (%d bytes), refreshing TTL", hash[:12], info.Size())
		w.WriteHeader(http.StatusOK)
		return
	}

	// Check capacity
	contentLength := req.ContentLength
	if contentLength <= 0 {
		http.Error(w, "content length required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.usedBytes+contentLength > s.capacityBytes {
		s.mu.Unlock()
		http.Error(w, "insufficient storage", http.StatusInsufficientStorage)
		return
	}
	s.mu.Unlock()

	// Atomic write: write to temp file then rename
	tmpPath := shardPath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(shardPath), 0755); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	written, err := io.Copy(tmpFile, req.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}

	if err := os.Rename(tmpPath, shardPath); err != nil {
		os.Remove(tmpPath)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.usedBytes += written
	s.shardIndex[hash] = time.Now().Add(time.Duration(ttl) * time.Second)
	s.mu.Unlock()

	log.Printf("Stored shard %s (%d bytes)", hash[:12], written)
	w.WriteHeader(http.StatusCreated)
}

func (s *StorageNode) getShard(w http.ResponseWriter, req *http.Request, hash string) {
	shardPath := s.shardPath(hash)

	// Check TTL
	s.mu.Lock()
	expiry, exists := s.shardIndex[hash]
	s.mu.Unlock()

	if !exists || time.Now().After(expiry) {
		if exists {
			s.deleteShardSilent(hash)
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(shardPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *StorageNode) deleteShard(w http.ResponseWriter, req *http.Request, hash string) {
	s.deleteShardSilent(hash)
	w.WriteHeader(http.StatusNoContent)
}

func (s *StorageNode) deleteShardSilent(hash string) {
	shardPath := s.shardPath(hash)
	if info, err := os.Stat(shardPath); err == nil {
		os.Remove(shardPath)
		s.mu.Lock()
		s.usedBytes -= info.Size()
		if s.usedBytes < 0 {
			s.usedBytes = 0
		}
		delete(s.shardIndex, hash)
		s.mu.Unlock()
		log.Printf("Deleted shard %s", hash[:12])
	}
}

func (s *StorageNode) healthHandler(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	shardCount := len(s.shardIndex)
	used := s.usedBytes
	s.mu.Unlock()

	resp := HealthResponse{
		Status:        "ok",
		CapacityBytes: s.capacityBytes,
		UsedBytes:     used,
		ShardCount:    shardCount,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		NodeID:        "ed25519:placeholder",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *StorageNode) shardPath(hash string) string {
	// Two-level directory prefix: ab/cd/abcdef...
	if len(hash) < 4 {
		return filepath.Join(s.dataDir, "shards", hash)
	}
	subdir := filepath.Join(s.dataDir, "shards", hash[:2], hash[2:4])
	return filepath.Join(subdir, hash)
}

func (s *StorageNode) calculateUsedBytes() {
	shardDir := filepath.Join(s.dataDir, "shards")
	var total int64
	filepath.Walk(shardDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
			hash := filepath.Base(path)
			s.shardIndex[hash] = time.Now().Add(time.Duration(s.ttlSeconds) * time.Second)
		}
		return nil
	})
	s.usedBytes = total
}

func (s *StorageNode) ttlCleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		var expired []string
		for hash, expiry := range s.shardIndex {
			if now.After(expiry) {
				expired = append(expired, hash)
			}
		}
		s.mu.Unlock()

		for _, hash := range expired {
			s.deleteShardSilent(hash)
		}

		if len(expired) > 0 {
			log.Printf("TTL cleanup: removed %d expired shards", len(expired))
		}
	}
}
