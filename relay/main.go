package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Relay struct {
	mu      sync.Mutex
	dataDir string
	started time.Time
}

type HealthResponse struct {
	Status         string `json:"status"`
	ManifestsStored int   `json:"manifests_stored"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
}

func main() {
	port := os.Getenv("RELAY_PORT")
	if port == "" {
		port = "7000"
	}

	dataDir := os.Getenv("RELAY_DIR")
	if dataDir == "" {
		dataDir = "/tmp/helppeer-relay"
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create relay data directory: %v", err)
	}

	relay := &Relay{dataDir: dataDir, started: time.Now()}

	mux := http.NewServeMux()
	mux.HandleFunc("/manifest/", relay.manifestHandler)
	mux.HandleFunc("/health", relay.healthHandler)

	addr := ":" + port
	log.Printf("Help Peer Relay Server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (r *Relay) manifestHandler(w http.ResponseWriter, req *http.Request) {
	hash := req.URL.Path[len("/manifest/"):]
	if hash == "" {
		http.Error(w, "missing hash", http.StatusBadRequest)
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
	if len(hash) < 4 {
		return filepath.Join(r.dataDir, hash)
	}
	subdir := filepath.Join(r.dataDir, hash[:2], hash[2:4])
	os.MkdirAll(subdir, 0755)
	return filepath.Join(subdir, hash)
}

func (r *Relay) putManifest(w http.ResponseWriter, req *http.Request, hash string) {
	manifestPath := r.manifestPath(hash)

	if _, err := os.Stat(manifestPath); err == nil {
		http.Error(w, "manifest already exists", http.StatusConflict)
		return
	}

	// Parse max retrievals (default 1 for backward compatibility)
	maxRetrievals := 1
	if hdr := req.Header.Get("X-Max-Retrievals"); hdr != "" {
		if n, err := strconv.Atoi(hdr); err == nil && n > 0 {
			maxRetrievals = n
		}
	}

	tmpPath := manifestPath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		log.Printf("Failed to create temp file: %v", err)
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

	if written == 0 {
		os.Remove(tmpPath)
		http.Error(w, "empty manifest", http.StatusBadRequest)
		return
	}

	if err := os.Rename(tmpPath, manifestPath); err != nil {
		os.Remove(tmpPath)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Write retrieval counter file
	counterPath := manifestPath + ".count"
	os.WriteFile(counterPath, []byte(fmt.Sprintf("%d", maxRetrievals)), 0644)

	log.Printf("Stored manifest %s (%d bytes, max_retrievals=%d)", hash[:min(12, len(hash))], written, maxRetrievals)
	w.WriteHeader(http.StatusCreated)
}

func (r *Relay) getManifest(w http.ResponseWriter, req *http.Request, hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	manifestPath := r.manifestPath(hash)

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Check and decrement retrieval counter
	counterPath := manifestPath + ".count"
	remaining := 1
	if counterData, err := os.ReadFile(counterPath); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(counterData))); err == nil {
			remaining = n
		}
	}

	remaining--
	if remaining <= 0 {
		// Last retrieval: delete manifest and counter
		os.Remove(manifestPath)
		os.Remove(counterPath)
		log.Printf("Retrieved and deleted manifest %s (%d bytes, final retrieval)", hash[:min(12, len(hash))], len(data))
	} else {
		// Write updated counter
		os.WriteFile(counterPath, []byte(fmt.Sprintf("%d", remaining)), 0644)
		log.Printf("Retrieved manifest %s (%d bytes, %d retrievals remaining)", hash[:min(12, len(hash))], len(data), remaining)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (r *Relay) healthHandler(w http.ResponseWriter, req *http.Request) {
	count := 0
	filepath.Walk(r.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			count++
		}
		return nil
	})

	resp := HealthResponse{
		Status:          "ok",
		ManifestsStored: count,
		UptimeSeconds:   int64(time.Since(r.started).Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
