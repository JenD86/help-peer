package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

	log.Printf("Stored manifest %s (%d bytes)", hash[:min(12, len(hash))], written)
	w.WriteHeader(http.StatusCreated)
}

func (r *Relay) getManifest(w http.ResponseWriter, req *http.Request, hash string) {
	manifestPath := r.manifestPath(hash)

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// One-time retrieval: delete after read
	os.Remove(manifestPath)

	log.Printf("Retrieved and deleted manifest %s (%d bytes)", hash[:min(12, len(hash))], len(data))

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
