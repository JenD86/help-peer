package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	nodeDownFor     = time.Minute
	heartbeatStale  = 5 * time.Minute
	heartbeatPeriod = 2 * time.Minute
)

// dynNode is a storage node that registered itself dynamically.
type dynNode struct {
	Public   string    `json:"public_url"`
	LastSeen time.Time `json:"last_seen"`
	Capacity int64     `json:"capacity_bytes"`
}

// nodeRegistry manages static (env-configured) and dynamic (self-registered)
// storage nodes. Static nodes are always present; dynamic nodes must
// heartbeat periodically or they are pruned.
type nodeRegistry struct {
	mu      sync.RWMutex
	static  []StorageNode
	dynamic map[string]*dynNode // keyed by public URL
	health  map[string]time.Time // public URL -> down until
	dataDir string
}

func newNodeRegistry(static []StorageNode, dataDir string) *nodeRegistry {
	r := &nodeRegistry{
		static:  static,
		dynamic: make(map[string]*dynNode),
		health:  make(map[string]time.Time),
		dataDir: dataDir,
	}
	r.load()
	return r
}

// AllNodes returns the combined list of static and active dynamic nodes.
func (r *nodeRegistry) AllNodes() []StorageNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	nodes := make([]StorageNode, 0, len(r.static)+len(r.dynamic))
	nodes = append(nodes, r.static...)
	for _, d := range r.dynamic {
		nodes = append(nodes, StorageNode{Internal: d.Public, Public: d.Public})
	}
	return nodes
}

// Register adds or refreshes a dynamically registered node.
func (r *nodeRegistry) Register(publicURL string, capacity int64) {
	publicURL = strings.TrimRight(publicURL, "/")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dynamic[publicURL] = &dynNode{
		Public:   publicURL,
		LastSeen: time.Now(),
		Capacity: capacity,
	}
	delete(r.health, publicURL)
	r.saveLocked()
}

// Deregister removes a dynamically registered node.
func (r *nodeRegistry) Deregister(publicURL string) {
	publicURL = strings.TrimRight(publicURL, "/")
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.dynamic, publicURL)
	delete(r.health, publicURL)
	r.saveLocked()
}

// PruneStale removes dynamic nodes that haven't heartbeated within maxAge.
func (r *nodeRegistry) PruneStale() {
	cutoff := time.Now().Add(-heartbeatStale)
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for url, d := range r.dynamic {
		if d.LastSeen.Before(cutoff) {
			delete(r.dynamic, url)
			delete(r.health, url)
			changed = true
		}
	}
	if changed {
		r.saveLocked()
	}
}

// IsDown reports whether a node URL is currently marked as down.
func (r *nodeRegistry) IsDown(url string) bool {
	url = strings.TrimRight(url, "/")
	r.mu.RLock()
	defer r.mu.RUnlock()
	return time.Now().Before(r.health[url])
}

// MarkDown marks a node URL as down for a short period.
func (r *nodeRegistry) MarkDown(url string) {
	url = strings.TrimRight(url, "/")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health[url] = time.Now().Add(nodeDownFor)
}

// InternalURL maps a node URL from a manifest to the URL this backend
// should use to reach it. Only known nodes are allowed: the URL comes
// from the browser, and fetching arbitrary URLs would let anyone use the
// server to reach internal services.
func (r *nodeRegistry) InternalURL(node string) (string, bool) {
	node = strings.TrimRight(node, "/")
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, n := range r.static {
		if n.Public == node || n.Internal == node {
			return n.Internal, true
		}
	}
	if _, ok := r.dynamic[node]; ok {
		return node, true
	}
	return "", false
}

func (r *nodeRegistry) load() {
	data, err := os.ReadFile(filepath.Join(r.dataDir, "nodes.json"))
	if err != nil {
		return
	}
	var nodes []*dynNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		log.Printf("Ignoring unreadable nodes.json: %v", err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range nodes {
		r.dynamic[n.Public] = n
	}
}

func (r *nodeRegistry) saveLocked() {
	nodes := make([]*dynNode, 0, len(r.dynamic))
	for _, d := range r.dynamic {
		nodes = append(nodes, d)
	}
	data, err := json.Marshal(nodes)
	if err != nil {
		log.Printf("Failed to encode nodes.json: %v", err)
		return
	}
	if err := writeFileAtomic(filepath.Join(r.dataDir, "nodes.json"), data); err != nil {
		log.Printf("Failed to save nodes.json: %v", err)
	}
}

// StartPruner runs a background goroutine that removes stale dynamic nodes.
func (r *nodeRegistry) StartPruner() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			r.PruneStale()
		}
	}()
}

// --- HTTP handlers ----------------------------------------------------------

// nodeRegisterHandler handles self-registration from storage nodes.
// The node POSTs its public URL; the backend health-checks it before adding.
func (s *Server) nodeRegisterHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		URL      string `json:"url"`
		Capacity int64  `json:"capacity_bytes"`
	}
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.URL == "" {
		writeError(w, http.StatusBadRequest, "invalid request: url is required")
		return
	}
	url := strings.TrimSpace(body.URL)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		writeError(w, http.StatusBadRequest, "url must start with http:// or https://")
		return
	}

	// Health check: the node must be reachable and respond to /health.
	healthURL := strings.TrimRight(url, "/") + "/health"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("could not reach node: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("node health check returned %d", resp.StatusCode))
		return
	}

	var hr struct {
		CapacityBytes int64 `json:"capacity_bytes"`
	}
	json.NewDecoder(resp.Body).Decode(&hr)
	capacity := body.Capacity
	if capacity == 0 {
		capacity = hr.CapacityBytes
	}

	s.nodes.Register(url, capacity)
	log.Printf("Storage node registered: %s (capacity: %d bytes)", url, capacity)
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

// nodeDeregisterHandler removes a node from the active list.
func (s *Server) nodeDeregisterHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		URL string `json:"url"`
	}
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.URL == "" {
		writeError(w, http.StatusBadRequest, "invalid request: url is required")
		return
	}
	s.nodes.Deregister(strings.TrimSpace(body.URL))
	log.Printf("Storage node deregistered: %s", body.URL)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deregistered"})
}
