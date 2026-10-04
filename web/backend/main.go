package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

//go:embed all:static
var staticFiles embed.FS

// StorageNode is a storage node as reached by this backend (Internal) and as
// written into manifests for other clients to use (Public). They differ when
// the backend talks to nodes over a private network, e.g. in Docker Compose.
type StorageNode struct {
	Internal string
	Public   string
}

type Server struct {
	db           *DB
	auth         *Auth
	relayURL     string
	storageNodes []StorageNode
	smtpConfig   *SMTPConfig
	static       fs.FS

	manifestMisses *rateLimiter // failed manifest lookups per client
	notifyLimit    *rateLimiter // notification emails per sender
}

type SMTPConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
}

func main() {
	port := os.Getenv("WEB_PORT")
	if port == "" {
		port = "8080"
	}

	relayURL := os.Getenv("RELAY_URL")
	if relayURL == "" {
		relayURL = "http://127.0.0.1:7000"
	}

	storageNodesStr := os.Getenv("STORAGE_NODES")
	if storageNodesStr == "" {
		storageNodesStr = "http://127.0.0.1:7001"
	}
	storageNodes, err := parseStorageNodes(storageNodesStr, os.Getenv("STORAGE_NODES_PUBLIC"))
	if err != nil {
		log.Fatal(err)
	}

	smtpConfig := &SMTPConfig{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     os.Getenv("SMTP_PORT"),
		User:     os.Getenv("SMTP_USER"),
		Password: os.Getenv("SMTP_PASS"),
		From:     os.Getenv("SMTP_FROM"),
	}
	if smtpConfig.From == "" {
		smtpConfig.From = smtpConfig.User
	}

	// Public URL used in login emails. It must come from config: building it
	// from the request's Host header lets an attacker request a login link for
	// someone else with Host: evil.com and receive their token.
	baseURL := strings.TrimRight(os.Getenv("WEB_BASE_URL"), "/")
	if baseURL == "" {
		if smtpConfig.Host != "" {
			log.Fatalf("WEB_BASE_URL is required when SMTP is configured (e.g. https://helppeer.example.com)")
		}
		baseURL = "http://localhost:" + port
	}

	trustProxy = os.Getenv("WEB_TRUST_PROXY") == "1"

	dataDir := os.Getenv("WEB_DATA_DIR")
	if dataDir == "" {
		dataDir = "/tmp/helppeer-web"
	}
	os.MkdirAll(dataDir, 0700)

	db, err := NewDB(dataDir)
	if err != nil {
		log.Fatalf("Failed to init DB: %v", err)
	}

	staticSub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to get static sub: %v", err)
	}

	server := NewServer(db, relayURL, storageNodes, smtpConfig, baseURL, staticSub)

	log.Printf("Help Peer Web Backend listening on :%s (relay: %s, nodes: %v)", port, relayURL, storageNodes)
	log.Fatal(http.ListenAndServe(":"+port, server.routes()))
}

func NewServer(db *DB, relayURL string, nodes []StorageNode, smtp *SMTPConfig, baseURL string, static fs.FS) *Server {
	return &Server{
		db:             db,
		auth:           NewAuth(db, smtp, baseURL),
		relayURL:       relayURL,
		storageNodes:   nodes,
		smtpConfig:     smtp,
		static:         static,
		manifestMisses: newRateLimiter(30, time.Minute),
		notifyLimit:    newRateLimiter(50, time.Hour),
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/auth/request", s.auth.authRequestHandler)
	mux.HandleFunc("/api/auth/verify", s.auth.authVerifyHandler)
	mux.HandleFunc("/api/auth/logout", s.auth.authLogoutHandler)
	mux.HandleFunc("/api/auth/me", s.auth.authMeHandler)
	mux.HandleFunc("/api/upload/segment", s.segmentUploadHandler)
	mux.HandleFunc("/api/upload/manifest", s.manifestUploadHandler)
	mux.HandleFunc("/api/download", s.downloadHandler)
	mux.HandleFunc("/api/download/segment", s.segmentDownloadHandler)
	mux.HandleFunc("/api/notify", s.notifyHandler)
	mux.HandleFunc("/api/history", s.historyHandler)
	mux.HandleFunc("/api/health", s.healthHandler)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, req *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})

	// Serve the frontend
	mux.Handle("/", spaHandler(s.static))
	return mux
}

// spaHandler serves static files, falling back to index.html for client-side
// routes such as /verify?token=..., which have no file of their own.
func spaHandler(static fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(static))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		name := strings.TrimPrefix(path.Clean(req.URL.Path), "/")
		if name != "" {
			if _, err := fs.Stat(static, name); err != nil {
				req = req.Clone(req.Context())
				req.URL.Path = "/"
			}
		}
		fileServer.ServeHTTP(w, req)
	})
}

func (s *Server) healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// parseStorageNodes pairs each internal node URL with its public URL.
func parseStorageNodes(internal, public string) ([]StorageNode, error) {
	in := splitCSV(internal)
	pub := in
	if public != "" {
		pub = splitCSV(public)
		if len(pub) != len(in) {
			return nil, fmt.Errorf("STORAGE_NODES_PUBLIC has %d entries but STORAGE_NODES has %d", len(pub), len(in))
		}
	}
	if len(in) == 0 {
		return nil, fmt.Errorf("no storage nodes configured")
	}
	nodes := make([]StorageNode, len(in))
	for i := range in {
		nodes[i] = StorageNode{Internal: strings.TrimRight(in[i], "/"), Public: strings.TrimRight(pub[i], "/")}
	}
	return nodes, nil
}

// internalNodeURL maps a node URL from a manifest to the URL this backend
// should use to reach it. Only configured nodes are allowed: the URL comes
// from the browser, and fetching arbitrary URLs would let anyone use the
// server to reach internal services.
func (s *Server) internalNodeURL(node string) (string, bool) {
	node = strings.TrimRight(node, "/")
	for _, n := range s.storageNodes {
		if n.Public == node || n.Internal == node {
			return n.Internal, true
		}
	}
	return "", false
}

var hexHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// isHexHash reports whether h is a 32-byte hex-encoded hash.
func isHexHash(h string) bool {
	return hexHashRe.MatchString(h)
}

func splitCSV(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) getUserEmail(req *http.Request) (string, bool) {
	cookie, err := req.Cookie("helppeer_session")
	if err != nil {
		return "", false
	}
	return s.db.GetSession(cookie.Value)
}
