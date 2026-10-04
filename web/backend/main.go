package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"
)

//go:embed all:static
var staticFiles embed.FS

type Server struct {
	db          *DB
	auth        *Auth
	relayURL    string
	storageNodes []string
	smtpConfig  *SMTPConfig
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

	dataDir := os.Getenv("WEB_DATA_DIR")
	if dataDir == "" {
		dataDir = "/tmp/helppeer-web"
	}
	os.MkdirAll(dataDir, 0755)

	db, err := NewDB(dataDir)
	if err != nil {
		log.Fatalf("Failed to init DB: %v", err)
	}

	// Parse storage nodes
	var storageNodes []string
	for _, n := range splitCSV(storageNodesStr) {
		storageNodes = append(storageNodes, n)
	}

	server := &Server{
		db:          db,
		relayURL:    relayURL,
		storageNodes: storageNodes,
		smtpConfig:  smtpConfig,
	}
	server.auth = NewAuth(db, smtpConfig)

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/auth/request", server.authRequestHandler)
	mux.HandleFunc("/api/auth/verify", server.authVerifyHandler)
	mux.HandleFunc("/api/auth/logout", server.authLogoutHandler)
	mux.HandleFunc("/api/auth/me", server.authMeHandler)
	mux.HandleFunc("/api/upload", server.uploadHandler)
	mux.HandleFunc("/api/download", server.downloadHandler)
	mux.HandleFunc("/api/download/segment", server.segmentDownloadHandler)
	mux.HandleFunc("/api/notify", server.notifyHandler)
	mux.HandleFunc("/api/history", server.historyHandler)
	mux.HandleFunc("/api/health", server.healthHandler)

	// Serve static frontend files
	staticSub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to get static sub: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticSub)))

	log.Printf("Help Peer Web Backend listening on :%s (relay: %s, nodes: %v)", port, relayURL, storageNodes)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func (s *Server) healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func splitCSV(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			if current != "" {
				result = append(result, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
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
	return s.auth.GetUserBySession(cookie.Value)
}

// Auth handler wrappers
func (s *Server) authRequestHandler(w http.ResponseWriter, req *http.Request) {
	s.auth.authRequestHandler(w, req)
}
func (s *Server) authVerifyHandler(w http.ResponseWriter, req *http.Request) {
	s.auth.authVerifyHandler(w, req)
}
func (s *Server) authLogoutHandler(w http.ResponseWriter, req *http.Request) {
	s.auth.authLogoutHandler(w, req)
}
func (s *Server) authMeHandler(w http.ResponseWriter, req *http.Request) {
	s.auth.authMeHandler(w, req)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
