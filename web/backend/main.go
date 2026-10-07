package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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
	db       *DB
	auth     *Auth
	relayURL string
	// relayPublicURL is the relay as CLI/SDK users reach it (for /api/config).
	relayPublicURL string
	nodes          *nodeRegistry
	smtpConfig     *SMTPConfig
	static         fs.FS
	baseURL        string // public site URL, for robots.txt and sitemap.xml

	manifestMisses  *rateLimiter // failed manifest lookups per client
	manifestUploads *rateLimiter // manifest uploads per client
	notifyLimit     *rateLimiter // notification emails per sender
	directoryLimit  *rateLimiter // username searches/lookups per user

	nodeRegistrations *rateLimiter // new storage node registrations per client
	segmentBytes      *rateLimiter // bytes of uploaded segments per client per 24 hours
	segmentSlots      *slotLimiter // segments being uploaded at once, per client and overall
	transferStarts    *rateLimiter // transfers a client may start per hour
	tickets           *ticketBook  // permissions to upload, one per transfer
	transferMax       int64        // largest single transfer, in bytes
	adminToken        string       // NODE_ADMIN_TOKEN for /api/admin/nodes; empty disables it
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

	server := NewServer(db, relayURL, storageNodes, smtpConfig, baseURL, staticSub, dataDir)
	if public := strings.TrimRight(os.Getenv("RELAY_URL_PUBLIC"), "/"); public != "" {
		server.relayPublicURL = public
	}
	// Volunteer nodes on private addresses are refused unless explicitly
	// allowed, for testing on a LAN.
	if os.Getenv("ALLOW_PRIVATE_NODES") == "1" {
		log.Printf("ALLOW_PRIVATE_NODES=1: volunteer storage nodes may use private addresses (testing only)")
		server.nodes.SetAllowPrivate(true)
	}
	server.adminToken = os.Getenv("NODE_ADMIN_TOKEN")
	server.nodes.StartMaintenance()
	if token := os.Getenv("RELAY_TRUSTED_TOKEN"); token != "" {
		httpClient.Transport = &relayAuthTransport{base: http.DefaultTransport, relayURL: strings.TrimRight(relayURL, "/"), token: token}
	}

	// Keep rate limits across restarts, saving on shutdown as well.
	limits := newLimiterStore(filepath.Join(dataDir, "ratelimits.json"), server.limiters()...)
	limits.Load()
	go limits.Run()
	saveOnExit(limits)

	log.Printf("Help Peer Web Backend listening on :%s (relay: %s, nodes: %v)", port, relayURL, storageNodes)
	log.Fatal(http.ListenAndServe(":"+port, server.routes()))
}

func NewServer(db *DB, relayURL string, nodes []StorageNode, smtp *SMTPConfig, baseURL string, static fs.FS, dataDir string) *Server {
	return &Server{
		db:              db,
		auth:            NewAuth(db, smtp, baseURL),
		relayURL:        relayURL,
		relayPublicURL:  relayURL,
		nodes:           newNodeRegistry(nodes, dataDir, false),
		smtpConfig:      smtp,
		static:          static,
		baseURL:         baseURL,
		manifestMisses:  newRateLimiter("manifest-misses", 30, time.Minute),
		manifestUploads: newRateLimiter("manifest-uploads", 30, time.Minute),
		notifyLimit:     newRateLimiter("notify", 50, time.Hour),
		directoryLimit:  newRateLimiter("directory", 60, time.Minute),

		nodeRegistrations: newRateLimiter("node-registrations", 30, time.Hour),
		segmentBytes: newRateLimiter("segment-bytes",
			int(envInt64("SEGMENT_DAILY_BYTES", defaultSegmentDailyBytes)), segmentBudgetWindow),
		segmentSlots: newSlotLimiter(
			int(envInt64("SEGMENT_CONCURRENCY", defaultSegmentPerClient)),
			int(envInt64("SEGMENT_MAX_CONCURRENT", defaultSegmentTotal))),
		transferStarts: newRateLimiter("transfer-starts",
			int(envInt64("TRANSFERS_PER_HOUR", defaultTransfersPerHour)), time.Hour),
		tickets:     newTicketBook(),
		transferMax: envInt64("TRANSFER_MAX_BYTES", defaultTransferMaxBytes),
	}
}

// authMeHandler reports who is logged in (by session or API token).
func (s *Server) authMeHandler(w http.ResponseWriter, req *http.Request) {
	email, ok := s.getUserEmail(req)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{"authenticated": false})
		return
	}
	u, _ := s.db.GetUser(email)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"email":         email,
		"username":      u.Username,
	})
}

// limiters lists every rate limiter, for saving their state.
func (s *Server) limiters() []*rateLimiter {
	return []*rateLimiter{
		s.manifestMisses, s.manifestUploads, s.notifyLimit, s.directoryLimit, s.nodeRegistrations,
		s.segmentBytes, s.transferStarts, s.auth.requestsPerIP, s.auth.requestsPerEmail,
	}
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

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/auth/request", s.auth.authRequestHandler)
	mux.HandleFunc("/api/auth/verify", s.auth.authVerifyHandler)
	mux.HandleFunc("/api/auth/logout", s.auth.authLogoutHandler)
	mux.HandleFunc("/api/auth/me", s.authMeHandler)
	mux.HandleFunc("/api/upload/segment", s.segmentUploadHandler)
	mux.HandleFunc("/api/upload/quota", s.uploadQuotaHandler)
	mux.HandleFunc("/api/upload/begin", s.uploadBeginHandler)
	mux.HandleFunc("/api/upload/finish", s.uploadFinishHandler)
	mux.HandleFunc("/api/upload/manifest", s.manifestUploadHandler)
	mux.HandleFunc("/api/download", s.downloadHandler)
	mux.HandleFunc("/api/download/segment", s.segmentDownloadHandler)
	mux.HandleFunc("/api/download/ack", s.ackHandler)
	mux.HandleFunc("/api/cancel", s.cancelHandler)
	mux.HandleFunc("/api/profile", s.profileHandler)
	mux.HandleFunc("/api/users/search", s.userSearchHandler)
	mux.HandleFunc("/api/users/lookup", s.userLookupHandler)
	mux.HandleFunc("/api/inbox", s.inboxHandler)
	mux.HandleFunc("/api/inbox/", s.inboxHandler)
	mux.HandleFunc("/api/inbox/received", s.inboxReceivedHandler)
	mux.HandleFunc("/api/tokens", s.tokensHandler)
	mux.HandleFunc("/api/tokens/", s.tokensHandler)
	mux.HandleFunc("/api/transfers", s.registerTransferHandler)
	mux.HandleFunc("/api/config", s.configHandler)
	mux.HandleFunc("/api/notify", s.notifyHandler)
	mux.HandleFunc("/api/history", s.historyHandler)
	mux.HandleFunc("/api/health", s.healthHandler)
	mux.HandleFunc("/api/node/register", s.nodeRegisterHandler)
	mux.HandleFunc("/api/node/deregister", s.nodeDeregisterHandler)
	mux.HandleFunc("/api/admin/nodes", s.adminNodesHandler)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, req *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})

	// Generated rather than static so they name whichever host serves them.
	mux.HandleFunc("/robots.txt", s.robotsHandler)
	mux.HandleFunc("/sitemap.xml", s.sitemapHandler)

	// Serve the frontend
	mux.Handle("/", spaHandler(s.static))
	return mux
}

// spaHandler serves static files, falling back to index.html for client-side
// routes such as /verify?token=..., which have no file of their own. A missing
// path with a file extension is a 404, so crawlers don't index the app shell
// as /favicon.ico or /old.js.
func spaHandler(static fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(static))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		name := strings.TrimPrefix(path.Clean(req.URL.Path), "/")
		if name != "" {
			if _, err := fs.Stat(static, name); err != nil {
				if path.Ext(name) != "" {
					http.NotFound(w, req)
					return
				}
				req = req.Clone(req.Context())
				req.URL.Path = "/"
			}
		}
		fileServer.ServeHTTP(w, req)
	})
}

func (s *Server) robotsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, `User-agent: *
Allow: /
Disallow: /api/
Disallow: /account
Disallow: /inbox
Disallow: /history
Disallow: /verify

Sitemap: %s/sitemap.xml
`, s.baseURL)
}

func (s *Server) sitemapHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
`)
	for _, p := range []string{"/", "/upload", "/download", "/llms.txt"} {
		fmt.Fprintf(w, "  <url><loc>%s%s</loc></url>\n", html.EscapeString(s.baseURL), p)
	}
	io.WriteString(w, "</urlset>\n")
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

// getUserEmail identifies the user from an API token (CLI/SDK, sent as
// "Authorization: Bearer hp_...") or a browser session cookie.
func (s *Server) getUserEmail(req *http.Request) (string, bool) {
	if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return s.db.EmailForAPIToken(strings.TrimPrefix(auth, "Bearer "))
	}
	return s.sessionEmail(req)
}

// sessionEmail identifies the user from a browser session cookie only.
func (s *Server) sessionEmail(req *http.Request) (string, bool) {
	cookie, err := req.Cookie("helppeer_session")
	if err != nil {
		return "", false
	}
	return s.db.GetSession(cookie.Value)
}
