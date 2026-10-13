package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// rateLimiter allows `limit` units per key per fixed window.
type rateLimiter struct {
	name   string // identifies it in the saved state file
	mu     sync.Mutex
	limit  int
	window time.Duration
	counts map[string]*rateWindow
}

type rateWindow struct {
	start time.Time
	n     int
}

func newRateLimiter(name string, limit int, window time.Duration) *rateLimiter {
	l := &rateLimiter{name: name, limit: limit, window: window, counts: make(map[string]*rateWindow)}
	go func() {
		for range time.Tick(window) {
			l.prune()
		}
	}()
	return l
}

func (l *rateLimiter) current(key string) *rateWindow {
	w, ok := l.counts[key]
	if !ok || time.Since(w.start) >= l.window {
		w = &rateWindow{start: time.Now()}
		l.counts[key] = w
	}
	return w
}

// Allow consumes n units for key, or reports false (consuming nothing) if
// that would exceed the limit.
func (l *rateLimiter) Allow(key string, n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.current(key)
	if w.n+n > l.limit {
		return false
	}
	w.n += n
	return true
}

// Exceeded reports whether key has used up its allowance, without consuming any.
func (l *rateLimiter) Exceeded(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.current(key).n >= l.limit
}

// Hit consumes one unit for key.
func (l *rateLimiter) Hit(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.current(key).n++
}

// prune drops windows that have ended so the map doesn't grow without bound.
func (l *rateLimiter) prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.counts {
		if time.Since(w.start) >= l.window {
			delete(l.counts, k)
		}
	}
}

// limiterStore saves rate-limiter state to a file so limits survive
// restarts; otherwise restarting the service would hand every client (and
// every login/notification email quota) a fresh allowance.
type limiterStore struct {
	path     string
	limiters []*rateLimiter
}

type savedWindow struct {
	Start time.Time `json:"start"`
	N     int       `json:"n"`
}

const limiterSaveInterval = 10 * time.Second

func newLimiterStore(path string, limiters ...*rateLimiter) *limiterStore {
	return &limiterStore{path: path, limiters: limiters}
}

// Save writes every limiter's still-active windows to disk.
func (s *limiterStore) Save() error {
	state := make(map[string]map[string]savedWindow, len(s.limiters))
	for _, l := range s.limiters {
		windows := make(map[string]savedWindow)
		l.mu.Lock()
		for key, w := range l.counts {
			if time.Since(w.start) < l.window {
				windows[key] = savedWindow{Start: w.start, N: w.n}
			}
		}
		l.mu.Unlock()
		state[l.name] = windows
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	// Private: the file lists client addresses and emails.
	return writeFileAtomic(s.path, data)
}

// Load restores windows saved by a previous run, skipping expired ones.
func (s *limiterStore) Load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var state map[string]map[string]savedWindow
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("Ignoring unreadable %s: %v", s.path, err)
		return
	}
	for _, l := range s.limiters {
		l.mu.Lock()
		for key, w := range state[l.name] {
			if time.Since(w.Start) < l.window {
				l.counts[key] = &rateWindow{start: w.Start, n: w.N}
			}
		}
		l.mu.Unlock()
	}
}

// Run saves periodically until the process exits.
func (s *limiterStore) Run() {
	for range time.Tick(limiterSaveInterval) {
		if err := s.Save(); err != nil {
			log.Printf("Failed to save rate limits: %v", err)
		}
	}
}

// trustProxy makes clientIP use X-Forwarded-For. Only enable it when the
// backend is reachable solely through a reverse proxy that sets the header,
// otherwise clients can spoof their address to dodge rate limits.
var trustProxy bool

// logSecrets makes a server without SMTP write the login links, transfer
// codes and messages it would have emailed to its log, so local testing can
// log in and see what was sent. Off by default: `docker compose up` without
// SMTP is the quickest way to run the site, and container logs are kept,
// shipped and shared.
var logSecrets bool

// clientIP identifies the caller for rate limiting.
func clientIP(req *http.Request) string {
	if trustProxy {
		// The proxy appends the address it saw, so the last entry is the one
		// we can trust.
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}
