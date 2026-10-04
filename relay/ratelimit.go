package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// rateLimiter allows `limit` hits per key per fixed window (0 = unlimited).
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
	return &rateLimiter{name: name, limit: limit, window: window, counts: make(map[string]*rateWindow)}
}

func (l *rateLimiter) current(key string) *rateWindow {
	w, ok := l.counts[key]
	if !ok || time.Since(w.start) >= l.window {
		w = &rateWindow{start: time.Now()}
		l.counts[key] = w
	}
	return w
}

// Exceeded reports whether key has used up its allowance for this window.
func (l *rateLimiter) Exceeded(key string) bool {
	if l.limit <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.current(key).n >= l.limit
}

// Allow consumes one unit for key, or reports false if none are left.
func (l *rateLimiter) Allow(key string) bool {
	if l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.current(key)
	if w.n >= l.limit {
		return false
	}
	w.n++
	return true
}

func (l *rateLimiter) Hit(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.current(key).n++
}

// Prune drops windows that have ended so the map doesn't grow without bound.
func (l *rateLimiter) Prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.counts {
		if time.Since(w.start) >= l.window {
			delete(l.counts, k)
		}
	}
}

// limiterStore saves rate-limiter state to a file so limits survive
// restarts; otherwise restarting the service would hand every client a
// fresh allowance.
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
	// Private: the file lists client addresses.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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
