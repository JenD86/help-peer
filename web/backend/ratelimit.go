package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter allows `limit` units per key per fixed window.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	counts map[string]*rateWindow
}

type rateWindow struct {
	start time.Time
	n     int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	l := &rateLimiter{limit: limit, window: window, counts: make(map[string]*rateWindow)}
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

// trustProxy makes clientIP use X-Forwarded-For. Only enable it when the
// backend is reachable solely through a reverse proxy that sets the header,
// otherwise clients can spoof their address to dodge rate limits.
var trustProxy bool

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
