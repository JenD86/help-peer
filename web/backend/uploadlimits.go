package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Limits on uploads through the website. Anyone may upload, so every client
// gets a byte allowance per 24 hours (stored data lives 24 hours, so this is
// what bounds storage and cost; it is reserved when a transfer starts, see
// uploadtickets.go), and only a few segments may be in flight at once (each
// one is held in memory while it is erasure-coded). The numbers can be
// changed with environment variables.
//
// These limits cover uploads made through the website only. The CLI and SDK
// send shards straight to the storage nodes and the manifest straight to the
// relay, so they never pass through this handler.
const (
	defaultSegmentDailyBytes = 20 << 30 // SEGMENT_DAILY_BYTES, per client per 24 hours
	defaultSegmentPerClient  = 3        // SEGMENT_CONCURRENCY, per client
	defaultSegmentTotal      = 8        // SEGMENT_MAX_CONCURRENT, whole server
	segmentBudgetWindow      = 24 * time.Hour
)

// envInt64 reads a positive integer from the environment, or returns def.
func envInt64(name string, def int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		log.Printf("Ignoring %s=%q: it must be a positive whole number", name, v)
		return def
	}
	return n
}

// limitKey identifies a client for the upload limits. An IPv6 user usually
// controls a whole /64, so the whole block counts as one client; otherwise
// switching to another address in the block would hand out a fresh allowance.
func limitKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// Status reports how much of key's allowance is used and when it resets.
func (l *rateLimiter) Status(key string) (used, limit int, resetsIn time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.counts[key]
	if !ok || time.Since(w.start) >= l.window {
		return 0, l.limit, l.window
	}
	return w.n, l.limit, l.window - time.Since(w.start)
}

// Refund gives back n units, for a request that ended up using none.
func (l *rateLimiter) Refund(key string, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if w, ok := l.counts[key]; ok {
		if w.n -= n; w.n < 0 {
			w.n = 0
		}
	}
}

// slotLimiter caps how many uploads run at once, per client and overall.
type slotLimiter struct {
	mu                  sync.Mutex
	perKey              map[string]int
	total               int
	maxPerKey, maxTotal int
}

func newSlotLimiter(maxPerKey, maxTotal int) *slotLimiter {
	return &slotLimiter{perKey: map[string]int{}, maxPerKey: maxPerKey, maxTotal: maxTotal}
}

// Acquire takes a slot for key. The returned function gives it back and is
// safe to call more than once.
func (l *slotLimiter) Acquire(key string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.perKey[key] >= l.maxPerKey {
		return nil, false
	}
	l.total++
	l.perKey[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.perKey[key] <= 1 {
				delete(l.perKey, key)
			} else {
				l.perKey[key]--
			}
		})
	}, true
}

// Active reports how many slots key holds.
func (l *slotLimiter) Active(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perKey[key]
}

// formatWait turns a duration into "3 h 12 min" for messages shown to users.
func formatWait(d time.Duration) string {
	mins := int((d + time.Minute - 1) / time.Minute) // round up
	switch {
	case mins <= 1:
		return "1 minute"
	case mins < 60:
		return fmt.Sprintf("%d min", mins)
	case mins%60 == 0:
		return fmt.Sprintf("%d h", mins/60)
	default:
		return fmt.Sprintf("%d h %d min", mins/60, mins%60)
	}
}

// acquireSegmentSlot reserves one of the client's upload slots, or answers
// 429 and reports false.
func (s *Server) acquireSegmentSlot(w http.ResponseWriter, key string) (release func(), ok bool) {
	release, ok = s.segmentSlots.Acquire(key)
	if !ok {
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusTooManyRequests, "Too many uploads at once. Wait for the current ones to finish and try again.")
	}
	return release, ok
}

// uploadQuotaHandler tells a client how much it may still upload, so the page
// can warn before a large upload starts instead of failing part way through.
func (s *Server) uploadQuotaHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	used, limit, resets := s.segmentBytes.Status(limitKey(clientIP(req)))
	remaining := limit - used
	if remaining < 0 {
		remaining = 0
	}
	startsUsed, startsLimit, startsResets := s.transferStarts.Status(limitKey(clientIP(req)))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"limit_bytes":                limit,
		"used_bytes":                 used,
		"remaining_bytes":            remaining,
		"resets_in_seconds":          int(resets.Seconds()),
		"max_segment_bytes":          maxEncryptedSegment,
		"max_transfer_bytes":         s.transferMax,
		"transfers_per_hour":         startsLimit,
		"transfers_left_this_hour":   startsLimit - startsUsed,
		"transfers_reset_in_seconds": int(startsResets.Seconds()),
	})
}
