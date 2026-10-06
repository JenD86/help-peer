package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// A transfer is announced before it is uploaded. The page says how many bytes
// it is going to send and, if the client is allowed to, gets a ticket; every
// segment must carry that ticket. That is what lets the server see "one
// upload" instead of a stream of 64 MB segments, so it can limit how big one
// upload may be, how many a client may start per hour, and how much a client
// may send per 24 hours, and tell the client at the start instead of part way
// through.
const (
	defaultTransferMaxBytes = 10 << 30 // TRANSFER_MAX_BYTES: the largest single transfer
	defaultTransfersPerHour = 2        // TRANSFERS_PER_HOUR: transfers one client may start
	ticketLifetime          = 24 * time.Hour
)

// uploadTicket is the permission to upload a number of bytes.
type uploadTicket struct {
	client    string // who it was issued to (the key of the limits)
	remaining int64
	total     int64
	expires   time.Time
}

// ticketBook remembers the tickets that have been handed out. They are kept
// in memory only: after a restart a transfer in progress has to be started
// again.
type ticketBook struct {
	mu sync.Mutex
	m  map[string]*uploadTicket // keyed by the hash of the token
}

func newTicketBook() *ticketBook {
	return &ticketBook{m: map[string]*uploadTicket{}}
}

func ticketKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue creates a ticket for total bytes and returns its token.
func (b *ticketBook) Issue(client string, total int64) string {
	token := generateToken(40)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for k, t := range b.m { // drop expired tickets as we go
		if now.After(t.expires) {
			delete(b.m, k)
		}
	}
	b.m[ticketKey(token)] = &uploadTicket{client: client, remaining: total, total: total, expires: now.Add(ticketLifetime)}
	return token
}

type spendResult int

const (
	spendOK      spendResult = iota
	spendUnknown             // no such ticket, or it has expired
	spendTooMuch             // more than the ticket allows
)

// Spend uses n bytes of the ticket.
func (b *ticketBook) Spend(token string, n int64) spendResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.m[ticketKey(token)]
	if t == nil || time.Now().After(t.expires) {
		return spendUnknown
	}
	if n > t.remaining {
		return spendTooMuch
	}
	t.remaining -= n
	return spendOK
}

// Refund gives back n bytes after a segment that stored nothing.
func (b *ticketBook) Refund(token string, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t := b.m[ticketKey(token)]; t != nil {
		if t.remaining += n; t.remaining > t.total {
			t.remaining = t.total
		}
	}
}

// Finish closes a ticket and says how much of it was not used.
func (b *ticketBook) Finish(token string) (client string, unused int64, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := ticketKey(token)
	t := b.m[k]
	if t == nil {
		return "", 0, false
	}
	delete(b.m, k)
	return t.client, t.remaining, true
}

// spendTicket checks a segment's ticket and length and uses its bytes. It
// answers the request and reports false when the segment must be refused. The
// length comes from the header, so a refusal costs nothing: nothing has been
// read yet.
func (s *Server) spendTicket(w http.ResponseWriter, req *http.Request) (token string, size int64, ok bool) {
	if req.ContentLength <= 0 {
		writeError(w, http.StatusLengthRequired, "Content-Length required")
		return "", 0, false
	}
	if req.ContentLength > maxEncryptedSegment {
		writeError(w, http.StatusRequestEntityTooLarge, "segment too large")
		return "", 0, false
	}
	token = req.Header.Get("X-Upload-Ticket")
	if token == "" {
		writeError(w, http.StatusBadRequest, "This page is out of date. Reload it and try again.")
		return "", 0, false
	}
	switch s.tickets.Spend(token, req.ContentLength) {
	case spendUnknown:
		writeError(w, http.StatusUnauthorized, "This upload session has expired. Start the transfer again.")
		return "", 0, false
	case spendTooMuch:
		writeError(w, http.StatusRequestEntityTooLarge, "This upload is larger than the size announced when it started.")
		return "", 0, false
	}
	return token, req.ContentLength, true
}

// uploadBeginHandler starts a transfer: POST {"total_bytes": N} returns a
// ticket, or says why the client may not upload that much now.
func (s *Server) uploadBeginHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		TotalBytes int64 `json:"total_bytes"`
	}
	req.Body = http.MaxBytesReader(w, req.Body, 1024)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.TotalBytes <= 0 {
		writeError(w, http.StatusBadRequest, "total_bytes is required")
		return
	}
	total := body.TotalBytes
	key := limitKey(clientIP(req))

	// Refusals that waiting would not fix come first, so they never use up
	// anything.
	if total > s.transferMax {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"This transfer (%s) is larger than the maximum of %s per transfer.", formatBytes(total), formatBytes(s.transferMax)))
		return
	}
	if limit := int64(s.segmentBytes.limit); total > limit {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"This transfer (%s) is larger than the whole upload allowance (%s per 24 hours), so it cannot be sent. The operator can raise SEGMENT_DAILY_BYTES.",
			formatBytes(total), formatBytes(limit)))
		return
	}

	if !s.transferStarts.Allow(key, 1) {
		_, limit, resets := s.transferStarts.Status(key)
		w.Header().Set("Retry-After", strconv.Itoa(int(resets.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf(
			"You can start %d transfers per hour. Try again in %s.", limit, formatWait(resets)))
		log.Printf("Transfer start refused for %s (%d per hour)", key, limit)
		return
	}
	if !s.segmentBytes.Allow(key, int(total)) {
		s.transferStarts.Refund(key, 1) // it did not start
		used, limit, resets := s.segmentBytes.Status(key)
		w.Header().Set("Retry-After", strconv.Itoa(int(resets.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf(
			"Upload limit reached: this transfer needs %s and you have %s left of %s per 24 hours. Try again in %s.",
			formatBytes(total), formatBytes(int64(limit-used)), formatBytes(int64(limit)), formatWait(resets)))
		log.Printf("Upload allowance refused for %s (%d bytes asked)", key, total)
		return
	}

	token := s.tickets.Issue(key, total)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ticket":             token,
		"total_bytes":        total,
		"expires_in_seconds": int(ticketLifetime.Seconds()),
	})
}

// uploadFinishHandler closes a transfer (finished, failed or abandoned) and
// gives back the allowance it reserved but did not use.
func (s *Server) uploadFinishHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	req.Body = http.MaxBytesReader(w, req.Body, 1024)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Ticket == "" {
		writeError(w, http.StatusBadRequest, "ticket is required")
		return
	}
	if client, unused, ok := s.tickets.Finish(body.Ticket); ok && unused > 0 {
		s.segmentBytes.Refund(client, int(unused))
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
