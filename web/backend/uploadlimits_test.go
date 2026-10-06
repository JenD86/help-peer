package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// useForwardedFor makes the server read the client address from
// X-Forwarded-For, as it does behind the proxy in production.
func useForwardedFor(t *testing.T) {
	t.Helper()
	old := trustProxy
	trustProxy = true
	log.SetOutput(io.Discard)
	t.Cleanup(func() {
		trustProxy = old
		log.SetOutput(os.Stderr)
	})
}

func segmentBytesOf(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// begin announces a transfer of total bytes as the given client.
func (e *testEnv) begin(t *testing.T, ip string, total int) *http.Response {
	t.Helper()
	data, _ := json.Marshal(map[string]int{"total_bytes": total})
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/upload/begin", bytes.NewReader(data))
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// beginOK announces a transfer that must be accepted and returns its ticket.
func (e *testEnv) beginOK(t *testing.T, ip string, total int) string {
	t.Helper()
	resp := e.begin(t, ip, total)
	var out map[string]interface{}
	decode(t, resp, &out)
	ticket, _ := out["ticket"].(string)
	if resp.StatusCode != http.StatusOK || ticket == "" {
		t.Fatalf("begin %d bytes: %d %v", total, resp.StatusCode, out)
	}
	return ticket
}

// segmentWith posts one segment with a ticket. withDeleteToken=false leaves out
// the delete-token header, which the handler refuses after reading the body.
func (e *testEnv) segmentWith(t *testing.T, ip, ticket string, body []byte, withDeleteToken bool) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/upload/segment", bytes.NewReader(body))
	req.Header.Set("X-Forwarded-For", ip)
	if ticket != "" {
		req.Header.Set("X-Upload-Ticket", ticket)
	}
	if withDeleteToken {
		req.Header.Set("X-Delete-Token-Hash", testDeleteTokenHash)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (e *testEnv) status(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	var out map[string]interface{}
	decode(t, resp, &out)
	msg, _ := out["error"].(string)
	return resp.StatusCode, msg
}

func (e *testEnv) finish(t *testing.T, ticket string) int {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"ticket": ticket})
	resp, err := http.Post(e.srv.URL+"/api/upload/finish", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestBeginIssuesATicketThatSegmentsSpend(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	ticket := e.beginOK(t, "198.51.100.1", 10000)

	for i := 0; i < 2; i++ {
		resp := e.segmentWith(t, "198.51.100.1", ticket, segmentBytesOf(5000), true)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("segment %d: %d", i+1, resp.StatusCode)
		}
	}
	// The ticket was for 10000 bytes: a third segment is more than was announced.
	code, msg := e.status(t, e.segmentWith(t, "198.51.100.1", ticket, segmentBytesOf(5000), true))
	if code != http.StatusRequestEntityTooLarge || !strings.Contains(msg, "larger than the size announced") {
		t.Fatalf("a segment beyond the ticket: %d %q", code, msg)
	}
}

func TestSegmentNeedsAValidTicket(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	seg := segmentBytesOf(5000)

	code, msg := e.status(t, e.segmentWith(t, "198.51.100.1", "", seg, true))
	if code != http.StatusBadRequest || !strings.Contains(msg, "out of date") {
		t.Fatalf("no ticket: %d %q", code, msg)
	}
	code, msg = e.status(t, e.segmentWith(t, "198.51.100.1", "not-a-real-ticket", seg, true))
	if code != http.StatusUnauthorized || !strings.Contains(msg, "expired") {
		t.Fatalf("unknown ticket: %d %q", code, msg)
	}
}

func TestOneTransferCannotBeLargerThanTheMaximum(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	e.s.transferMax = 8000

	code, msg := e.status(t, e.begin(t, "198.51.100.1", 9000))
	if code != http.StatusRequestEntityTooLarge || !strings.Contains(msg, "maximum of") {
		t.Fatalf("over the maximum: %d %q", code, msg)
	}
	// The refusal used none of the allowance or of the transfers per hour.
	key := limitKey("198.51.100.1")
	if used, _, _ := e.s.segmentBytes.Status(key); used != 0 {
		t.Fatalf("allowance used: %d", used)
	}
	if used, _, _ := e.s.transferStarts.Status(key); used != 0 {
		t.Fatalf("transfers started: %d", used)
	}
	e.beginOK(t, "198.51.100.1", 8000) // exactly the maximum is fine
}

func TestTransfersPerHourAreLimitedPerClient(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	e.s.transferStarts = newRateLimiter("transfer-starts", 2, time.Hour)

	e.beginOK(t, "198.51.100.1", 1000)
	e.beginOK(t, "198.51.100.1", 1000)
	resp := e.begin(t, "198.51.100.1", 1000)
	retry := resp.Header.Get("Retry-After")
	code, msg := e.status(t, resp)
	if code != http.StatusTooManyRequests || !strings.Contains(msg, "2 transfers per hour") {
		t.Fatalf("the third transfer in an hour: %d %q", code, msg)
	}
	if secs, err := strconv.Atoi(retry); err != nil || secs < 1 {
		t.Fatalf("Retry-After %q", retry)
	}
	e.beginOK(t, "198.51.100.2", 1000) // another client is not affected
}

func TestTheAllowanceIsReservedWhenATransferStarts(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	e.s.segmentBytes = newRateLimiter("segment-bytes", 12000, 24*time.Hour)
	e.s.transferStarts = newRateLimiter("transfer-starts", 10, time.Hour)
	key := limitKey("198.51.100.1")

	e.beginOK(t, "198.51.100.1", 5000)
	e.beginOK(t, "198.51.100.1", 5000)
	resp := e.begin(t, "198.51.100.1", 5000) // 15000 would be more than 12000
	retry := resp.Header.Get("Retry-After")
	code, msg := e.status(t, resp)
	if code != http.StatusTooManyRequests || !strings.Contains(msg, "Upload limit reached") || !strings.Contains(msg, "left of") {
		t.Fatalf("over the allowance: %d %q", code, msg)
	}
	if retry == "" {
		t.Fatal("Retry-After missing")
	}
	// A transfer that did not start does not count as started.
	if used, _, _ := e.s.transferStarts.Status(key); used != 2 {
		t.Fatalf("transfers started: %d, expected 2", used)
	}
}

func TestATransferLargerThanTheWholeAllowanceSaysSo(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	e.s.segmentBytes = newRateLimiter("segment-bytes", 3000, 24*time.Hour)
	key := limitKey("198.51.100.1")

	resp := e.begin(t, "198.51.100.1", 5000)
	retry := resp.Header.Get("Retry-After")
	code, msg := e.status(t, resp)
	if code != http.StatusRequestEntityTooLarge || !strings.Contains(msg, "whole upload allowance") {
		t.Fatalf("%d %q", code, msg)
	}
	if retry != "" {
		t.Fatal("waiting cannot help, so there must be no Retry-After")
	}
	if used, _, _ := e.s.segmentBytes.Status(key); used != 0 {
		t.Fatalf("allowance used: %d", used)
	}
	if used, _, _ := e.s.transferStarts.Status(key); used != 0 {
		t.Fatalf("transfers started: %d", used)
	}
}

func TestFinishGivesBackWhatWasNotUsed(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	key := limitKey("198.51.100.1")

	ticket := e.beginOK(t, "198.51.100.1", 10000)
	if used, _, _ := e.s.segmentBytes.Status(key); used != 10000 {
		t.Fatalf("reserved %d, expected 10000", used)
	}
	resp := e.segmentWith(t, "198.51.100.1", ticket, segmentBytesOf(4000), true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("segment: %d", resp.StatusCode)
	}

	if code := e.finish(t, ticket); code != http.StatusOK {
		t.Fatalf("finish: %d", code)
	}
	if used, _, _ := e.s.segmentBytes.Status(key); used != 4000 {
		t.Fatalf("used after finish: %d, expected 4000", used)
	}
	// The ticket is closed, and closing twice is harmless.
	if code, _ := e.status(t, e.segmentWith(t, "198.51.100.1", ticket, segmentBytesOf(1000), true)); code != http.StatusUnauthorized {
		t.Fatalf("a segment after finish: %d", code)
	}
	if code := e.finish(t, ticket); code != http.StatusOK {
		t.Fatalf("second finish: %d", code)
	}
	if used, _, _ := e.s.segmentBytes.Status(key); used != 4000 {
		t.Fatalf("a second finish changed the allowance: %d", used)
	}
}

func TestASegmentThatStoresNothingGivesItsBytesBack(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	ticket := e.beginOK(t, "198.51.100.1", 10000)
	seg := segmentBytesOf(5000)

	// Without the delete-token header the segment is refused after it was counted.
	for i := 0; i < 3; i++ {
		resp := e.segmentWith(t, "198.51.100.1", ticket, seg, false)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attempt %d: %d", i+1, resp.StatusCode)
		}
	}
	// None of them used the ticket: the two real segments still fit.
	for i := 0; i < 2; i++ {
		resp := e.segmentWith(t, "198.51.100.1", ticket, seg, true)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("segment %d: %d", i+1, resp.StatusCode)
		}
	}
}

func TestSegmentNeedsAContentLength(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	ticket := e.beginOK(t, "198.51.100.1", 10000)
	// A body of unknown length is sent chunked.
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/upload/segment", io.NopCloser(bytes.NewReader(segmentBytesOf(5000))))
	req.Header.Set("X-Delete-Token-Hash", testDeleteTokenHash)
	req.Header.Set("X-Upload-Ticket", ticket)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusLengthRequired {
		t.Fatalf("expected 411, got %d", resp.StatusCode)
	}
}

// holdUpload starts a segment upload that stays open until the returned writer
// is closed, so the slot it holds can be observed.
func (e *testEnv) holdUpload(t *testing.T, ip, ticket string) *io.PipeWriter {
	t.Helper()
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/upload/segment", pr)
	req.ContentLength = 5000
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("X-Delete-Token-Hash", testDeleteTokenHash)
	req.Header.Set("X-Upload-Ticket", ticket)
	go func() {
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	return pw
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestOnlyAFewSegmentsMayBeUploadedAtOnce(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	e.s.segmentSlots = newSlotLimiter(2, 3) // 2 per client, 3 overall
	a := limitKey("198.51.100.1")
	ticketA := e.beginOK(t, "198.51.100.1", 100000)
	ticketB := e.beginOK(t, "198.51.100.2", 100000)
	ticketC := e.beginOK(t, "198.51.100.3", 100000)
	seg := segmentBytesOf(5000)

	held := []*io.PipeWriter{e.holdUpload(t, "198.51.100.1", ticketA), e.holdUpload(t, "198.51.100.1", ticketA)}
	waitUntil(t, "two uploads in flight", func() bool { return e.s.segmentSlots.Active(a) == 2 })

	// A third from the same client is refused, and told to wait.
	resp := e.segmentWith(t, "198.51.100.1", ticketA, seg, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("third upload from one client: %d", resp.StatusCode)
	}

	// Another client may start one, which fills the server-wide limit of 3.
	held = append(held, e.holdUpload(t, "198.51.100.2", ticketB))
	waitUntil(t, "three uploads in flight", func() bool { return e.s.segmentSlots.Active(limitKey("198.51.100.2")) == 1 })
	resp = e.segmentWith(t, "198.51.100.3", ticketC, seg, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a client when the server is full: %d", resp.StatusCode)
	}

	// Finishing the uploads frees the slots.
	for _, pw := range held {
		pw.CloseWithError(io.ErrUnexpectedEOF)
	}
	waitUntil(t, "slots to be released", func() bool { return e.s.segmentSlots.Active(a) == 0 })
	resp = e.segmentWith(t, "198.51.100.1", ticketA, seg, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after the slots were released: %d", resp.StatusCode)
	}
}

func TestQuotaEndpointShowsTheLimits(t *testing.T) {
	e := newTestEnv(t)
	useForwardedFor(t)
	e.s.segmentBytes = newRateLimiter("segment-bytes", 20000, 24*time.Hour)
	e.s.transferStarts = newRateLimiter("transfer-starts", 3, time.Hour)
	e.s.transferMax = 15000

	quota := func() map[string]float64 {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/api/upload/quota", nil)
		req.Header.Set("X-Forwarded-For", "198.51.100.1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]float64
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := quota()
	if before["limit_bytes"] != 20000 || before["used_bytes"] != 0 || before["remaining_bytes"] != 20000 ||
		before["max_transfer_bytes"] != 15000 || before["transfers_per_hour"] != 3 || before["transfers_left_this_hour"] != 3 {
		t.Fatalf("fresh quota: %v", before)
	}
	e.beginOK(t, "198.51.100.1", 5000)
	after := quota()
	if after["used_bytes"] != 5000 || after["remaining_bytes"] != 15000 || after["transfers_left_this_hour"] != 2 || after["resets_in_seconds"] < 86000 {
		t.Fatalf("quota after starting a transfer: %v", after)
	}
}

func TestTicketBook(t *testing.T) {
	b := newTicketBook()
	token := b.Issue("client", 1000)

	if b.Spend(token, 600) != spendOK || b.Spend(token, 600) != spendTooMuch {
		t.Fatal("a ticket must allow 1000 bytes in total")
	}
	if b.Spend("other", 1) != spendUnknown {
		t.Fatal("an unknown token was accepted")
	}
	b.Refund(token, 5000) // never more than the ticket was for
	if b.Spend(token, 1000) != spendOK || b.Spend(token, 1) != spendTooMuch {
		t.Fatal("a refund must not raise the ticket above its total")
	}

	client, unused, ok := b.Finish(token)
	if !ok || client != "client" || unused != 0 {
		t.Fatalf("finish: %q %d %v", client, unused, ok)
	}
	if _, _, ok := b.Finish(token); ok {
		t.Fatal("a ticket can be closed only once")
	}

	// An expired ticket is refused and dropped when the next one is issued.
	old := b.Issue("client", 1000)
	b.m[ticketKey(old)].expires = time.Now().Add(-time.Second)
	if b.Spend(old, 1) != spendUnknown {
		t.Fatal("an expired ticket was accepted")
	}
	b.Issue("client", 1000)
	if _, there := b.m[ticketKey(old)]; there {
		t.Fatal("the expired ticket was not dropped")
	}
}

func TestSlotReleaseIsSafeToRepeat(t *testing.T) {
	l := newSlotLimiter(1, 1)
	release, ok := l.Acquire("a")
	if !ok {
		t.Fatal("first acquire refused")
	}
	if _, ok := l.Acquire("a"); ok {
		t.Fatal("a second slot was given to the same client")
	}
	release()
	release() // must not give back a slot that someone else now holds
	again, ok := l.Acquire("b")
	if !ok {
		t.Fatal("the slot was not released")
	}
	release()
	if _, ok := l.Acquire("c"); ok {
		t.Fatal("repeating release freed a slot it did not own")
	}
	again()
}

func TestLimitKeyTreatsAnIPv6BlockAsOneClient(t *testing.T) {
	same := [][2]string{
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff"},
		{"203.0.113.7", "::ffff:203.0.113.7"},
	}
	for _, p := range same {
		if limitKey(p[0]) != limitKey(p[1]) {
			t.Errorf("%s and %s should be one client", p[0], p[1])
		}
	}
	different := [][2]string{
		{"2001:db8:1:2::1", "2001:db8:1:3::1"},
		{"203.0.113.7", "203.0.113.8"},
	}
	for _, p := range different {
		if limitKey(p[0]) == limitKey(p[1]) {
			t.Errorf("%s and %s should be different clients", p[0], p[1])
		}
	}
	if limitKey("not an address") != "not an address" {
		t.Error("an unparsable address should be used as it is")
	}
}

func TestFormatWait(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{10 * time.Second, "1 minute"},
		{time.Minute, "1 minute"},
		{61 * time.Second, "2 min"},
		{45 * time.Minute, "45 min"},
		{time.Hour, "1 h"},
		{3*time.Hour + 12*time.Minute, "3 h 12 min"},
		{3*time.Hour + 11*time.Minute + 5*time.Second, "3 h 12 min"},
		{24 * time.Hour, "24 h"},
	}
	for _, c := range cases {
		if got := formatWait(c.d); got != c.want {
			t.Errorf("formatWait(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestUploadLimitsAreSavedAcrossRestarts(t *testing.T) {
	e := newTestEnv(t)
	saved := map[*rateLimiter]bool{}
	for _, l := range e.s.limiters() {
		saved[l] = true
	}
	if !saved[e.s.segmentBytes] || !saved[e.s.transferStarts] {
		t.Fatal("the upload allowance or the transfers per hour are not in the list of saved limiters")
	}
}

func TestRefundAndStatus(t *testing.T) {
	l := newRateLimiter("t", 100, time.Hour)
	if !l.Allow("k", 60) {
		t.Fatal("first 60 refused")
	}
	l.Refund("k", 40)
	if used, limit, _ := l.Status("k"); used != 20 || limit != 100 {
		t.Fatalf("status after refund: used %d limit %d", used, limit)
	}
	l.Refund("k", 500) // never below zero
	if used, _, _ := l.Status("k"); used != 0 {
		t.Fatalf("used %d", used)
	}
	l.Refund("nobody", 5) // an unknown key is harmless
}
