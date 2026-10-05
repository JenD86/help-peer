package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

const maxCancelShards = 200000

// CancelRequest withdraws a transfer. The browser that uploaded it still
// holds the decrypted manifest, so it supplies the secrets and shard list;
// this server never sees the code.
type CancelRequest struct {
	ManifestHash string `json:"manifest_hash"`
	AckSecret    string `json:"ack_secret"`
	DeleteToken  string `json:"delete_token"`
	Shards       []struct {
		Hash string `json:"hash"`
		Node string `json:"node"`
	} `json:"shards"`
}

func (s *Server) cancelHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := clientIP(req)
	if s.manifestMisses.Exceeded(ip) {
		writeError(w, http.StatusTooManyRequests, "too many failed requests, try again later")
		return
	}

	var body CancelRequest
	req.Body = http.MaxBytesReader(w, req.Body, 32<<20)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !isHexHash(body.ManifestHash) || !isHexHash(body.AckSecret) || !isHexHash(body.DeleteToken) {
		writeError(w, http.StatusBadRequest, "invalid manifest hash or secrets")
		return
	}
	if len(body.Shards) > maxCancelShards {
		writeError(w, http.StatusBadRequest, "too many shards")
		return
	}

	// Withdraw the manifest first so no new download can start. Not
	// retried: cancelling isn't idempotent from the caller's point of view.
	relayReq, err := http.NewRequest(http.MethodDelete, s.relayURL+"/manifest/"+body.ManifestHash,
		strings.NewReader(body.AckSecret))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp, err := httpClient.Do(relayReq)
	if err != nil {
		log.Printf("Cancel error: %v", err)
		writeError(w, http.StatusBadGateway, "relay unavailable")
		return
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
	case http.StatusNotFound, http.StatusForbidden:
		s.manifestMisses.Hit(ip)
		writeError(w, resp.StatusCode, "transfer not found: it expired, was already received, or was already cancelled")
		return
	default:
		writeError(w, http.StatusBadGateway, fmt.Sprintf("relay returned %d", resp.StatusCode))
		return
	}

	// Codes for this transfer are now useless; drop them from inboxes.
	s.db.DeleteInboxItems(func(i *InboxItem) bool { return i.ManifestHash == body.ManifestHash })

	// Then delete the shards, on our own storage nodes only (the list comes
	// from the browser).
	var mu sync.Mutex
	counts := map[string]int{}
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, sh := range body.Shards {
		nodeURL, ok := s.nodes.InternalURL(sh.Node)
		if !ok || !isHexHash(sh.Hash) {
			counts["failed"]++
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()
			outcome := deleteShard(url, body.DeleteToken)
			mu.Lock()
			counts[outcome]++
			mu.Unlock()
		}(nodeURL + "/shard/" + sh.Hash)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":              "ok",
		"shards_deleted":      counts["deleted"],
		"shards_already_gone": counts["already_gone"],
		"shards_failed":       counts["failed"],
	})
}

// deleteShard deletes one shard with the transfer's delete token and
// reports "deleted", "already_gone" or "failed".
func deleteShard(url, token string) string {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return "failed"
	}
	req.Header.Set("X-Delete-Token", token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "failed"
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return "deleted"
	case http.StatusNotFound:
		return "already_gone"
	default:
		return "failed"
	}
}
