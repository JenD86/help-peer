package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/klauspost/reedsolomon"
)

const (
	DataShards   = 8
	ParityShards = 4
	TotalShards  = DataShards + ParityShards

	SegmentSize = 64 * 1024 * 1024
	// AES-GCM adds a 12-byte nonce and a 16-byte tag to each segment.
	segmentOverhead     = 12 + 16
	maxEncryptedSegment = SegmentSize + segmentOverhead

	maxManifestBytes = 32 << 20
	maxRetrievalsCap = 100
	maxNameLength    = 200
)

// httpClient is shared so connections to nodes and the relay are pooled.
var httpClient = &http.Client{Timeout: 5 * time.Minute}

// SegmentUploadResponse tells the browser where a segment's shards went, so
// it can build the manifest.
type SegmentUploadResponse struct {
	EncryptedSize int         `json:"encrypted_size"`
	Shards        []ShardInfo `json:"shards"`
}

// segmentUploadHandler takes one encrypted segment (raw bytes, already
// encrypted by the browser), erasure-codes it and stores the shards.
func (s *Server) segmentUploadHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	data, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxEncryptedSegment))
	if err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "segment too large")
			return
		}
		writeError(w, http.StatusBadRequest, "read failed")
		return
	}
	if len(data) <= segmentOverhead {
		writeError(w, http.StatusBadRequest, "segment too small")
		return
	}
	deleteTokenHash := req.Header.Get("X-Delete-Token-Hash")
	if !isHexHash(deleteTokenHash) {
		writeError(w, http.StatusBadRequest, "X-Delete-Token-Hash required")
		return
	}

	enc, err := reedsolomon.New(DataShards, ParityShards)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erasure coding error")
		return
	}
	shards, err := enc.Split(data)
	if err == nil {
		err = enc.Encode(shards)
	}
	if err != nil {
		log.Printf("Erasure coding error: %v", err)
		writeError(w, http.StatusInternalServerError, "erasure coding error")
		return
	}

	// Upload the shards in parallel, spread over nodes with room for them
	// (no more than two per volunteer network), moving a shard elsewhere if
	// its node fails.
	place := s.nodes.newPlacement(int64(len(shards[0])))
	infos := make([]ShardInfo, len(shards))
	errs := make([]error, len(shards))
	var wg sync.WaitGroup
	for i, shard := range shards {
		hash := blake3Hex(shard)
		wg.Add(1)
		go func(i int, hash string, shard []byte) {
			defer wg.Done()
			node, err := s.uploadShard(place, hash, shard, deleteTokenHash)
			infos[i] = ShardInfo{Index: i, Hash: hash, Node: node.Public}
			errs[i] = err
		}(i, hash, shard)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			log.Printf("Shard upload error: %v", err)
			if errors.Is(err, errNoCapacity) {
				writeError(w, http.StatusServiceUnavailable, "not enough storage space available right now")
				return
			}
			writeError(w, http.StatusBadGateway, "shard upload failed")
			return
		}
	}

	writeJSON(w, http.StatusOK, SegmentUploadResponse{EncryptedSize: len(data), Shards: infos})
}

// uploadShard stores a shard on the node the placement picks, trying
// others if it fails. A node saying it's full is skipped without penalty.
func (s *Server) uploadShard(place *placement, hash string, shard []byte, deleteTokenHash string) (placeTarget, error) {
	for {
		t, err := place.pick()
		if err != nil {
			return placeTarget{}, err
		}
		status, err := putWithRetry(s.nodes.ClientFor(t.Key), t.Internal+"/shard/"+hash, shard, map[string]string{
			"X-Delete-Token-Hash": deleteTokenHash,
		})
		if err == nil {
			place.succeeded(t, hash, len(shard))
			return t, nil
		}
		log.Printf("Storage node %s failed: %v", t.Internal, err)
		place.failed(t, status == http.StatusInsufficientStorage)
	}
}

// ManifestUploadRequest carries the browser-encrypted manifest plus the
// plaintext details shown in the sender's history.
type ManifestUploadRequest struct {
	ManifestHash  string `json:"manifest_hash"` // BLAKE3(K_index) hex
	ManifestData  []byte `json:"manifest_data"` // encrypted manifest (base64 in JSON)
	AckHash       string `json:"ack_hash"`      // BLAKE3 of the manifest's ack secret
	MaxRetrievals int    `json:"max_retrievals"`
	TransferName  string `json:"transfer_name"`
	Message       string `json:"message"`
	Files         int    `json:"files"`
	TotalBytes    int64  `json:"total_bytes"`
}

func (s *Server) manifestUploadHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// The relay sees every web user as this server's address, so limit
	// uploads per client here.
	if !s.manifestUploads.Allow(clientIP(req), 1) {
		writeError(w, http.StatusTooManyRequests, "too many uploads, try again later")
		return
	}

	var body ManifestUploadRequest
	// base64 inflates by 4/3
	req.Body = http.MaxBytesReader(w, req.Body, maxManifestBytes*4/3+4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !isHexHash(body.ManifestHash) {
		writeError(w, http.StatusBadRequest, "invalid manifest hash")
		return
	}
	if !isHexHash(body.AckHash) {
		writeError(w, http.StatusBadRequest, "invalid ack hash")
		return
	}
	if len(body.ManifestData) == 0 {
		writeError(w, http.StatusBadRequest, "empty manifest")
		return
	}
	message, err := cleanMessage(body.Message)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.MaxRetrievals == 0 {
		body.MaxRetrievals = 1
	}
	if body.MaxRetrievals < 1 || body.MaxRetrievals > maxRetrievalsCap {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("max_retrievals must be 1-%d", maxRetrievalsCap))
		return
	}

	status, err := uploadManifest(s.relayURL, body.ManifestHash, body.ManifestData, body.MaxRetrievals, body.AckHash)
	if err != nil {
		log.Printf("Manifest upload error: %v", err)
		if status == http.StatusConflict {
			writeError(w, http.StatusConflict, "transfer code already in use, please retry")
			return
		}
		writeError(w, http.StatusBadGateway, "manifest upload failed")
		return
	}

	// Record the transfer in the sender's history. The code is never sent
	// here, so the server can't decrypt the transfer.
	resp := map[string]string{"status": "ok"}
	if userID, ok := s.getUserID(req); ok {
		record := &TransferRecord{
			ID:           generateToken(16),
			SenderID:     userID,
			TransferName: truncate(body.TransferName, maxNameLength),
			Message:      message,
			Files:        body.Files,
			TotalBytes:   body.TotalBytes,
			CreatedAt:    time.Now(),
		}
		s.db.SaveTransfer(record)
		resp["transfer_id"] = record.ID
	}
	writeJSON(w, http.StatusOK, resp)
}

const maxMessageChars = 2000

var errMessageTooLong = fmt.Errorf("message is longer than %d characters", maxMessageChars)

// cleanMessage validates a sender's note and drops control characters other
// than newlines and tabs, since it ends up in emails and on other people's
// screens.
func cleanMessage(msg string) (string, error) {
	if utf8.RuneCountInString(msg) > maxMessageChars {
		return "", errMessageTooLong
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, strings.TrimSpace(msg)), nil
}

// truncate shortens s to at most n bytes without splitting a UTF-8 character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// putWithRetry PUTs data to url, retrying network errors and 5xx responses.
// It returns the final status code.
func putWithRetry(client *http.Client, url string, data []byte, headers map[string]string) (int, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}
		req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			return resp.StatusCode, nil
		}
		lastErr = fmt.Errorf("%s returned %d", url, resp.StatusCode)
		// "Full" (507) won't change by retrying; nor will other client errors.
		if resp.StatusCode == http.StatusInsufficientStorage ||
			(resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests) {
			return resp.StatusCode, lastErr
		}
	}
	return 0, lastErr
}

func uploadManifest(relayURL, hash string, data []byte, maxRetrievals int, ackHash string) (int, error) {
	return putWithRetry(httpClient, relayURL+"/manifest/"+hash, data, map[string]string{
		"X-Max-Retrievals": fmt.Sprintf("%d", maxRetrievals),
		"X-Ack-Hash":       ackHash,
	})
}
