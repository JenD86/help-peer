package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/klauspost/reedsolomon"
	"lukechampine.com/blake3"
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

	// Upload the shards in parallel (round-robin node assignment)
	infos := make([]ShardInfo, len(shards))
	errs := make([]error, len(shards))
	var wg sync.WaitGroup
	for i, shard := range shards {
		node := s.storageNodes[i%len(s.storageNodes)]
		sum := blake3.Sum256(shard)
		hash := hex.EncodeToString(sum[:])
		infos[i] = ShardInfo{Index: i, Hash: hash, Node: node.Public}

		wg.Add(1)
		go func(i int, nodeURL, hash string, shard []byte) {
			defer wg.Done()
			errs[i] = uploadShard(nodeURL, hash, shard)
		}(i, node.Internal, hash, shard)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			log.Printf("Shard upload error: %v", err)
			writeError(w, http.StatusBadGateway, "shard upload failed")
			return
		}
	}

	writeJSON(w, http.StatusOK, SegmentUploadResponse{EncryptedSize: len(data), Shards: infos})
}

// ManifestUploadRequest carries the browser-encrypted manifest plus the
// plaintext details shown in the sender's history.
type ManifestUploadRequest struct {
	ManifestHash  string `json:"manifest_hash"` // BLAKE3(K_index) hex
	ManifestData  []byte `json:"manifest_data"` // encrypted manifest (base64 in JSON)
	MaxRetrievals int    `json:"max_retrievals"`
	TransferName  string `json:"transfer_name"`
	Files         int    `json:"files"`
	TotalBytes    int64  `json:"total_bytes"`
}

func (s *Server) manifestUploadHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
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
	if len(body.ManifestData) == 0 {
		writeError(w, http.StatusBadRequest, "empty manifest")
		return
	}
	if body.MaxRetrievals == 0 {
		body.MaxRetrievals = 1
	}
	if body.MaxRetrievals < 1 || body.MaxRetrievals > maxRetrievalsCap {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("max_retrievals must be 1-%d", maxRetrievalsCap))
		return
	}

	status, err := uploadManifest(s.relayURL, body.ManifestHash, body.ManifestData, body.MaxRetrievals)
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
	if email, ok := s.getUserEmail(req); ok {
		record := &TransferRecord{
			ID:           generateToken(16),
			SenderEmail:  email,
			TransferName: truncate(body.TransferName, maxNameLength),
			Files:        body.Files,
			TotalBytes:   body.TotalBytes,
			CreatedAt:    time.Now(),
		}
		s.db.SaveTransfer(record)
		resp["transfer_id"] = record.ID
	}
	writeJSON(w, http.StatusOK, resp)
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
func putWithRetry(url string, data []byte, headers map[string]string) (int, error) {
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
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			return resp.StatusCode, nil
		}
		lastErr = fmt.Errorf("%s returned %d", url, resp.StatusCode)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return resp.StatusCode, lastErr
		}
	}
	return 0, lastErr
}

func uploadShard(nodeURL, hash string, data []byte) error {
	_, err := putWithRetry(nodeURL+"/shard/"+hash, data, nil)
	return err
}

func uploadManifest(relayURL, hash string, data []byte, maxRetrievals int) (int, error) {
	return putWithRetry(relayURL+"/manifest/"+hash, data, map[string]string{
		"X-Max-Retrievals": fmt.Sprintf("%d", maxRetrievals),
	})
}
