package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/klauspost/reedsolomon"
	"lukechampine.com/blake3"
)

// DownloadRequest is the JSON body for the download API.
type DownloadRequest struct {
	ManifestHash string `json:"manifest_hash"` // BLAKE3(K_index) hex
}

type ShardInfo struct {
	Index int    `json:"index"`
	Hash  string `json:"hash"`
	Node  string `json:"node"`
}

// SegmentDownloadRequest requests a specific segment's reconstructed encrypted data.
type SegmentDownloadRequest struct {
	Shards        []ShardInfo `json:"shards"`
	EncryptedSize int         `json:"encrypted_size"`
	DataShards    int         `json:"data_shards"`
	ParityShards  int         `json:"parity_shards"`
}

func (s *Server) downloadHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// The relay sees every web user as this server's address, so throttle
	// code guessing per client here.
	ip := clientIP(req)
	if s.manifestMisses.Exceeded(ip) {
		writeError(w, http.StatusTooManyRequests, "too many failed lookups, try again later")
		return
	}

	var body DownloadRequest
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if !isHexHash(body.ManifestHash) {
		writeError(w, http.StatusBadRequest, "invalid manifest hash")
		return
	}

	// Fetch encrypted manifest from relay; the browser decrypts it.
	manifestData, status, err := downloadManifest(s.relayURL, body.ManifestHash)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"manifest_data": manifestData,
		})
	case status == http.StatusNotFound:
		s.manifestMisses.Hit(ip)
		writeError(w, http.StatusNotFound, "transfer not found")
	case status == http.StatusTooManyRequests:
		writeError(w, http.StatusTooManyRequests, "relay is rate limiting, try again later")
	default:
		log.Printf("Manifest download error: %v", err)
		writeError(w, http.StatusBadGateway, "relay unavailable")
	}
}

// segmentDownloadHandler fetches a segment's shards, verifies them, rebuilds
// the encrypted segment and returns it as raw bytes.
func (s *Server) segmentDownloadHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body SegmentDownloadRequest
	req.Body = http.MaxBytesReader(w, req.Body, 64*1024)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// The request comes straight from the browser, so nothing in it is trusted:
	// only fetch from our own configured storage nodes (otherwise this endpoint
	// lets anyone make the server fetch arbitrary URLs), and bounds-check every
	// index and size before it is used.
	if (body.DataShards != 0 && body.DataShards != DataShards) ||
		(body.ParityShards != 0 && body.ParityShards != ParityShards) {
		writeError(w, http.StatusBadRequest, "unsupported erasure parameters")
		return
	}
	if body.EncryptedSize <= segmentOverhead || body.EncryptedSize > maxEncryptedSegment {
		writeError(w, http.StatusBadRequest, "invalid encrypted_size")
		return
	}
	if len(body.Shards) > TotalShards {
		writeError(w, http.StatusBadRequest, "too many shards")
		return
	}

	type target struct {
		index int
		url   string
		hash  string
	}
	targets := make([]target, 0, len(body.Shards))
	seen := make(map[int]bool, len(body.Shards))
	unknown := 0
	for _, info := range body.Shards {
		if info.Index < 0 || info.Index >= TotalShards || seen[info.Index] {
			writeError(w, http.StatusBadRequest, "invalid shard index")
			return
		}
		seen[info.Index] = true
		if !isHexHash(info.Hash) {
			writeError(w, http.StatusBadRequest, "invalid shard hash")
			return
		}
		nodeURL, ok := s.nodes.InternalURL(info.Node)
		if !ok {
			// A node that has left the list (it deregistered or stopped
			// heartbeating) still appears in manifests for up to 24 hours.
			// Treat its shards as lost: any 8 of the 12 rebuild the segment.
			// We never contact an address that is not in the list.
			unknown++
			continue
		}
		targets = append(targets, target{info.Index, nodeURL + "/shard/" + info.Hash, info.Hash})
	}
	if len(targets) == 0 && unknown > 0 {
		writeError(w, http.StatusBadRequest, "unknown storage node")
		return
	}

	// Fetch shards in parallel, keeping only ones whose content matches their
	// hash and size, and stop once we have enough to rebuild.
	perShard := (body.EncryptedSize + DataShards - 1) / DataShards
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	type result struct {
		index int
		data  []byte
	}
	results := make(chan result, len(targets))
	for _, t := range targets {
		go func(t target) {
			data, err := downloadShard(ctx, t.url, int64(perShard))
			if err != nil {
				results <- result{t.index, nil}
				return
			}
			sum := blake3.Sum256(data)
			if len(data) != perShard || hex.EncodeToString(sum[:]) != t.hash {
				log.Printf("Discarding corrupt shard %s", t.hash)
				data = nil
			}
			results <- result{t.index, data}
		}(t)
	}

	shards := make([][]byte, TotalShards)
	have := 0
	for range targets {
		r := <-results
		if r.data != nil {
			shards[r.index] = r.data
			if have++; have == DataShards {
				break
			}
		}
	}
	cancel()

	if have < DataShards {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("insufficient shards: got %d, need %d", have, DataShards))
		return
	}

	enc, err := reedsolomon.New(DataShards, ParityShards)
	if err == nil {
		err = enc.ReconstructData(shards)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reconstruction failed")
		return
	}

	// Join the data shards and drop the erasure-coding padding; AES-GCM
	// authentication fails if any trailing padding is left on.
	buf := make([]byte, 0, perShard*DataShards)
	for i := 0; i < DataShards; i++ {
		buf = append(buf, shards[i]...)
	}
	buf = buf[:body.EncryptedSize]

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(buf)
}

// AckRequest confirms a completed, verified download.
type AckRequest struct {
	ManifestHash string `json:"manifest_hash"`
	AckSecret    string `json:"ack_secret"` // hex, from inside the decrypted manifest
}

func (s *Server) ackHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := clientIP(req)
	if s.manifestMisses.Exceeded(ip) {
		writeError(w, http.StatusTooManyRequests, "too many failed requests, try again later")
		return
	}

	var body AckRequest
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !isHexHash(body.ManifestHash) || !isHexHash(body.AckSecret) {
		writeError(w, http.StatusBadRequest, "invalid manifest hash or ack secret")
		return
	}

	// Not retried: a confirmation isn't idempotent.
	resp, err := httpClient.Post(s.relayURL+"/manifest/"+body.ManifestHash+"/ack",
		"text/plain", strings.NewReader(body.AckSecret))
	if err != nil {
		log.Printf("Ack error: %v", err)
		writeError(w, http.StatusBadGateway, "relay unavailable")
		return
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case http.StatusNotFound, http.StatusForbidden:
		s.manifestMisses.Hit(ip)
		writeError(w, resp.StatusCode, "transfer not found or wrong ack secret")
	case http.StatusTooManyRequests:
		writeError(w, http.StatusTooManyRequests, "relay is rate limiting, try again later")
	default:
		writeError(w, http.StatusBadGateway, fmt.Sprintf("relay returned %d", resp.StatusCode))
	}
}

func downloadManifest(relayURL, hash string) ([]byte, int, error) {
	resp, err := httpClient.Get(relayURL + "/manifest/" + hash)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("manifest download returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	return data, resp.StatusCode, err
}

func downloadShard(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shard download returned %d", resp.StatusCode)
	}
	// Read one byte past the expected size so oversized shards are detected
	// without buffering an unbounded response.
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
}
