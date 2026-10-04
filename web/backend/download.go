package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/klauspost/reedsolomon"
)

// DownloadRequest is the JSON body for the download API.
type DownloadRequest struct {
	ManifestHash string `json:"manifest_hash"` // BLAKE3(K_index) hex
}

// DownloadResponse contains the encrypted manifest and segment metadata.
// The browser fetches segments one at a time via /api/download/segment.
type DownloadResponse struct {
	ManifestData []byte             `json:"manifest_data"` // encrypted manifest (browser decrypts)
	Manifest     *ManifestInfo      `json:"manifest"`
}

type ManifestInfo struct {
	Version              int          `json:"version"`
	TransferName         string       `json:"transfer_name"`
	TotalBytes           int64        `json:"total_bytes"`
	SegmentSize          int          `json:"segment_size"`
	ErasureDataShards    int          `json:"erasure_data_shards"`
	ErasureParityShards  int          `json:"erasure_parity_shards"`
	Files               []FileInfo    `json:"files"`
}

type FileInfo struct {
	Path     string         `json:"path"`
	Size     int64          `json:"size"`
	Segments []SegmentInfo  `json:"segments"`
}

type SegmentInfo struct {
	ID            string       `json:"id"`
	EncryptedSize int          `json:"encrypted_size"`
	Shards        []ShardInfo  `json:"shards"`
}

type ShardInfo struct {
	Index int    `json:"index"`
	Hash  string `json:"hash"`
	Node  string `json:"node"`
}

// SegmentDownloadRequest requests a specific segment's reconstructed encrypted data.
type SegmentDownloadRequest struct {
	Shards []ShardInfo `json:"shards"`
	DataShards int     `json:"data_shards"`
	ParityShards int   `json:"parity_shards"`
}

// SegmentDownloadResponse returns the reconstructed encrypted segment.
type SegmentDownloadResponse struct {
	EncryptedData []byte `json:"encrypted_data"`
}

func (s *Server) downloadHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body DownloadRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Fetch encrypted manifest from relay
	manifestData, err := downloadManifest(s.relayURL, body.ManifestHash)
	if err != nil {
		log.Printf("Manifest download error: %v", err)
		writeError(w, http.StatusNotFound, "manifest not found")
		return
	}

	// We can't decrypt the manifest (browser does that), but we need the manifest
	// structure to know which shards to fetch. The browser will send us the
	// decrypted manifest structure in a follow-up request for each segment.
	// For now, just return the encrypted manifest — browser decrypts and parses.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"manifest_data": manifestData,
	})
}

func (s *Server) segmentDownloadHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body SegmentDownloadRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	dataShards := body.DataShards
	if dataShards <= 0 {
		dataShards = DataShards
	}
	parityShards := body.ParityShards
	if parityShards <= 0 {
		parityShards = ParityShards
	}

	// Download shards concurrently
	shards := make([][]byte, dataShards+parityShards)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0

	for _, shardInfo := range body.Shards {
		wg.Add(1)
		go func(info ShardInfo) {
			defer wg.Done()
			data, err := downloadShard(info.Node, info.Hash)
			if err != nil {
				log.Printf("Shard download error (%s): %v", info.Hash[:12], err)
				return
			}
			mu.Lock()
			shards[info.Index] = data
			successCount++
			mu.Unlock()
		}(shardInfo)
	}

	wg.Wait()

	if successCount < dataShards {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("insufficient shards: got %d, need %d", successCount, dataShards))
		return
	}

	// Reconstruct using Reed-Solomon
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erasure init error")
		return
	}

	// Convert to [][]byte for reconstruction
	shardPtrs := make([][]byte, dataShards+parityShards)
	for i, s := range shards {
		if s != nil {
			shardPtrs[i] = s
		} else {
			shardPtrs[i] = nil
		}
	}

	if err := enc.Reconstruct(shardPtrs); err != nil {
		writeError(w, http.StatusInternalServerError, "reconstruction failed")
		return
	}

	// Join shards back into the encrypted segment
	var buf []byte
	for i := 0; i < dataShards; i++ {
		buf = append(buf, shardPtrs[i]...)
	}

	writeJSON(w, http.StatusOK, SegmentDownloadResponse{
		EncryptedData: buf,
	})
}

func downloadManifest(relayURL, hash string) ([]byte, error) {
	url := relayURL + "/manifest/" + hash
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest download returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func downloadShard(nodeURL, hash string) ([]byte, error) {
	url := nodeURL + "/shard/" + hash
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shard download returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
