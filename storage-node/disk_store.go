package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DiskStore stores shards on the local filesystem.
type DiskStore struct {
	mu         sync.Mutex
	dataDir    string
	shardIndex map[string]time.Time // hash -> expiry time
	usedBytes  int64
}

func NewDiskStore(dataDir string, ttlSeconds int64) (*DiskStore, error) {
	shardDir := filepath.Join(dataDir, "shards")
	if err := os.MkdirAll(shardDir, 0755); err != nil {
		return nil, err
	}

	ds := &DiskStore{
		dataDir:    dataDir,
		shardIndex: make(map[string]time.Time),
	}

	// Rebuild index from existing files
	ds.rebuildIndex(ttlSeconds)

	return ds, nil
}

func (d *DiskStore) Put(hash string, data io.Reader, ttl time.Duration) (int64, error) {
	shardPath := d.shardPath(hash)

	// Check if shard already exists (dedup)
	if info, err := os.Stat(shardPath); err == nil {
		return info.Size(), d.Touch(hash, ttl)
	}

	// Atomic write: write to temp file then rename
	if err := os.MkdirAll(filepath.Dir(shardPath), 0755); err != nil {
		return 0, err
	}

	tmpPath := shardPath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return 0, err
	}

	written, err := io.Copy(tmpFile, data)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return 0, err
	}

	if err := os.Rename(tmpPath, shardPath); err != nil {
		os.Remove(tmpPath)
		return 0, err
	}

	d.mu.Lock()
	d.usedBytes += written
	d.shardIndex[hash] = time.Now().Add(ttl)
	d.mu.Unlock()

	return written, nil
}

func (d *DiskStore) Get(hash string) (io.ReadCloser, error) {
	shardPath := d.shardPath(hash)

	d.mu.Lock()
	expiry, exists := d.shardIndex[hash]
	d.mu.Unlock()

	if !exists || time.Now().After(expiry) {
		if exists {
			d.Delete(hash)
		}
		return nil, os.ErrNotExist
	}

	return os.Open(shardPath)
}

func (d *DiskStore) Delete(hash string) error {
	shardPath := d.shardPath(hash)
	if info, err := os.Stat(shardPath); err == nil {
		os.Remove(shardPath)
		d.mu.Lock()
		d.usedBytes -= info.Size()
		if d.usedBytes < 0 {
			d.usedBytes = 0
		}
		delete(d.shardIndex, hash)
		d.mu.Unlock()
	}
	return nil
}

func (d *DiskStore) Exists(hash string) (int64, error) {
	shardPath := d.shardPath(hash)
	info, err := os.Stat(shardPath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// Touch refreshes the shard's expiry. The file mtime records when the TTL
// started, so expiries survive a restart (see rebuildIndex).
func (d *DiskStore) Touch(hash string, ttl time.Duration) error {
	now := time.Now()
	if err := os.Chtimes(d.shardPath(hash), now, now); err != nil {
		return err
	}
	d.mu.Lock()
	d.shardIndex[hash] = now.Add(ttl)
	d.mu.Unlock()
	return nil
}

func (d *DiskStore) UsedBytes() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.usedBytes
}

func (d *DiskStore) ShardCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.shardIndex)
}

func (d *DiskStore) CleanupExpired() ([]string, error) {
	now := time.Now()
	d.mu.Lock()
	var expired []string
	for hash, expiry := range d.shardIndex {
		if now.After(expiry) {
			expired = append(expired, hash)
		}
	}
	d.mu.Unlock()

	for _, hash := range expired {
		d.Delete(hash)
	}

	return expired, nil
}

func (d *DiskStore) Close() error {
	return nil
}

func (d *DiskStore) shardPath(hash string) string {
	if len(hash) < 4 {
		return filepath.Join(d.dataDir, "shards", hash)
	}
	return filepath.Join(d.dataDir, "shards", hash[:2], hash[2:4], hash)
}

func (d *DiskStore) rebuildIndex(ttlSeconds int64) {
	shardDir := filepath.Join(d.dataDir, "shards")
	var total int64
	filepath.Walk(shardDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		// Leftovers from an interrupted upload.
		if strings.HasSuffix(path, ".tmp") {
			os.Remove(path)
			return nil
		}
		total += info.Size()
		hash := filepath.Base(path)
		// Expire relative to when the shard was stored (or last touched),
		// not relative to the restart; otherwise every restart would grant
		// every shard a fresh TTL.
		d.shardIndex[hash] = info.ModTime().Add(time.Duration(ttlSeconds) * time.Second)
		return nil
	})
	d.usedBytes = total
}
