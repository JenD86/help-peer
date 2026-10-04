package main

import (
	"io"
	"time"
)

// ShardStore is the pluggable storage interface for shard persistence.
// Implementations include DiskStore (local filesystem) and S3Store
// (S3-compatible: AWS S3, MinIO, Cloudflare R2, Backblaze B2).
type ShardStore interface {
	// Put stores shard data with the given hash and TTL.
	// Returns the number of bytes written.
	Put(hash string, data io.Reader, ttl time.Duration) (int64, error)

	// Get retrieves shard data by hash.
	// Returns nil reader and error if not found.
	Get(hash string) (io.ReadCloser, error)

	// Delete removes a shard by hash.
	Delete(hash string) error

	// Exists checks if a shard exists and returns its size.
	Exists(hash string) (int64, error)

	// UsedBytes returns the total bytes currently stored.
	UsedBytes() int64

	// ShardCount returns the number of shards stored.
	ShardCount() int

	// CleanupExpired removes all shards past their TTL.
	// Returns the list of expired hashes that were removed.
	CleanupExpired() ([]string, error)

	// Close releases any resources.
	Close() error
}
