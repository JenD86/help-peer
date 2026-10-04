package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Store stores shards in an S3-compatible bucket.
// Works with AWS S3, MinIO, Cloudflare R2, Backblaze B2, etc.
type S3Store struct {
	mu         sync.Mutex
	client     *s3.Client
	bucket     string
	keyPrefix  string
	shardIndex map[string]time.Time // hash -> expiry time
	usedBytes  int64
	ttl        time.Duration
}

func NewS3Store(ctx context.Context, ttl time.Duration) (*S3Store, error) {
	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		return nil, fmt.Errorf("S3_BUCKET is required for S3 backend")
	}

	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "us-east-1"
	}

	endpoint := os.Getenv("S3_ENDPOINT") // e.g., http://localhost:9000 for MinIO
	keyPrefix := os.Getenv("S3_PREFIX")
	if keyPrefix == "" {
		keyPrefix = "shards"
	}

	accessKey := os.Getenv("S3_ACCESS_KEY")
	secretKey := os.Getenv("S3_SECRET_KEY")

	var creds aws.CredentialsProvider
	if accessKey != "" && secretKey != "" {
		creds = credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
	}

	cfg, err := awscfg.LoadDefaultConfig(ctx,
		awscfg.WithRegion(region),
		awscfg.WithCredentialsProvider(creds),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = true // required for MinIO and R2
	})

	store := &S3Store{
		client:     client,
		bucket:     bucket,
		keyPrefix:  keyPrefix,
		shardIndex: make(map[string]time.Time),
		ttl:        ttl,
	}

	// Rebuild index from existing objects
	store.rebuildIndex(ctx)

	return store, nil
}

func (s *S3Store) Put(hash string, data io.Reader, ttl time.Duration) (int64, error) {
	key := s.shardKey(hash)

	// Read data into buffer to get size (S3 requires content-length or streaming)
	buf, err := io.ReadAll(data)
	if err != nil {
		return 0, fmt.Errorf("failed to read shard data: %w", err)
	}

	// Check if shard already exists (dedup)
	if _, err := s.Exists(hash); err == nil {
		return int64(len(buf)), s.Touch(hash, ttl)
	}

	_, err = s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(buf),
		ContentType: aws.String("application/octet-stream"),
		Metadata: map[string]string{
			"expires-at": time.Now().Add(ttl).Format(time.RFC3339),
		},
	})
	if err != nil {
		return 0, fmt.Errorf("S3 PutObject failed: %w", err)
	}

	s.mu.Lock()
	s.usedBytes += int64(len(buf))
	s.shardIndex[hash] = time.Now().Add(ttl)
	s.mu.Unlock()

	return int64(len(buf)), nil
}

func (s *S3Store) Get(hash string) (io.ReadCloser, error) {
	key := s.shardKey(hash)

	s.mu.Lock()
	expiry, exists := s.shardIndex[hash]
	s.mu.Unlock()

	if !exists || time.Now().After(expiry) {
		if exists {
			s.Delete(hash)
		}
		return nil, fmt.Errorf("shard not found: %s", hash)
	}

	resp, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

func (s *S3Store) Delete(hash string) error {
	key := s.shardKey(hash)

	// Get size before deleting for accounting
	size, _ := s.Exists(hash)

	_, err := s.client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.usedBytes -= size
	if s.usedBytes < 0 {
		s.usedBytes = 0
	}
	delete(s.shardIndex, hash)
	s.mu.Unlock()

	return nil
}

func (s *S3Store) Exists(hash string) (int64, error) {
	key := s.shardKey(hash)

	resp, err := s.client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return 0, err
	}

	if resp.ContentLength != nil {
		return *resp.ContentLength, nil
	}
	return 0, nil
}

// Touch refreshes the shard's expiry in the in-memory index. After a restart
// the expiry is recomputed from the object's LastModified time, so a touch
// only lasts until the node restarts.
func (s *S3Store) Touch(hash string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shardIndex[hash] = time.Now().Add(ttl)
	return nil
}

func (s *S3Store) UsedBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usedBytes
}

func (s *S3Store) ShardCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.shardIndex)
}

func (s *S3Store) CleanupExpired() ([]string, error) {
	now := time.Now()
	s.mu.Lock()
	var expired []string
	for hash, expiry := range s.shardIndex {
		if now.After(expiry) {
			expired = append(expired, hash)
		}
	}
	s.mu.Unlock()

	for _, hash := range expired {
		s.Delete(hash)
	}

	return expired, nil
}

func (s *S3Store) Close() error {
	return nil
}

func (s *S3Store) shardKey(hash string) string {
	if len(hash) < 4 {
		return fmt.Sprintf("%s/%s", s.keyPrefix, hash)
	}
	return fmt.Sprintf("%s/%s/%s/%s", s.keyPrefix, hash[:2], hash[2:4], hash)
}

func (s *S3Store) rebuildIndex(ctx context.Context) {
	prefix := s.keyPrefix + "/"
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})

	var total int64
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Printf("S3 rebuild index: failed to list objects: %v", err)
			return
		}

		for _, obj := range page.Contents {
			if obj.Key != nil {
				key := *obj.Key
				hash := key[strings.LastIndex(key, "/")+1:]
				if obj.Size != nil {
					total += *obj.Size
				}

				// Expire relative to upload time; metadata isn't available in
				// ListObjects, and resetting to now would let shards live forever.
				expiry := time.Now().Add(s.ttl)
				if obj.LastModified != nil {
					expiry = obj.LastModified.Add(s.ttl)
				}
				s.shardIndex[hash] = expiry
			}
		}
	}

	s.usedBytes = total
	log.Printf("S3 index rebuilt: %d shards, %d bytes", len(s.shardIndex), total)
}
