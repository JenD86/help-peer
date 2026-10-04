package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DB is a file-based store for users, sessions, magic links, and transfers.
type DB struct {
	mu       sync.Mutex
	dataDir  string
	users    map[string]*User
	sessions map[string]string // session token -> email
	links    map[string]*MagicLink
	transfers map[string]*TransferRecord
}

type User struct {
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type MagicLink struct {
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	Expires   time.Time `json:"expires"`
}

type TransferRecord struct {
	Code        string    `json:"code"`
	SenderEmail string    `json:"sender_email"`
	Recipients  []string  `json:"recipients"`
	TransferName string  `json:"transfer_name"`
	Files       int       `json:"files"`
	TotalBytes   int64     `json:"total_bytes"`
	CreatedAt   time.Time `json:"created_at"`
}

func NewDB(dataDir string) (*DB, error) {
	db := &DB{
		dataDir:   dataDir,
		users:     make(map[string]*User),
		sessions:  make(map[string]string),
		links:     make(map[string]*MagicLink),
		transfers: make(map[string]*TransferRecord),
	}
	db.load()
	return db, nil
}

func (d *DB) load() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if data, err := os.ReadFile(filepath.Join(d.dataDir, "users.json")); err == nil {
		json.Unmarshal(data, &d.users)
	}
	if data, err := os.ReadFile(filepath.Join(d.dataDir, "sessions.json")); err == nil {
		json.Unmarshal(data, &d.sessions)
	}
	if data, err := os.ReadFile(filepath.Join(d.dataDir, "links.json")); err == nil {
		json.Unmarshal(data, &d.links)
	}
	if data, err := os.ReadFile(filepath.Join(d.dataDir, "transfers.json")); err == nil {
		json.Unmarshal(data, &d.transfers)
	}
}

func (d *DB) save() {
	if data, err := json.Marshal(d.users); err == nil {
		os.WriteFile(filepath.Join(d.dataDir, "users.json"), data, 0644)
	}
	if data, err := json.Marshal(d.sessions); err == nil {
		os.WriteFile(filepath.Join(d.dataDir, "sessions.json"), data, 0644)
	}
	if data, err := json.Marshal(d.links); err == nil {
		os.WriteFile(filepath.Join(d.dataDir, "links.json"), data, 0644)
	}
	if data, err := json.Marshal(d.transfers); err == nil {
		os.WriteFile(filepath.Join(d.dataDir, "transfers.json"), data, 0644)
	}
}

func (d *DB) GetOrCreateUser(email string) *User {
	d.mu.Lock()
	defer d.mu.Unlock()

	if u, ok := d.users[email]; ok {
		return u
	}
	u := &User{
		Email:     email,
		CreatedAt: time.Now(),
	}
	d.users[email] = u
	d.save()
	return u
}

func (d *DB) CreateMagicLink(email string) (*MagicLink, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	token := generateToken(32)
	link := &MagicLink{
		Token:   token,
		Email:   email,
		Expires: time.Now().Add(15 * time.Minute),
	}
	d.links[token] = link
	d.save()
	return link, nil
}

func (d *DB) VerifyMagicLink(token string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	link, ok := d.links[token]
	if !ok {
		return "", fmt.Errorf("invalid token")
	}
	if time.Now().After(link.Expires) {
		delete(d.links, token)
		d.save()
		return "", fmt.Errorf("token expired")
	}
	delete(d.links, token)
	d.GetOrCreateUser(link.Email)
	d.save()
	return link.Email, nil
}

func (d *DB) CreateSession(email string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	token := generateToken(32)
	d.sessions[token] = email
	d.save()
	return token
}

func (d *DB) GetSession(token string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	email, ok := d.sessions[token]
	return email, ok
}

func (d *DB) DeleteSession(token string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sessions, token)
	d.save()
}

func (d *DB) SaveTransfer(record *TransferRecord) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.transfers[record.Code] = record
	d.save()
}

func (d *DB) GetTransfersByEmail(email string) []*TransferRecord {
	d.mu.Lock()
	defer d.mu.Unlock()

	var result []*TransferRecord
	for _, t := range d.transfers {
		if t.SenderEmail == email {
			result = append(result, t)
		}
	}
	return result
}

func generateToken(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = chars[secureRandInt()%len(chars)]
	}
	return string(b)
}

func secureRandInt() int {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return int(time.Now().UnixNano() % 256)
	}
	return int(b[0])
}
