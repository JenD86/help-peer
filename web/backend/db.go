package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	sessionTTL   = 7 * 24 * time.Hour
	magicLinkTTL = 15 * time.Minute
)

// DB is a file-based store for users, sessions, magic links, transfers,
// inbox items and API tokens.
type DB struct {
	mu        sync.Mutex
	dataDir   string
	users     map[string]*User
	sessions  map[string]*Session // session token -> session
	links     map[string]*MagicLink
	transfers map[string]*TransferRecord // record ID -> record
	inbox     map[string]*InboxItem      // item ID -> item
	tokens    map[string]*APIToken       // SHA-256 of token -> token
	usernames map[string]string          // username -> email (derived from users)
}

type User struct {
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	// Username lets others send to this user without knowing their email.
	Username string `json:"username,omitempty"`
	// Listed users appear in directory search; unlisted ones can still be
	// sent to by exact username.
	Listed bool `json:"listed,omitempty"`
}

type Session struct {
	Email   string    `json:"email"`
	Expires time.Time `json:"expires"`
}

type MagicLink struct {
	Token   string    `json:"token"`
	Email   string    `json:"email"`
	Expires time.Time `json:"expires"`
}

// TransferRecord is a sender's history entry. It deliberately has no code:
// whoever holds the code can decrypt the transfer, so the server must not
// keep it.
type TransferRecord struct {
	ID           string    `json:"id"`
	SenderEmail  string    `json:"sender_email"`
	Recipients   []string  `json:"recipients"`
	TransferName string    `json:"transfer_name"`
	Message      string    `json:"message,omitempty"` // sender's note, shown to recipients
	Files        int       `json:"files"`
	TotalBytes   int64     `json:"total_bytes"`
	CreatedAt    time.Time `json:"created_at"`
}

func NewDB(dataDir string) (*DB, error) {
	db := &DB{
		dataDir:   dataDir,
		users:     make(map[string]*User),
		sessions:  make(map[string]*Session),
		links:     make(map[string]*MagicLink),
		transfers: make(map[string]*TransferRecord),
		inbox:     make(map[string]*InboxItem),
		tokens:    make(map[string]*APIToken),
		usernames: make(map[string]string),
	}
	db.load()
	return db, nil
}

func (d *DB) load() {
	d.mu.Lock()
	defer d.mu.Unlock()

	loadJSON := func(name string, v interface{}) {
		data, err := os.ReadFile(filepath.Join(d.dataDir, name))
		if err != nil {
			return
		}
		if err := json.Unmarshal(data, v); err != nil {
			// e.g. sessions.json from before sessions had expiries; those
			// users just log in again.
			log.Printf("Ignoring unreadable %s: %v", name, err)
		}
	}
	loadJSON("users.json", &d.users)
	loadJSON("sessions.json", &d.sessions)
	loadJSON("links.json", &d.links)
	loadJSON("transfers.json", &d.transfers)
	loadJSON("inbox.json", &d.inbox)
	loadJSON("tokens.json", &d.tokens)

	for email, u := range d.users {
		if u != nil && u.Username != "" {
			d.usernames[u.Username] = email
		}
	}

	// Older versions keyed transfer records by their transfer code, which
	// let anyone with the data directory decrypt those transfers. Re-key
	// them by random ID so the codes are dropped on the next save.
	migrated := false
	for key, t := range d.transfers {
		if t.ID == "" {
			delete(d.transfers, key)
			t.ID = generateToken(16)
			d.transfers[t.ID] = t
			migrated = true
		}
	}
	d.removeExpiredLocked()
	if migrated {
		d.save()
	}
}

// save writes everything to disk. Requires d.mu.
func (d *DB) save() {
	for name, v := range map[string]interface{}{
		"users.json":     d.users,
		"sessions.json":  d.sessions,
		"links.json":     d.links,
		"transfers.json": d.transfers,
		"inbox.json":     d.inbox,
		"tokens.json":    d.tokens,
	} {
		data, err := json.Marshal(v)
		if err != nil {
			log.Printf("Failed to encode %s: %v", name, err)
			continue
		}
		if err := writeFileAtomic(filepath.Join(d.dataDir, name), data); err != nil {
			log.Printf("Failed to save %s: %v", name, err)
		}
	}
}

// writeFileAtomic replaces path so readers never see a half-written file.
// Files are private to the server's user: they hold session tokens.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// removeExpiredLocked drops expired sessions and links. Requires d.mu.
func (d *DB) removeExpiredLocked() {
	now := time.Now()
	for token, s := range d.sessions {
		if s == nil || now.After(s.Expires) {
			delete(d.sessions, token)
		}
	}
	for token, l := range d.links {
		if l == nil || now.After(l.Expires) {
			delete(d.links, token)
		}
	}
	// Inbox items hold transfer codes, so drop them as soon as the transfer
	// itself would have expired.
	for id, item := range d.inbox {
		if item == nil || now.After(item.ExpiresAt) {
			delete(d.inbox, id)
		}
	}
}

func (d *DB) GetOrCreateUser(email string) *User {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.getOrCreateUserLocked(email)
}

// getOrCreateUserLocked requires d.mu to be held. sync.Mutex is not
// reentrant, so callers that already hold the lock must use this.
func (d *DB) getOrCreateUserLocked(email string) *User {
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

	d.removeExpiredLocked()
	link := &MagicLink{
		Token:   generateToken(32),
		Email:   email,
		Expires: time.Now().Add(magicLinkTTL),
	}
	d.links[link.Token] = link
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
	delete(d.links, token)
	if time.Now().After(link.Expires) {
		d.save()
		return "", fmt.Errorf("token expired")
	}
	d.getOrCreateUserLocked(link.Email)
	d.save()
	return link.Email, nil
}

func (d *DB) CreateSession(email string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.removeExpiredLocked()
	token := generateToken(32)
	d.sessions[token] = &Session{Email: email, Expires: time.Now().Add(sessionTTL)}
	d.save()
	return token
}

func (d *DB) GetSession(token string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	s, ok := d.sessions[token]
	if !ok || time.Now().After(s.Expires) {
		return "", false
	}
	return s.Email, true
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
	d.transfers[record.ID] = record
	d.save()
}

// SetRecipients records who was notified about a transfer. It only succeeds
// for the transfer's own sender.
func (d *DB) SetRecipients(id, senderEmail string, recipients []string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.transfers[id]
	if !ok || t.SenderEmail != senderEmail {
		return false
	}
	t.Recipients = recipients
	d.save()
	return true
}

func (d *DB) GetTransfer(id string) (TransferRecord, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.transfers[id]
	if !ok {
		return TransferRecord{}, false
	}
	return *t, true
}

// GetTransfersByEmail returns the sender's transfers, newest first.
func (d *DB) GetTransfersByEmail(email string) []*TransferRecord {
	d.mu.Lock()
	defer d.mu.Unlock()

	var result []*TransferRecord
	for _, t := range d.transfers {
		if t.SenderEmail == email {
			copied := *t
			result = append(result, &copied)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}

// generateToken returns a random alphanumeric string from crypto/rand.
func generateToken(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	max := big.NewInt(int64(len(chars)))
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			// Never fall back to a predictable token.
			panic(fmt.Sprintf("crypto/rand failed: %v", err))
		}
		b[i] = chars[n.Int64()]
	}
	return string(b)
}
