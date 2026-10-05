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
	"strings"
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
	users     map[string]*User           // user ID -> user
	sessions  map[string]*Session        // session token -> session
	links     map[string]*MagicLink
	transfers map[string]*TransferRecord // record ID -> record
	inbox     map[string]*InboxItem      // item ID -> item
	tokens    map[string]*APIToken       // SHA-256 of token -> token
	usernames map[string]string          // username -> user ID
	emails    map[string]string          // email -> user ID (for magic-link login)
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// Username lets others send to this user without knowing their email.
	Username string `json:"username,omitempty"`
	// Listed users appear in directory search; unlisted ones can still be
	// sent to by exact username.
	Listed bool `json:"listed,omitempty"`
}

type Session struct {
	UserID  string    `json:"user_id"`
	Email   string    `json:"email,omitempty"` // legacy, migrated on load
	Expires time.Time `json:"expires"`
}

type MagicLink struct {
	Token   string    `json:"token"`
	Email   string    `json:"email"`
	UserID  string    `json:"user_id,omitempty"` // if set, link email to this user instead of creating new
	Expires time.Time `json:"expires"`
}

// TransferRecord is a sender's history entry. It deliberately has no code:
// whoever holds the code can decrypt the transfer, so the server must not
// keep it.
type TransferRecord struct {
	ID           string    `json:"id"`
	SenderID     string    `json:"sender_id"`
	SenderEmail  string    `json:"sender_email,omitempty"` // legacy, migrated on load
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
		emails:    make(map[string]string),
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

	// --- Migrate old email-keyed data to ID-keyed ---
	migrated := false

	// Users: old format keyed by email with no ID field.
	oldUsers := map[string]*User{}
	for key, u := range d.users {
		if u == nil {
			continue
		}
		if u.ID == "" {
			u.ID = generateToken(16)
			oldUsers[key] = u
			migrated = true
		}
		if u.Email != "" {
			d.emails[strings.ToLower(u.Email)] = u.ID
		}
		if u.Username != "" {
			d.usernames[u.Username] = u.ID
		}
	}
	// Re-key users map by ID.
	if len(oldUsers) > 0 {
		for oldKey, u := range oldUsers {
			delete(d.users, oldKey)
			d.users[u.ID] = u
		}
	}

	// Sessions: old format has Email but no UserID.
	for _, s := range d.sessions {
		if s == nil {
			continue
		}
		if s.UserID == "" && s.Email != "" {
			if uid, ok := d.emails[strings.ToLower(s.Email)]; ok {
				s.UserID = uid
				s.Email = ""
				migrated = true
			}
		}
	}

	// Transfers: old format has SenderEmail but no SenderID.
	for _, t := range d.transfers {
		if t == nil {
			continue
		}
		if t.SenderID == "" && t.SenderEmail != "" {
			if uid, ok := d.emails[strings.ToLower(t.SenderEmail)]; ok {
				t.SenderID = uid
				t.SenderEmail = ""
				migrated = true
			}
		}
	}

	// Inbox: old format has RecipientEmail/SenderEmail but no IDs.
	for _, item := range d.inbox {
		if item == nil {
			continue
		}
		if item.RecipientID == "" && item.RecipientEmail != "" {
			if uid, ok := d.emails[strings.ToLower(item.RecipientEmail)]; ok {
				item.RecipientID = uid
				item.RecipientEmail = ""
				migrated = true
			}
		}
		if item.SenderID == "" && item.SenderEmail != "" {
			if uid, ok := d.emails[strings.ToLower(item.SenderEmail)]; ok {
				item.SenderID = uid
				item.SenderEmail = ""
				migrated = true
			}
		}
	}

	// API tokens: old format has Email but no UserID.
	for _, tok := range d.tokens {
		if tok == nil {
			continue
		}
		if tok.UserID == "" && tok.Email != "" {
			if uid, ok := d.emails[strings.ToLower(tok.Email)]; ok {
				tok.UserID = uid
				tok.Email = ""
				migrated = true
			}
		}
	}

	// Older versions keyed transfer records by their transfer code, which
	// let anyone with the data directory decrypt those transfers. Re-key
	// them by random ID so the codes are dropped on the next save.
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

func (d *DB) GetOrCreateUserByEmail(email string) *User {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.getOrCreateUserByEmailLocked(email)
}

// getOrCreateUserByEmailLocked requires d.mu to be held.
func (d *DB) getOrCreateUserByEmailLocked(email string) *User {
	email = strings.ToLower(email)
	if uid, ok := d.emails[email]; ok {
		return d.users[uid]
	}
	u := &User{
		ID:        generateToken(16),
		Email:     email,
		CreatedAt: time.Now(),
	}
	d.users[u.ID] = u
	d.emails[email] = u.ID
	d.save()
	return u
}

// CreateUser creates a new user with no email (just an ID).
func (d *DB) CreateUser() *User {
	d.mu.Lock()
	defer d.mu.Unlock()
	u := &User{
		ID:        generateToken(16),
		CreatedAt: time.Now(),
	}
	d.users[u.ID] = u
	d.save()
	return u
}

// GetUserByEmail looks up a user by their email address.
func (d *DB) GetUserByEmail(email string) (User, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	uid, ok := d.emails[strings.ToLower(email)]
	if !ok {
		return User{}, false
	}
	u, ok := d.users[uid]
	if !ok {
		return User{}, false
	}
	return *u, true
}

// LinkEmail associates an email address with an existing user account.
func (d *DB) LinkEmail(userID, email string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	email = strings.ToLower(email)
	if existingUID, ok := d.emails[email]; ok && existingUID != userID {
		return fmt.Errorf("email already linked to another account")
	}
	u, ok := d.users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}
	// Remove old email mapping if any.
	if u.Email != "" {
		delete(d.emails, u.Email)
	}
	u.Email = email
	d.emails[email] = userID
	d.save()
	return nil
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

// CreateMagicLinkForUser creates a magic link that, when verified, links
// the email to the given user ID instead of creating a new user.
func (d *DB) CreateMagicLinkForUser(email, userID string) (*MagicLink, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.removeExpiredLocked()
	link := &MagicLink{
		Token:   generateToken(32),
		Email:   email,
		UserID:  userID,
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
	var userID string
	if link.UserID != "" {
		// Link email to an existing user account.
		u, ok := d.users[link.UserID]
		if !ok {
			d.save()
			return "", fmt.Errorf("user not found")
		}
		email := strings.ToLower(link.Email)
		if u.Email != "" {
			delete(d.emails, u.Email)
		}
		u.Email = email
		d.emails[email] = u.ID
		userID = u.ID
	} else {
		u := d.getOrCreateUserByEmailLocked(link.Email)
		userID = u.ID
	}
	d.save()
	return userID, nil
}

func (d *DB) CreateSession(userID string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.removeExpiredLocked()
	token := generateToken(32)
	d.sessions[token] = &Session{UserID: userID, Expires: time.Now().Add(sessionTTL)}
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
	return s.UserID, true
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
func (d *DB) SetRecipients(id, senderID string, recipients []string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.transfers[id]
	if !ok || t.SenderID != senderID {
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

// GetTransfersByUserID returns the sender's transfers, newest first.
func (d *DB) GetTransfersByUserID(userID string) []*TransferRecord {
	d.mu.Lock()
	defer d.mu.Unlock()

	var result []*TransferRecord
	for _, t := range d.transfers {
		if t.SenderID == userID {
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
