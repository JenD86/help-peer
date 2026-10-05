package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// --- Data -------------------------------------------------------------------

// InboxItem is a transfer sent to a user by username. It holds the transfer
// code, so it is deleted as soon as the transfer is received, cancelled or
// dismissed, and in any case when the transfer would expire.
type InboxItem struct {
	ID             string    `json:"id"`
	RecipientEmail string    `json:"recipient_email"`
	SenderEmail    string    `json:"sender_email"`
	SenderUsername string    `json:"sender_username,omitempty"`
	TransferName   string    `json:"transfer_name"`
	Message        string    `json:"message,omitempty"`
	Files          int       `json:"files"`
	TotalBytes     int64     `json:"total_bytes"`
	Code           string    `json:"code"`
	ManifestHash   string    `json:"manifest_hash"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// APIToken lets the CLI/SDK act as a user. Only the SHA-256 of the token is
// stored (as the map key), so a leaked tokens.json can't be used to log in.
type APIToken struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

const (
	inboxTTL         = 24 * time.Hour // matches the relay and storage TTL
	maxTokensPerUser = 20
	apiTokenPrefix   = "hp_"
	minSearchLength  = 3
	maxSearchResults = 10
)

var (
	usernameRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,29}$`)
	reservedUsernames = map[string]bool{
		"admin": true, "administrator": true, "root": true, "support": true, "help": true,
		"helppeer": true, "help-peer": true, "api": true, "system": true, "inbox": true,
		"security": true, "abuse": true, "postmaster": true, "noreply": true,
	}

	errUsernameInvalid = errors.New("usernames are 3-30 characters: lowercase letters, digits, '-' and '_', starting with a letter or digit")
	errUsernameTaken   = errors.New("that username is taken")
	errTooManyTokens   = errors.New("too many API tokens; revoke one first")
)

// normalizeUsername lowercases a username and strips a leading '@'.
func normalizeUsername(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "@"))
}

func (d *DB) GetUser(email string) (User, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, ok := d.users[email]
	if !ok {
		return User{}, false
	}
	return *u, true
}

// SetProfile sets a user's username (empty to remove it) and listing.
func (d *DB) SetProfile(email, username string, listed bool) error {
	username = normalizeUsername(username)
	if username != "" && (!usernameRe.MatchString(username) || reservedUsernames[username]) {
		return errUsernameInvalid
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if owner, ok := d.usernames[username]; ok && owner != email {
		return errUsernameTaken
	}
	u := d.getOrCreateUserLocked(email)
	if u.Username != "" {
		delete(d.usernames, u.Username)
	}
	u.Username = username
	u.Listed = listed && username != ""
	if username != "" {
		d.usernames[username] = email
	}
	d.save()
	return nil
}

// EmailForUsername resolves any username, listed or not.
func (d *DB) EmailForUsername(username string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	email, ok := d.usernames[normalizeUsername(username)]
	return email, ok
}

// SearchUsernames returns listed usernames starting with prefix.
func (d *DB) SearchUsernames(prefix string) []string {
	prefix = normalizeUsername(prefix)
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []string{}
	for name, email := range d.usernames {
		if strings.HasPrefix(name, prefix) && d.users[email].Listed {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if len(out) > maxSearchResults {
		out = out[:maxSearchResults]
	}
	return out
}

func (d *DB) AddInboxItem(item *InboxItem) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inbox[item.ID] = item
	d.save()
}

// InboxFor returns a user's unexpired inbox items, newest first.
func (d *DB) InboxFor(email string) []InboxItem {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	out := []InboxItem{}
	for _, item := range d.inbox {
		if item.RecipientEmail == email && now.Before(item.ExpiresAt) {
			out = append(out, *item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// DeleteInboxItems removes items matching the filter and returns how many.
func (d *DB) DeleteInboxItems(match func(*InboxItem) bool) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for id, item := range d.inbox {
		if match(item) {
			delete(d.inbox, id)
			n++
		}
	}
	if n > 0 {
		d.save()
	}
	return n
}

func hashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken returns the new token (shown to the user once) and its record.
func (d *DB) CreateAPIToken(email, name string) (string, APIToken, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	count := 0
	for _, t := range d.tokens {
		if t.Email == email {
			count++
		}
	}
	if count >= maxTokensPerUser {
		return "", APIToken{}, errTooManyTokens
	}
	token := apiTokenPrefix + generateToken(40)
	rec := &APIToken{ID: generateToken(12), Email: email, Name: name, CreatedAt: time.Now()}
	d.tokens[hashAPIToken(token)] = rec
	d.save()
	return token, *rec, nil
}

func (d *DB) ListAPITokens(email string) []APIToken {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []APIToken{}
	for _, t := range d.tokens {
		if t.Email == email {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (d *DB) RevokeAPIToken(id, email string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for h, t := range d.tokens {
		if t.ID == id && t.Email == email {
			delete(d.tokens, h)
			d.save()
			return true
		}
	}
	return false
}

// EmailForAPIToken authenticates a bearer token.
func (d *DB) EmailForAPIToken(token string) (string, bool) {
	if !strings.HasPrefix(token, apiTokenPrefix) {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.tokens[hashAPIToken(token)]
	if !ok {
		return "", false
	}
	// Record use, but don't rewrite the DB on every request.
	if time.Since(t.LastUsed) > time.Hour {
		t.LastUsed = time.Now()
		d.save()
	}
	return t.Email, true
}

// --- Handlers ---------------------------------------------------------------

// requireUser writes 401 and returns false if the request isn't logged in
// (by session cookie or API token).
func (s *Server) requireUser(w http.ResponseWriter, req *http.Request) (string, bool) {
	email, ok := s.getUserEmail(req)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
	}
	return email, ok
}

func profileJSON(u User) map[string]interface{} {
	return map[string]interface{}{"email": u.Email, "username": u.Username, "listed": u.Listed}
}

// profileHandler: GET returns the user's profile; POST {username, listed} updates it.
func (s *Server) profileHandler(w http.ResponseWriter, req *http.Request) {
	email, ok := s.requireUser(w, req)
	if !ok {
		return
	}
	switch req.Method {
	case http.MethodGet:
		u, _ := s.db.GetUser(email)
		u.Email = email
		writeJSON(w, http.StatusOK, profileJSON(u))
	case http.MethodPost:
		var body struct {
			Username string `json:"username"`
			Listed   bool   `json:"listed"`
		}
		req.Body = http.MaxBytesReader(w, req.Body, 4096)
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		switch err := s.db.SetProfile(email, body.Username, body.Listed); err {
		case nil:
			u, _ := s.db.GetUser(email)
			writeJSON(w, http.StatusOK, profileJSON(u))
		case errUsernameTaken:
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// userSearchHandler finds listed users by username prefix. Logged-in only,
// with a minimum query length and rate limit so the directory can't simply
// be dumped.
func (s *Server) userSearchHandler(w http.ResponseWriter, req *http.Request) {
	email, ok := s.requireUser(w, req)
	if !ok {
		return
	}
	if !s.directoryLimit.Allow(email, 1) {
		writeError(w, http.StatusTooManyRequests, "too many searches, try again later")
		return
	}
	q := normalizeUsername(req.URL.Query().Get("q"))
	if len(q) < minSearchLength {
		writeError(w, http.StatusBadRequest, "search needs at least 3 characters")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": s.db.SearchUsernames(q)})
}

// userLookupHandler checks an exact username exists (listed or not), so the
// sender can catch typos before uploading.
func (s *Server) userLookupHandler(w http.ResponseWriter, req *http.Request) {
	email, ok := s.requireUser(w, req)
	if !ok {
		return
	}
	if !s.directoryLimit.Allow(email, 1) {
		writeError(w, http.StatusTooManyRequests, "too many lookups, try again later")
		return
	}
	_, exists := s.db.EmailForUsername(req.URL.Query().Get("username"))
	writeJSON(w, http.StatusOK, map[string]bool{"exists": exists})
}

// inboxHandler: GET lists the user's inbox; DELETE /api/inbox/{id} dismisses an item.
func (s *Server) inboxHandler(w http.ResponseWriter, req *http.Request) {
	email, ok := s.requireUser(w, req)
	if !ok {
		return
	}
	switch req.Method {
	case http.MethodGet:
		items := s.db.InboxFor(email)
		// Drop items whose transfer is gone from the relay (received,
		// cancelled from the CLI, or expired) rather than showing dead codes.
		live := items[:0]
		for _, item := range items {
			if s.manifestExists(item.ManifestHash) == existsNo {
				id := item.ID
				s.db.DeleteInboxItems(func(i *InboxItem) bool { return i.ID == id })
				continue
			}
			live = append(live, item)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": live})
	case http.MethodDelete:
		id := strings.TrimPrefix(req.URL.Path, "/api/inbox/")
		n := s.db.DeleteInboxItems(func(i *InboxItem) bool { return i.ID == id && i.RecipientEmail == email })
		if n == 0 {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// inboxReceivedHandler clears the user's inbox items for a transfer they've
// just received ({manifest_hash}).
func (s *Server) inboxReceivedHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	email, ok := s.requireUser(w, req)
	if !ok {
		return
	}
	var body struct {
		ManifestHash string `json:"manifest_hash"`
	}
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil || !isHexHash(body.ManifestHash) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	n := s.db.DeleteInboxItems(func(i *InboxItem) bool {
		return i.RecipientEmail == email && i.ManifestHash == body.ManifestHash
	})
	writeJSON(w, http.StatusOK, map[string]int{"removed": n})
}

// tokensHandler manages API tokens: GET lists, POST {name} creates (the
// token is returned once), DELETE /api/tokens/{id} revokes. Requires a
// browser session: an API token can't be used to mint more tokens.
func (s *Server) tokensHandler(w http.ResponseWriter, req *http.Request) {
	email, ok := s.sessionEmail(req)
	if !ok {
		writeError(w, http.StatusUnauthorized, "log in on the website to manage API tokens")
		return
	}
	switch req.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]interface{}{"tokens": s.db.ListAPITokens(email)})
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		req.Body = http.MaxBytesReader(w, req.Body, 4096)
		json.NewDecoder(req.Body).Decode(&body)
		name := truncate(strings.TrimSpace(body.Name), 100)
		if name == "" {
			name = "CLI"
		}
		token, rec, err := s.db.CreateAPIToken(email, name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"token": token, "id": rec.ID, "name": rec.Name})
	case http.MethodDelete:
		if !s.db.RevokeAPIToken(strings.TrimPrefix(req.URL.Path, "/api/tokens/"), email) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// registerTransferHandler records a transfer sent by the CLI/SDK (which
// upload straight to the relay and storage nodes), so it appears in the
// sender's history and can be used with /api/notify.
func (s *Server) registerTransferHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	email, ok := s.requireUser(w, req)
	if !ok {
		return
	}
	var body struct {
		ManifestHash string `json:"manifest_hash"`
		TransferName string `json:"transfer_name"`
		Message      string `json:"message"`
		Files        int    `json:"files"`
		TotalBytes   int64  `json:"total_bytes"`
	}
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil || !isHexHash(body.ManifestHash) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	message, err := cleanMessage(body.Message)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Only real transfers on our relay can be registered.
	if s.manifestExists(body.ManifestHash) != existsYes {
		writeError(w, http.StatusNotFound, "transfer not found on this server's relay")
		return
	}
	record := &TransferRecord{
		ID:           generateToken(16),
		SenderEmail:  email,
		TransferName: truncate(body.TransferName, maxNameLength),
		Message:      message,
		Files:        body.Files,
		TotalBytes:   body.TotalBytes,
		CreatedAt:    time.Now(),
	}
	s.db.SaveTransfer(record)
	writeJSON(w, http.StatusOK, map[string]string{"transfer_id": record.ID})
}

// configHandler tells the CLI/SDK which relay and storage nodes this site
// uses, so a logged-in client talks to the same ones.
func (s *Server) configHandler(w http.ResponseWriter, req *http.Request) {
	all := s.nodes.AllNodes()
	nodes := make([]string, len(all))
	for i, n := range all {
		nodes[i] = n.Public
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"relay_url":     s.relayPublicURL,
		"storage_nodes": nodes,
	})
}

type existence int

const (
	existsUnknown existence = iota // relay unreachable or returned an error
	existsYes
	existsNo
)

// manifestExists asks the relay whether a transfer is still available,
// without fetching or consuming it.
func (s *Server) manifestExists(hash string) existence {
	if !isHexHash(hash) {
		return existsNo
	}
	req, err := http.NewRequest(http.MethodHead, s.relayURL+"/manifest/"+hash, nil)
	if err != nil {
		return existsUnknown
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return existsUnknown
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return existsYes
	case http.StatusNotFound:
		return existsNo
	default:
		return existsUnknown
	}
}

// relayAuthTransport adds the shared X-Relay-Token to requests bound for the
// relay. The relay then skips its per-IP rate limits for this server, which
// would otherwise lump every web user together under one address; this
// server applies its own per-user limits instead.
type relayAuthTransport struct {
	base     http.RoundTripper
	relayURL string
	token    string
}

func (t *relayAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.String(), t.relayURL+"/") {
		req = req.Clone(req.Context())
		req.Header.Set("X-Relay-Token", t.token)
	}
	return t.base.RoundTrip(req)
}
