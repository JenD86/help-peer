package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

// Storage nodes come in two kinds:
//   - static nodes, configured by the operator (STORAGE_NODES), trusted;
//   - volunteer nodes, which register themselves. Anyone may run one, so the
//     registry checks who controls each node, how much space it really has,
//     whether it keeps what it's given, and that no one network holds enough
//     of any segment to lose it.

const (
	nodeDownFor         = time.Minute        // skip a node this long after it fails
	nodeFullFor         = 5 * time.Minute    // or after it says it's full (until its next heartbeat)
	heartbeatStale      = 5 * time.Minute    // volunteer nodes heartbeat every 2 minutes
	forgetInactiveAfter = 7 * 24 * time.Hour // keep history this long so leaving doesn't reset it
	maxClockSkew        = 5 * time.Minute    // accepted age of a signed node request

	// At most this many of a segment's 12 shards go to volunteer nodes in
	// one network (IPv4 /24, IPv6 /48). Losing a segment takes 5, so one
	// operator needs machines in 3+ networks to cause any harm.
	maxShardsPerNetwork = 2

	auditSampleRate = 20 // spot-check 1 in N shards placed on volunteer nodes
	auditWindow     = 20 // recent results kept per node
	auditFailLimit  = 3  // failures within the window that suspend a node
	suspendFor      = 24 * time.Hour

	registrationTestBytes = 1 << 20 // written and read back when a node registers
)

// dynNode is a volunteer node. Entries outlive the node's registration (as
// inactive) so that leaving and rejoining doesn't wipe its audit record.
type dynNode struct {
	ID             string    `json:"id"` // "ed25519:<public key>"
	Public         string    `json:"public_url"`
	Network        string    `json:"network"`
	Active         bool      `json:"active"`
	Banned         bool      `json:"banned,omitempty"`
	Capacity       int64     `json:"capacity_bytes"`
	Available      int64     `json:"available_bytes"` // as of its last heartbeat
	LastSeen       time.Time `json:"last_seen"`
	LastTimestamp  int64     `json:"last_timestamp"` // newest signed request, against replays
	Audits         []bool    `json:"audits,omitempty"`
	AuditsPassed   int       `json:"audits_passed"`
	AuditsFailed   int       `json:"audits_failed"`
	SuspendedUntil time.Time `json:"suspended_until,omitempty"`

	placed    int64     // bytes placed here since its last heartbeat
	fullUntil time.Time // it refused data as full
	downUntil time.Time // it failed a request
}

// auditTask is a shard to fetch back from a volunteer node later.
type auditTask struct {
	NodeID   string
	Hash     string
	Size     int
	Due      time.Time
	Expires  time.Time
	Attempts int
}

type nodeRegistry struct {
	mu           sync.Mutex
	static       []StorageNode
	staticDown   map[string]time.Time // internal URL -> skip until
	staticFull   map[string]time.Time
	nodes        map[string]*dynNode // node ID -> node
	byURL        map[string]string   // active public URL -> node ID
	audits       []auditTask
	rotation     int
	dataDir      string
	allowPrivate bool
	client       *http.Client // for volunteer nodes

	// Overridable in tests.
	resolve   func(host string) ([]net.IP, error)
	networkOf func(ip net.IP, nodeURL string) string
	sample    func() bool // whether to audit a placed shard
}

func newNodeRegistry(static []StorageNode, dataDir string, allowPrivate bool) *nodeRegistry {
	r := &nodeRegistry{
		static:       static,
		staticDown:   map[string]time.Time{},
		staticFull:   map[string]time.Time{},
		nodes:        map[string]*dynNode{},
		byURL:        map[string]string{},
		dataDir:      dataDir,
		allowPrivate: allowPrivate,
		client:       newNodeClient(allowPrivate, 5*time.Minute),
		resolve:      func(host string) ([]net.IP, error) { return net.LookupIP(host) },
		sample:       func() bool { return mrand.Intn(auditSampleRate) == 0 },
	}
	r.networkOf = func(ip net.IP, nodeURL string) string {
		if !isPublicIP(ip) {
			// Private addresses are only allowed for local testing
			// (ALLOW_PRIVATE_NODES); treat each node as its own network.
			return "local:" + nodeURL
		}
		if ip4 := ip.To4(); ip4 != nil {
			return (&net.IPNet{IP: ip4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
		}
		return (&net.IPNet{IP: ip.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String()
	}
	r.load()
	return r
}

// SetAllowPrivate allows volunteer nodes on private addresses (LAN testing).
func (r *nodeRegistry) SetAllowPrivate(allow bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowPrivate = allow
	r.client = newNodeClient(allow, 5*time.Minute)
}

// --- Lookups ---------------------------------------------------------------

func staticKey(n StorageNode) string { return "static:" + n.Internal }

// InternalURL maps a node URL from a manifest to the URL this backend uses
// to reach it, plus a key identifying the node. Only known nodes are
// allowed: the URL comes from the browser, and fetching arbitrary URLs
// would let anyone use the server to reach internal services.
func (r *nodeRegistry) InternalURL(node string) (internal, key string, ok bool) {
	node = strings.TrimRight(node, "/")
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.static {
		if n.Public == node || n.Internal == node {
			return n.Internal, staticKey(n), true
		}
	}
	if id, ok := r.byURL[node]; ok && !r.nodes[id].Banned {
		return node, id, true
	}
	return "", "", false
}

// ClientFor returns the HTTP client to use for a node: volunteer nodes get
// the client that refuses internal addresses.
func (r *nodeRegistry) ClientFor(key string) *http.Client {
	if strings.HasPrefix(key, "static:") {
		return httpClient
	}
	return r.client
}

// isDynamic reports whether key is a volunteer node's ID.
func isDynamic(key string) bool { return strings.HasPrefix(key, nodeIDPrefix) }

// ConfigNodes lists storage nodes for CLI/SDK clients, which spread shards
// over the list round-robin and can't apply the per-network limit. So the
// list has at most one volunteer node per network, and volunteers are only
// included once there are enough nodes that each gets no more than 2 of a
// segment's 12 shards.
func (r *nodeRegistry) ConfigNodes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, n := range r.static {
		out = append(out, n.Public)
	}
	best := map[string]*dynNode{}
	for _, n := range r.nodes {
		if r.usableLocked(n) && n.Available >= 64<<20 {
			if b, ok := best[n.Network]; !ok || n.Available > b.Available {
				best[n.Network] = n
			}
		}
	}
	var vols []string
	for _, n := range best {
		vols = append(vols, n.Public)
	}
	sort.Strings(vols)
	if len(out) == 0 || len(out)+len(vols) >= 6 {
		out = append(out, vols...)
	}
	return out
}

// usableLocked reports whether a volunteer node can be given new data
// (ignoring free space). Requires r.mu.
func (r *nodeRegistry) usableLocked(n *dynNode) bool {
	now := time.Now()
	return n.Active && !n.Banned && now.After(n.SuspendedUntil) &&
		now.Sub(n.LastSeen) < heartbeatStale && now.After(n.downUntil) && now.After(n.fullUntil)
}

// --- Placement ---------------------------------------------------------------

// placeTarget is a node chosen to store one shard.
type placeTarget struct {
	Key      string // static key or volunteer node ID
	Internal string
	Public   string
	Network  string // volunteer nodes only
}

// placement assigns one segment's shards to nodes: spread evenly, at most
// maxShardsPerNetwork per volunteer network, and only to volunteers with
// room for the shard.
type placement struct {
	mu       sync.Mutex
	reg      *nodeRegistry
	size     int64
	cands    []placeTarget
	start    int
	perNode  map[string]int
	perNet   map[string]int
	excluded map[string]bool
}

var errNoCapacity = errors.New("not enough storage nodes with free space")

func (r *nodeRegistry) newPlacement(shardSize int64) *placement {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	p := &placement{
		reg: r, size: shardSize,
		perNode: map[string]int{}, perNet: map[string]int{},
		excluded: map[string]bool{},
	}
	for _, n := range r.static {
		if now.After(r.staticDown[n.Internal]) && now.After(r.staticFull[n.Internal]) {
			p.cands = append(p.cands, placeTarget{Key: staticKey(n), Internal: n.Internal, Public: n.Public})
		}
	}
	ids := make([]string, 0, len(r.nodes))
	for id, n := range r.nodes {
		if r.usableLocked(n) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids) // stable order; rotation spreads the load
	for _, id := range ids {
		n := r.nodes[id]
		p.cands = append(p.cands, placeTarget{Key: id, Internal: n.Public, Public: n.Public, Network: n.Network})
	}
	if len(p.cands) > 0 {
		p.start = r.rotation % len(p.cands)
		r.rotation++
	}
	return p
}

// pick chooses the node for the next shard.
func (p *placement) pick() (placeTarget, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		best := -1
		for k := range p.cands {
			i := (p.start + k) % len(p.cands)
			c := p.cands[i]
			if p.excluded[c.Key] || (c.Network != "" && p.perNet[c.Network] >= maxShardsPerNetwork) {
				continue
			}
			if best == -1 || p.perNode[c.Key] < p.perNode[p.cands[best].Key] {
				best = i
			}
		}
		if best == -1 {
			return placeTarget{}, errNoCapacity
		}
		c := p.cands[best]
		if c.Network != "" && !p.reg.reserve(c.Key, p.size) {
			p.excluded[c.Key] = true // no room for this segment's shards
			continue
		}
		p.perNode[c.Key]++
		if c.Network != "" {
			p.perNet[c.Network]++
		}
		return c, nil
	}
}

// failed records that storing a shard on t failed. full means the node said
// it has no room (HTTP 507): that's normal and never counts against it.
func (p *placement) failed(t placeTarget, full bool) {
	p.mu.Lock()
	p.perNode[t.Key]--
	p.excluded[t.Key] = true
	if t.Network != "" {
		p.perNet[t.Network]--
		p.reg.release(t.Key, p.size)
	}
	p.mu.Unlock()
	p.reg.markUnavailable(t.Key, full)
}

// succeeded records a stored shard, sometimes scheduling a spot-check.
func (p *placement) succeeded(t placeTarget, hash string, size int) {
	if t.Network == "" || !p.reg.sample() {
		return
	}
	now := time.Now()
	// Check at a random time while the shard should still be there (nodes
	// keep shards 24 hours).
	delay := 10*time.Minute + time.Duration(mrand.Int63n(int64(19*time.Hour)))
	p.reg.mu.Lock()
	if len(p.reg.audits) < 100000 {
		p.reg.audits = append(p.reg.audits, auditTask{
			NodeID: t.Key, Hash: hash, Size: size, Due: now.Add(delay), Expires: now.Add(23 * time.Hour),
		})
	}
	p.reg.mu.Unlock()
}

// reserve counts bytes about to be sent to a volunteer node against its
// last reported free space. It fails if they won't fit.
func (r *nodeRegistry) reserve(id string, n int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	node, ok := r.nodes[id]
	if !ok || node.Available-node.placed < n {
		return false
	}
	node.placed += n
	return true
}

func (r *nodeRegistry) release(id string, n int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if node, ok := r.nodes[id]; ok {
		node.placed -= n
	}
}

// markUnavailable skips a node for a while: briefly after an error, or
// until its next heartbeat after it said it was full.
func (r *nodeRegistry) markUnavailable(key string, full bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	until := time.Now().Add(nodeDownFor)
	if full {
		until = time.Now().Add(nodeFullFor)
	}
	if strings.HasPrefix(key, "static:") {
		internal := strings.TrimPrefix(key, "static:")
		if full {
			r.staticFull[internal] = until
		} else {
			r.staticDown[internal] = until
		}
		return
	}
	if n, ok := r.nodes[key]; ok {
		if full {
			n.fullUntil = until
		} else {
			n.downUntil = until
		}
	}
}

// --- Audits ------------------------------------------------------------------

// RecordAudit records whether a volunteer node returned a shard it had
// accepted intact. Repeated losses suspend it from receiving new data. Only
// data the node accepted (and that hasn't expired) is ever audited, so
// being full or offline is never counted as losing data.
func (r *nodeRegistry) RecordAudit(id string, ok bool) {
	if !isDynamic(id) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n, exists := r.nodes[id]
	if !exists {
		return
	}
	n.Audits = append(n.Audits, ok)
	if len(n.Audits) > auditWindow {
		n.Audits = n.Audits[len(n.Audits)-auditWindow:]
	}
	if ok {
		n.AuditsPassed++
		return
	}
	n.AuditsFailed++
	failures := 0
	for _, a := range n.Audits {
		if !a {
			failures++
		}
	}
	if failures >= auditFailLimit {
		n.SuspendedUntil = time.Now().Add(suspendFor)
		n.Audits = nil
		log.Printf("Storage node %s (%s) suspended for %s: %d recent audit failures", n.Public, id, suspendFor, failures)
	}
	r.saveLocked()
}

// runDueAudits fetches back the spot-check shards that are due.
func (r *nodeRegistry) runDueAudits() {
	now := time.Now()
	r.mu.Lock()
	var due, later []auditTask
	for _, t := range r.audits {
		switch {
		case now.After(t.Expires):
			// Too late to check fairly; drop it.
		case now.After(t.Due) && len(due) < 16:
			due = append(due, t)
		default:
			later = append(later, t)
		}
	}
	r.audits = later
	r.mu.Unlock()

	for _, t := range due {
		r.mu.Lock()
		n, ok := r.nodes[t.NodeID]
		active := ok && n.Active && !n.Banned
		url := ""
		if active {
			url = n.Public + "/shard/" + t.Hash
		}
		r.mu.Unlock()
		if !active {
			continue // left the network; its data is already treated as lost
		}

		data, status, err := fetch(r.client, url, int64(t.Size))
		switch {
		case err != nil || status >= 500:
			// Unreachable right now: try again later rather than call it lost.
			t.Attempts++
			if t.Attempts < 3 {
				t.Due = time.Now().Add(30 * time.Minute)
				r.mu.Lock()
				r.audits = append(r.audits, t)
				r.mu.Unlock()
			} else {
				r.RecordAudit(t.NodeID, false)
			}
		case status == http.StatusOK && len(data) == t.Size && blake3Hex(data) == t.Hash:
			r.RecordAudit(t.NodeID, true)
		default:
			r.RecordAudit(t.NodeID, false) // missing or corrupt
		}
	}
}

func fetch(client *http.Client, url string, maxBytes int64) ([]byte, int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	return data, resp.StatusCode, err
}

func blake3Hex(data []byte) string {
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// --- Registration ----------------------------------------------------------

const nodeIDPrefix = "ed25519:"

// nodeRequest is the signed body of a registration, heartbeat or
// deregistration (protocol/SPEC.md §2.5).
type nodeRequest struct {
	Action         string `json:"action"`
	NodeID         string `json:"node_id"`
	URL            string `json:"url"`
	CapacityBytes  int64  `json:"capacity_bytes"`
	AvailableBytes int64  `json:"available_bytes"`
	Timestamp      int64  `json:"timestamp"` // unix milliseconds
}

// verifyNodeRequest checks a node request's signature against the key in
// its node_id, and that it's recent.
func verifyNodeRequest(body []byte, sigHeader, action string) (nodeRequest, error) {
	var r nodeRequest
	if err := json.Unmarshal(body, &r); err != nil {
		return r, errors.New("invalid request")
	}
	if r.Action != action {
		return r, fmt.Errorf("expected action %q", action)
	}
	if !strings.HasPrefix(r.NodeID, nodeIDPrefix) {
		return r, errors.New("invalid node_id")
	}
	pub, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(r.NodeID, nodeIDPrefix))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return r, errors.New("invalid node_id")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigHeader)
	if err != nil || !ed25519.Verify(pub, body, sig) {
		return r, errors.New("invalid signature")
	}
	age := time.Since(time.UnixMilli(r.Timestamp))
	if age > maxClockSkew || age < -maxClockSkew {
		return r, errors.New("request timestamp too old or in the future (check the node's clock)")
	}
	return r, nil
}

// canonicalNodeURL validates a node's public URL: http(s), a host and
// optional port, nothing else.
func canonicalNodeURL(raw string) (string, *url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, errors.New("url must be http(s)://host[:port] with no path")
	}
	return u.Scheme + "://" + u.Host, u, nil
}

// registerError carries the HTTP status to report.
type registerError struct {
	status int
	msg    string
}

func (e *registerError) Error() string { return e.msg }

func regErr(status int, format string, args ...interface{}) error {
	return &registerError{status, fmt.Sprintf(format, args...)}
}

// Register handles a signed registration or heartbeat. A node's first
// registration (or a change of URL) proves that the URL serves this node's
// key and really stores data; heartbeats just refresh its free space.
func (r *nodeRegistry) Register(req nodeRequest) error {
	nodeURL, parsed, err := canonicalNodeURL(req.URL)
	if err != nil {
		return regErr(http.StatusBadRequest, "%v", err)
	}

	r.mu.Lock()
	n := r.nodes[req.NodeID]
	if n != nil && n.Banned {
		r.mu.Unlock()
		return regErr(http.StatusForbidden, "this node has been banned by the operator")
	}
	if n != nil && req.Timestamp <= n.LastTimestamp {
		r.mu.Unlock()
		return regErr(http.StatusConflict, "stale or replayed request")
	}
	needsCheck := n == nil || !n.Active || n.Public != nodeURL
	network := ""
	if n != nil {
		network = n.Network
	}
	r.mu.Unlock()

	if needsCheck {
		network, err = r.checkNewNode(nodeURL, parsed.Hostname(), req.NodeID)
		if err != nil {
			return err
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if n = r.nodes[req.NodeID]; n == nil {
		n = &dynNode{ID: req.NodeID}
		r.nodes[req.NodeID] = n
	}
	if req.Timestamp <= n.LastTimestamp { // a concurrent request got here first
		return regErr(http.StatusConflict, "stale or replayed request")
	}
	if needsCheck {
		// The URL now demonstrably serves this key, so any other node
		// registered at it has lost it.
		if other, ok := r.byURL[nodeURL]; ok && other != req.NodeID {
			r.nodes[other].Active = false
		}
		if n.Active && n.Public != nodeURL {
			delete(r.byURL, n.Public)
		}
		n.Public, n.Network = nodeURL, network
		r.byURL[nodeURL] = req.NodeID
		log.Printf("Storage node registered: %s (%s, network %s)", nodeURL, req.NodeID, network)
	}
	n.Active = true
	n.Capacity = req.CapacityBytes
	n.Available = req.AvailableBytes
	n.LastSeen = time.Now()
	n.LastTimestamp = req.Timestamp
	n.placed = 0              // its report now includes what we've sent
	n.fullUntil = time.Time{} // and says whether it has room again
	r.saveLocked()
	return nil
}

// checkNewNode verifies a node before it's listed: its address must be
// public (unless ALLOW_PRIVATE_NODES), its /health must report the key that
// signed the request (so nobody can register someone else's server, or an
// internal service), and it must store a test shard and give it back.
// Returns the node's network for the spread limit.
func (r *nodeRegistry) checkNewNode(nodeURL, host, id string) (string, error) {
	ips, err := r.resolve(host)
	if err != nil || len(ips) == 0 {
		return "", regErr(http.StatusBadRequest, "cannot resolve %s", host)
	}
	for _, ip := range ips {
		if !r.allowPrivate && !isPublicIP(ip) {
			return "", regErr(http.StatusBadRequest, "%s resolves to a private or internal address", host)
		}
	}
	network := r.networkOf(ips[0], nodeURL)

	resp, err := r.client.Get(nodeURL + "/health")
	if err != nil {
		return "", regErr(http.StatusBadGateway, "could not reach node: %v", err)
	}
	var health struct {
		NodeID string `json:"node_id"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&health)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || health.NodeID != id {
		return "", regErr(http.StatusBadRequest, "%s/health does not identify as this node", nodeURL)
	}

	if err := storageTest(r.client, nodeURL); err != nil {
		return "", regErr(http.StatusBadGateway, "storage test failed: %v", err)
	}
	return network, nil
}

// storageTest writes a random shard (kept 10 minutes at most), reads it
// back and deletes it.
func storageTest(client *http.Client, nodeURL string) error {
	data := make([]byte, registrationTestBytes)
	token := make([]byte, 32)
	rand.Read(data)
	rand.Read(token)
	hash := blake3Hex(data)
	shardURL := nodeURL + "/shard/" + hash

	req, _ := http.NewRequest(http.MethodPut, shardURL, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Delete-Token-Hash", blake3Hex(token))
	req.Header.Set("X-TTL-Seconds", "600")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusInsufficientStorage {
		return errors.New("node reports it is full")
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("storing returned %d", resp.StatusCode)
	}

	got, status, err := fetch(client, shardURL, int64(len(data)))
	if err != nil || status != http.StatusOK || !bytes.Equal(got, data) {
		return errors.New("node did not return the data it stored")
	}

	req, _ = http.NewRequest(http.MethodDelete, shardURL, nil)
	req.Header.Set("X-Delete-Token", hex.EncodeToString(token))
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
	return nil
}

// Deregister handles a signed deregistration: only the node's own key can
// remove it.
func (r *nodeRegistry) Deregister(req nodeRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[req.NodeID]
	if !ok || !n.Active {
		return nil
	}
	if req.Timestamp <= n.LastTimestamp {
		return regErr(http.StatusConflict, "stale or replayed request")
	}
	n.LastTimestamp = req.Timestamp
	n.Active = false
	delete(r.byURL, n.Public)
	log.Printf("Storage node deregistered: %s (%s)", n.Public, n.ID)
	r.saveLocked()
	return nil
}

// --- Operator controls -------------------------------------------------------

// SetBanned bans or unbans a volunteer node. Banned nodes are removed and
// can't register again with the same key.
func (r *nodeRegistry) SetBanned(id string, banned bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return false
	}
	n.Banned = banned
	if banned {
		n.Active = false
		delete(r.byURL, n.Public)
	}
	r.saveLocked()
	return true
}

// Reinstate lifts a suspension and clears recent audit failures.
func (r *nodeRegistry) Reinstate(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return false
	}
	n.SuspendedUntil = time.Time{}
	n.Audits = nil
	r.saveLocked()
	return true
}

// Snapshot lists all nodes for the operator.
func (r *nodeRegistry) Snapshot() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	static := make([]map[string]string, len(r.static))
	for i, n := range r.static {
		static[i] = map[string]string{"internal_url": n.Internal, "public_url": n.Public}
	}
	vols := make([]dynNode, 0, len(r.nodes))
	for _, n := range r.nodes {
		vols = append(vols, *n)
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Public < vols[j].Public })
	return map[string]interface{}{"static": static, "volunteers": vols, "pending_audits": len(r.audits)}
}

// --- Persistence and maintenance --------------------------------------------

func (r *nodeRegistry) load() {
	data, err := os.ReadFile(filepath.Join(r.dataDir, "nodes.json"))
	if err != nil {
		return
	}
	var state struct {
		Nodes []*dynNode `json:"nodes"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		// Includes the unsigned registrations of older versions, whose
		// nodes must re-register with a key anyway.
		log.Printf("Ignoring unreadable nodes.json: %v", err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range state.Nodes {
		if n == nil || !strings.HasPrefix(n.ID, nodeIDPrefix) {
			continue
		}
		r.nodes[n.ID] = n
		if n.Active && !n.Banned {
			r.byURL[n.Public] = n.ID
		}
	}
}

func (r *nodeRegistry) saveLocked() {
	nodes := make([]*dynNode, 0, len(r.nodes))
	for _, n := range r.nodes {
		nodes = append(nodes, n)
	}
	data, err := json.Marshal(map[string]interface{}{"nodes": nodes})
	if err != nil {
		log.Printf("Failed to encode nodes.json: %v", err)
		return
	}
	if err := writeFileAtomic(filepath.Join(r.dataDir, "nodes.json"), data); err != nil {
		log.Printf("Failed to save nodes.json: %v", err)
	}
}

// PruneStale deactivates volunteer nodes that stopped heartbeating, and
// forgets long-gone ones (banned nodes are kept so the ban sticks).
func (r *nodeRegistry) PruneStale() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for id, n := range r.nodes {
		switch {
		case n.Active && now.Sub(n.LastSeen) > heartbeatStale:
			n.Active = false
			delete(r.byURL, n.Public)
			changed = true
		case !n.Active && !n.Banned && now.Sub(n.LastSeen) > forgetInactiveAfter:
			delete(r.nodes, id)
			changed = true
		}
	}
	if changed {
		r.saveLocked()
	}
}

// StartMaintenance prunes stale nodes and runs due audits in the background.
func (r *nodeRegistry) StartMaintenance() {
	go func() {
		for range time.Tick(30 * time.Second) {
			r.PruneStale()
			r.runDueAudits()
		}
	}()
}

// --- HTTP handlers ----------------------------------------------------------

// readSignedNodeRequest reads and verifies a node request body.
func readSignedNodeRequest(w http.ResponseWriter, req *http.Request, action string) (nodeRequest, bool) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return nodeRequest{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 4096))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return nodeRequest{}, false
	}
	r, err := verifyNodeRequest(body, req.Header.Get("X-Node-Signature"), action)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return nodeRequest{}, false
	}
	return r, true
}

func writeRegistryError(w http.ResponseWriter, err error) {
	var re *registerError
	if errors.As(err, &re) {
		writeError(w, re.status, re.msg)
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

// nodeRegisterHandler handles signed registrations and heartbeats from
// volunteer storage nodes.
func (s *Server) nodeRegisterHandler(w http.ResponseWriter, req *http.Request) {
	r, ok := readSignedNodeRequest(w, req, "register")
	if !ok {
		return
	}
	// A brand-new registration triggers a storage test, so don't let one
	// client trigger lots of them.
	if !s.nodeRegistrations.Allow(clientIP(req), 1) {
		writeError(w, http.StatusTooManyRequests, "too many registrations, try again later")
		return
	}
	if err := s.nodes.Register(r); err != nil {
		writeRegistryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

// nodeDeregisterHandler handles a signed deregistration.
func (s *Server) nodeDeregisterHandler(w http.ResponseWriter, req *http.Request) {
	r, ok := readSignedNodeRequest(w, req, "deregister")
	if !ok {
		return
	}
	if err := s.nodes.Deregister(r); err != nil {
		writeRegistryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deregistered"})
}

// requireAdmin checks the operator's NODE_ADMIN_TOKEN. Without one
// configured, the admin endpoints don't exist.
func (s *Server) requireAdmin(w http.ResponseWriter, req *http.Request) bool {
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if s.adminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) != 1 {
		writeError(w, http.StatusNotFound, "not found")
		return false
	}
	return true
}

// adminNodesHandler: GET lists nodes; POST {action: ban|unban|reinstate,
// node_id} manages a volunteer node.
func (s *Server) adminNodesHandler(w http.ResponseWriter, req *http.Request) {
	if !s.requireAdmin(w, req) {
		return
	}
	switch req.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.nodes.Snapshot())
	case http.MethodPost:
		var body struct {
			Action string `json:"action"`
			NodeID string `json:"node_id"`
		}
		req.Body = http.MaxBytesReader(w, req.Body, 4096)
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		var found bool
		switch body.Action {
		case "ban":
			found = s.nodes.SetBanned(body.NodeID, true)
		case "unban":
			found = s.nodes.SetBanned(body.NodeID, false)
		case "reinstate":
			found = s.nodes.Reinstate(body.NodeID)
		default:
			writeError(w, http.StatusBadRequest, "action must be ban, unban or reinstate")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "no such node")
			return
		}
		log.Printf("Operator: %s %s", body.Action, body.NodeID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
