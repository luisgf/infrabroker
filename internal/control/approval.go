// Package control implements the control plane: a Policy Enforcement Point that
// sits between the broker and the signer. It orchestrates human approval for
// commands (human-in-the-loop) and behaviour guardrails, WITHOUT holding the CA
// key (which remains in the signer). The signer enforces authoritative policy;
// the control plane decides when an operation needs approval and manages it.
package control

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/luisgf/ssh-broker/internal/monitor"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// Status is the state of an approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// Approval is a human-approval request for an operation that the command
// policy flagged as require_approval.
type Approval struct {
	ID        string    `json:"id"`
	Caller    string    `json:"caller"`             // CN of the broker that originated the request
	EndUser   string    `json:"end_user,omitempty"` // OIDC identity of the end user
	Host      string    `json:"host"`
	Command   string    `json:"command"`
	Sudo      bool      `json:"sudo,omitempty"`
	SudoUser  string    `json:"sudo_user,omitempty"`
	Rule      string    `json:"rule,omitempty"` // require_approval rule that matched
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitempty"`

	// LearnTTL, when > 0 on an approved request, asks the signer to mint a TTL'd
	// approval waiver for this command on the next (approved) forward — so the same
	// command runs without re-approval until it expires (approve-and-learn).
	LearnTTL time.Duration `json:"learn_ttl,omitempty"`

	// req is the original request to forward to the signer once approved. Not
	// serialised externally (contains the ephemeral public key).
	req signer.WireRequest
	// consumed prevents a single approval from issuing more than one certificate.
	consumed bool
	// issuing is true while one poller is forwarding the approved request to the
	// signer. It prevents concurrent double-issuance without burning the approval
	// if the signer fails before returning a cert/decision.
	issuing bool
}

// Redactor masks secrets in an approval's command for notification sinks. It
// is satisfied by *redact.Redactor; declared here so control does not import
// the redact package (the dependency stays one-way, wired by the control
// plane at startup).
type Redactor interface {
	Redact(string) string
}

// WithRedactedCommand returns a copy of the approval whose Command has been
// passed through r, for notification sinks that persist or leave the host
// (process log, webhook, Teams). The registry entry keeps the original
// command: the mTLS approval UI/API must show the approver exactly what will
// run, and the approved request forwarded to the signer is untouched. A nil r
// returns the approval unchanged.
func (a Approval) WithRedactedCommand(r Redactor) Approval {
	if r != nil {
		a.Command = r.Redact(a.Command)
	}
	return a
}

// RegistrySchema is the statedb migration list for the approval registry
// (state_db in control-plane.json). Times are unix seconds; request_json is
// the original signer.WireRequest (public material only — the broker's
// ephemeral PUBLIC key), kept so a pending or approved-but-uncollected
// approval survives a restart and can still be consumed.
var RegistrySchema = []string{`
CREATE TABLE approvals (
	id                TEXT PRIMARY KEY,
	caller            TEXT NOT NULL DEFAULT '',
	end_user          TEXT NOT NULL DEFAULT '',
	host              TEXT NOT NULL DEFAULT '',
	command           TEXT NOT NULL DEFAULT '',
	sudo              INTEGER NOT NULL DEFAULT 0,
	sudo_user         TEXT NOT NULL DEFAULT '',
	rule              TEXT NOT NULL DEFAULT '',
	status            TEXT NOT NULL,
	created_at        INTEGER NOT NULL,
	decided_by        TEXT NOT NULL DEFAULT '',
	decided_at        INTEGER NOT NULL DEFAULT 0,
	learn_ttl_seconds INTEGER NOT NULL DEFAULT 0,
	consumed          INTEGER NOT NULL DEFAULT 0,
	request_json      TEXT NOT NULL
);
CREATE INDEX approvals_created ON approvals(created_at);
`}

// stateDBErrors counts best-effort state-db write failures (registered by
// name; shared with every statedb consumer in the process).
var stateDBErrors = monitor.GetCounter("statedb_errors_total",
	"State-db best-effort write failures (in-memory state diverged from disk).")

// Registry keeps approval requests in memory with TTL-based expiry. With a
// state db (NewRegistryDB) the create/decide/consume transitions are written
// through and usable requests are reloaded at startup; the in-memory map
// remains the only state consulted per poll.
type Registry struct {
	mu    sync.Mutex
	items map[string]*Approval
	ttl   time.Duration
	db    *sql.DB // nil = memory-only
}

// NewRegistry creates a registry with the given TTL. Pending requests must be
// approved before this window elapses from CreatedAt; approved-but-unconsumed
// requests must be collected before the same window elapses from DecidedAt.
func NewRegistry(ttl time.Duration) *Registry {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &Registry{items: make(map[string]*Approval), ttl: ttl}
}

// NewRegistryDB returns a registry backed by the given state db (opened with
// statedb.Open and RegistrySchema), preloaded with every request still inside
// the purge window — including terminal ones, so a broker polling across the
// restart sees the same status instead of a 404. The `issuing` gate is NOT
// persisted: it is an intra-process concurrency claim, so after a restart an
// approved-but-unconsumed request is consumable again (exactly once).
func NewRegistryDB(ttl time.Duration, db *sql.DB) (*Registry, error) {
	r := NewRegistry(ttl)
	r.db = db
	rows, err := db.Query(`SELECT id, caller, end_user, host, command, sudo, sudo_user,
		rule, status, created_at, decided_by, decided_at, learn_ttl_seconds, consumed, request_json
		FROM approvals WHERE created_at > ?`, time.Now().Add(-2*r.ttl).Unix())
	if err != nil {
		return nil, fmt.Errorf("loading approvals: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			a                    Approval
			sudo, consumed       int
			createdAt, decidedAt int64
			learnTTLSeconds      int64
			status, reqJS        string
		)
		if err := rows.Scan(&a.ID, &a.Caller, &a.EndUser, &a.Host, &a.Command, &sudo, &a.SudoUser,
			&a.Rule, &status, &createdAt, &a.DecidedBy, &decidedAt, &learnTTLSeconds, &consumed, &reqJS); err != nil {
			return nil, fmt.Errorf("scanning approval row: %w", err)
		}
		if err := json.Unmarshal([]byte(reqJS), &a.req); err != nil {
			// Without its original request the approval can never be forwarded;
			// dropping it fails safe (the broker re-requests, a new approval is
			// created).
			log.Printf("warning: state db: dropping approval %s (request_json: %v)", a.ID, err)
			continue
		}
		a.Status = Status(status)
		a.Sudo = sudo != 0
		a.consumed = consumed != 0
		a.CreatedAt = time.Unix(createdAt, 0).UTC()
		if decidedAt != 0 {
			a.DecidedAt = time.Unix(decidedAt, 0).UTC()
		}
		a.LearnTTL = time.Duration(learnTTLSeconds) * time.Second
		r.items[a.ID] = &a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loading approvals: %w", err)
	}
	return r, nil
}

// Create registers a new pending request from the wire request and policy
// decision. Returns the created approval (with an assigned ID).
func (r *Registry) Create(req signer.WireRequest, caller string, dec *signer.DecisionInfo) (*Approval, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.purgeLocked()
	r.mu.Unlock()
	a := &Approval{
		ID:        id,
		Caller:    caller,
		EndUser:   req.EndUser,
		Host:      req.Host,
		Command:   req.Command,
		Sudo:      req.Sudo,
		SudoUser:  req.SudoUser,
		Status:    StatusPending,
		CreatedAt: time.Now().UTC(),
		req:       req,
	}
	if dec != nil {
		a.Rule = dec.MatchedRule
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Write-through, insert-first: a request that cannot be persisted fails
	// creation (the broker retries) instead of silently existing only in
	// memory.
	if r.db != nil {
		if err := r.insertDB(a); err != nil {
			return nil, fmt.Errorf("persisting approval: %w", err)
		}
	}
	r.items[id] = a
	return a, nil
}

// insertDB mirrors a new approval into the state db. Must be called with r.mu
// held.
func (r *Registry) insertDB(a *Approval) error {
	reqJS, err := json.Marshal(a.req)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO approvals (id, caller, end_user, host, command, sudo,
		sudo_user, rule, status, created_at, decided_by, decided_at, learn_ttl_seconds,
		consumed, request_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Caller, a.EndUser, a.Host, a.Command, boolToInt(a.Sudo), a.SudoUser,
		a.Rule, string(a.Status), a.CreatedAt.Unix(), a.DecidedBy, 0, 0, 0, string(reqJS))
	return err
}

// updateDBBestEffort mirrors a state transition without failing the caller:
// the in-memory transition already happened (and, for consume, the
// certificate is already issued), so the only honest option is to record the
// divergence. Failures are counted and logged; a restart re-derives the state
// from the last persisted transition, which is always the more conservative
// one. Must be called with r.mu held.
func (r *Registry) updateDBBestEffort(query string, args ...any) {
	if r.db == nil {
		return
	}
	if _, err := r.db.Exec(query, args...); err != nil {
		stateDBErrors.Inc()
		log.Printf("warning: state db: %v", err)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Get returns a copy of the request, applying lazy expiry.
func (r *Registry) Get(id string) (Approval, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return Approval{}, false
	}
	r.expireLocked(a)
	return *a, true
}

// Request returns the original WireRequest (to forward to the signer after
// approval).
func (r *Registry) Request(id string) (signer.WireRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return signer.WireRequest{}, false
	}
	return a.req, true
}

// Decide resolves a pending request as approved or denied. Fails if the
// request does not exist or is no longer pending (expired/resolved).
// Decide transitions a pending approval. learnTTL, when > 0 on an approval, asks
// the signer to mint a TTL'd approval waiver for this command on the next forward
// (approve-and-learn); it is ignored on a denial.
func (r *Registry) Decide(id string, approve bool, by string, learnTTL time.Duration) (Approval, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return Approval{}, fmt.Errorf("unknown approval request: %q", id)
	}
	r.expireLocked(a)
	if a.Status != StatusPending {
		return *a, fmt.Errorf("request %q is no longer pending (status: %s)", id, a.Status)
	}
	if approve {
		a.Status = StatusApproved
		if learnTTL > 0 {
			a.LearnTTL = learnTTL
		}
	} else {
		a.Status = StatusDenied
	}
	a.DecidedBy = by
	a.DecidedAt = time.Now().UTC()
	// Best-effort: the human decision stands in memory either way; a missed
	// write means a restart shows the request pending again within its TTL
	// (the more conservative state — it needs a fresh decision).
	r.updateDBBestEffort(`UPDATE approvals SET status = ?, decided_by = ?, decided_at = ?,
		learn_ttl_seconds = ? WHERE id = ?`,
		string(a.Status), a.DecidedBy, a.DecidedAt.Unix(), int64(a.LearnTTL/time.Second), a.ID)
	return *a, nil
}

// BeginConsume claims an approved request for forwarding to the signer. Returns
// (true, false) only for the first active poller. If another poller is already
// issuing the approval, it returns (false, true) so the caller can keep polling.
// Once consumed, denied, expired, or unknown, it returns (false, false).
func (r *Registry) BeginConsume(id string) (started, retry bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return false, false
	}
	r.expireLocked(a)
	if a.Status != StatusApproved || a.consumed {
		return false, false
	}
	if a.issuing {
		return false, true
	}
	a.issuing = true
	return true, false
}

// FinishConsume completes a BeginConsume claim. On success the approval is
// burned permanently; on failure it is released so the broker can retry a
// transient signer/control-plane failure without asking the human again.
func (r *Registry) FinishConsume(id string, success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return
	}
	if success {
		a.consumed = true
		// Best-effort: the certificate is already issued, so this cannot be
		// rolled back. A missed write leaves a crash window in which a restart
		// re-exposes the approval as consumable once more — bounded by the
		// approval TTL and the certificate TTL, and flagged by
		// statedb_errors_total (see THREAT_MODEL).
		r.updateDBBestEffort("UPDATE approvals SET consumed = 1 WHERE id = ?", a.ID)
	}
	a.issuing = false
}

// List returns a copy of all requests (applying expiry and purging old
// terminal entries).
func (r *Registry) List() []Approval {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.purgeLocked()
	out := make([]Approval, 0, len(r.items))
	for _, a := range r.items {
		r.expireLocked(a)
		out = append(out, *a)
	}
	return out
}

// expireLocked marks requests as expired when their usable window has elapsed.
// Pending requests expire from CreatedAt. Approved requests that have not yet
// been consumed expire from DecidedAt, so an old approval cannot be redeemed
// indefinitely if the broker stops polling after the human decision.
// Must be called with r.mu held.
func (r *Registry) expireLocked(a *Approval) {
	switch a.Status {
	case StatusPending:
		if time.Since(a.CreatedAt) <= r.ttl {
			return
		}
	case StatusApproved:
		if a.consumed || a.issuing {
			return
		}
		anchor := a.DecidedAt
		if anchor.IsZero() {
			anchor = a.CreatedAt
		}
		if time.Since(anchor) <= r.ttl {
			return
		}
	default:
		return
	}
	if !a.consumed {
		a.Status = StatusExpired
	}
}

// purgeLocked deletes requests that can no longer change state, so the
// registry does not grow without bound. A request is purged 2×TTL after its
// creation: by then it is expired or decided, and any result has been
// collected (the broker polls every 2 s while it waits). Invoked
// opportunistically from Create and List, keeping the per-poll Get at O(1).
// A purged id answers 404 on later polls instead of 408/410. Must be called
// with r.mu held.
func (r *Registry) purgeLocked() {
	for id, a := range r.items {
		if time.Since(a.CreatedAt) > 2*r.ttl {
			delete(r.items, id)
		}
	}
	// One sweep bounds the db too (also covers rows aged out while the
	// process was down); rows outside the purge window are not loaded at
	// startup, so a missed delete only costs space.
	r.updateDBBestEffort("DELETE FROM approvals WHERE created_at <= ?",
		time.Now().Add(-2*r.ttl).Unix())
}

// newID generates a random 128-bit hexadecimal identifier.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating approval id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
