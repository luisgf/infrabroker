// Package control implements the control plane: a Policy Enforcement Point that
// sits between the broker and the signer. It orchestrates human approval for
// commands (human-in-the-loop) and behaviour guardrails, WITHOUT holding the CA
// key (which remains in the signer). The signer enforces authoritative policy;
// the control plane decides when an operation needs approval and manages it.
package control

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

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

	// req is the original request to forward to the signer once approved. Not
	// serialised externally (contains the ephemeral public key).
	req signer.WireRequest
	// consumed prevents a single approval from issuing more than one certificate.
	consumed bool
}

// Registry keeps approval requests in memory with TTL-based expiry.
type Registry struct {
	mu    sync.Mutex
	items map[string]*Approval
	ttl   time.Duration
}

// NewRegistry creates a registry with the given TTL for pending requests.
func NewRegistry(ttl time.Duration) *Registry {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &Registry{items: make(map[string]*Approval), ttl: ttl}
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
	r.items[id] = a
	r.mu.Unlock()
	return a, nil
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
func (r *Registry) Decide(id string, approve bool, by string) (Approval, error) {
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
	} else {
		a.Status = StatusDenied
	}
	a.DecidedBy = by
	a.DecidedAt = time.Now().UTC()
	return *a, nil
}

// Consume marks an approved request as already issued. Returns true only the
// first time (approved and not yet consumed); otherwise false. Prevents a
// single approval from being reused to issue multiple certificates.
func (r *Registry) Consume(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return false
	}
	r.expireLocked(a)
	if a.Status != StatusApproved || a.consumed {
		return false
	}
	a.consumed = true
	return true
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

// expireLocked marks a pending request as expired when its TTL has elapsed.
// Must be called with r.mu held.
func (r *Registry) expireLocked(a *Approval) {
	if a.Status == StatusPending && time.Since(a.CreatedAt) > r.ttl {
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
}

// newID generates a random 128-bit hexadecimal identifier.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating approval id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
