package signer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// GrantProvider supplies the live runtime grants consulted on the decision path.
// nil means "no grants" (the common, fail-safe default).
type GrantProvider interface {
	// GrantsFor returns the live (non-expired) widen-only allow policies that
	// apply to host for the given intent at time now. Each is an allowlist
	// CommandPolicy carrying only Allow patterns.
	GrantsFor(host string, in Intent, now time.Time) PolicySet
	// WaiverMatches reports whether a live approval waiver applies to the intent
	// (same host/scope, same elevation, a pattern matching the command). A match
	// suppresses require_approval for an already-allowed command (approve-and-learn);
	// it never widens allow/deny, so it carries no inversion risk.
	WaiverMatches(host string, in Intent, now time.Time) bool
}

// Grant is a time-boxed runtime overlay on a host's command policy. It can carry
// two kinds of widening, neither of which can ever narrow or invert policy:
//   - Allow: widen-only allowlist patterns. Applied only on a host that is
//     already allowlist-active (else it would invert default-allow → default-deny).
//   - WaiveApproval: patterns whose require_approval is suppressed for the TTL
//     (approve-and-learn). Only un-gates an ALREADY-allowed command; applies on
//     any host, no inversion risk.
//
// Optional Caller/EndUser scope restrict a grant to a single broker CN / OIDC end
// user; empty = host-wide. Learn-minted WaiveApproval grants should carry the
// approved caller/end-user scope. For a WaiveApproval grant, Sudo/SudoUser bind it
// to the exact elevation that was approved (a waiver minted for a non-sudo command
// must not un-gate the sudo variant, and vice versa). ApprovalID links a
// learn-minted waiver to its approval.
type Grant struct {
	ID            string    `json:"id"`
	Host          string    `json:"host"`
	Allow         []string  `json:"allow,omitempty"`
	WaiveApproval []string  `json:"waive_approval,omitempty"`
	Caller        string    `json:"caller,omitempty"`
	EndUser       string    `json:"end_user,omitempty"`
	Sudo          bool      `json:"sudo,omitempty"`
	SudoUser      string    `json:"sudo_user,omitempty"`
	Approver      string    `json:"approver,omitempty"`
	ApprovalID    string    `json:"approval_id,omitempty"`
	GrantedAt     time.Time `json:"granted_at"`
	ExpiresAt     time.Time `json:"expires_at"`

	// waiverRE holds the compiled WaiveApproval patterns. Compiled once at Add and
	// kept on the grant (not in the package-level regex cache) so an unbounded
	// stream of unique learned commands cannot pollute that cache forever — the
	// regexes are freed with the grant on expiry/revoke. Not serialised.
	waiverRE []*regexp.Regexp
}

func (g *Grant) active(now time.Time) bool { return now.Before(g.ExpiresAt) }

func (g *Grant) matches(host string, in Intent) bool {
	return g.Host == host &&
		(g.Caller == "" || g.Caller == in.Caller) &&
		(g.EndUser == "" || g.EndUser == in.EndUser)
}

func canonicalGrantSudoUser(sudo bool, user string) string {
	if !sudo {
		return ""
	}
	if user == "" {
		return "root"
	}
	return user
}

// waiverApplies reports whether this grant's approval waiver applies to the intent:
// the host/caller/end-user scope matches AND the elevation (sudo/sudo_user) is the
// SAME as what was approved AND one of its patterns matches the command.
func (g *Grant) waiverApplies(host string, in Intent) bool {
	if !g.matches(host, in) || g.Sudo != in.Sudo ||
		canonicalGrantSudoUser(g.Sudo, g.SudoUser) != canonicalGrantSudoUser(in.Sudo, in.SudoUser) {
		return false
	}
	for _, re := range g.waiverRE {
		if re.MatchString(in.Command) {
			return true
		}
	}
	return false
}

// GrantStore is an in-memory, concurrency-safe set of grants implementing
// GrantProvider. It survives config reloads (created once and shared into each
// rebuilt Local) but not a signer restart — grants are TTL'd, and losing them on
// restart fails safe (the decision falls back to the file baseline, which is the
// more restrictive state because grants only widen).
type GrantStore struct {
	mu     sync.Mutex
	grants map[string]*Grant
}

// NewGrantStore returns an empty store.
func NewGrantStore() *GrantStore {
	return &GrantStore{grants: map[string]*Grant{}}
}

// Add validates the grant's regexes, assigns it a fresh id, and stores it.
func (s *GrantStore) Add(g Grant) (string, error) {
	if len(g.Allow) == 0 && len(g.WaiveApproval) == 0 {
		return "", fmt.Errorf("grant needs at least one allow or waive_approval pattern")
	}
	g.SudoUser = canonicalGrantSudoUser(g.Sudo, g.SudoUser)
	for _, p := range g.Allow {
		if _, err := cachedRegex(p); err != nil {
			return "", fmt.Errorf("invalid allow regex %q: %w", p, err)
		}
	}
	g.waiverRE = make([]*regexp.Regexp, 0, len(g.WaiveApproval))
	for _, p := range g.WaiveApproval {
		re, err := regexp.Compile(p) // compiled onto the grant, not the global cache
		if err != nil {
			return "", fmt.Errorf("invalid waive_approval regex %q: %w", p, err)
		}
		g.waiverRE = append(g.waiverRE, re)
	}
	g.ID = newGrantID()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[g.ID] = &g
	return g.ID, nil
}

// SupersedeWaiver revokes any live waiver grant with the same host, scope,
// elevation, and identical waive_approval patterns, so re-learning a command
// refreshes a single waiver instead of accumulating duplicates. Returns the count
// removed.
func (s *GrantStore) SupersedeWaiver(g Grant) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	sudoUser := canonicalGrantSudoUser(g.Sudo, g.SudoUser)
	for id, ex := range s.grants {
		if ex.Host == g.Host && ex.Caller == g.Caller && ex.EndUser == g.EndUser &&
			ex.Sudo == g.Sudo && canonicalGrantSudoUser(ex.Sudo, ex.SudoUser) == sudoUser &&
			slicesEqual(ex.WaiveApproval, g.WaiveApproval) && len(ex.Allow) == 0 {
			delete(s.grants, id)
			n++
		}
	}
	return n
}

// Purge drops expired grants. Called opportunistically (List) and by a periodic
// background sweep so expired waivers do not linger in memory until the next list.
func (s *GrantStore) Purge(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, g := range s.grants {
		if !g.active(now) {
			delete(s.grants, id)
			n++
		}
	}
	return n
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Revoke removes a grant; returns false if it did not exist.
func (s *GrantStore) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[id]; !ok {
		return false
	}
	delete(s.grants, id)
	return true
}

// List returns the active (non-expired) grants, purging expired ones in passing.
func (s *GrantStore) List(now time.Time) []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Grant{}
	for id, g := range s.grants {
		if !g.active(now) {
			delete(s.grants, id)
			continue
		}
		out = append(out, *g)
	}
	return out
}

// GrantsFor implements GrantProvider: one allowlist CommandPolicy per live grant
// matching host and the intent's caller/end-user scope. The Allow slices are
// shared read-only (grants are immutable after Add).
func (s *GrantStore) GrantsFor(host string, in Intent, now time.Time) PolicySet {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ps PolicySet
	for _, g := range s.grants {
		if g.active(now) && g.matches(host, in) && len(g.Allow) > 0 {
			ps = append(ps, CommandPolicy{Mode: CmdPolicyAllowlist, Allow: g.Allow})
		}
	}
	return ps
}

// WaiverMatches implements GrantProvider: whether a live grant waives approval for
// this intent — same host/scope, same elevation, and a pattern matching the command.
func (s *GrantStore) WaiverMatches(host string, in Intent, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.grants {
		if g.active(now) && g.waiverApplies(host, in) {
			return true
		}
	}
	return false
}

func newGrantID() string {
	var b [12]byte
	// crypto/rand.Read never returns an error on Go 1.24+ (it crashes the process
	// if the OS RNG fails), so this cannot produce a deterministic id; the error is
	// intentionally discarded rather than checked as dead code.
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
