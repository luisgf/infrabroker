// Package policyrec turns the audit log into command-policy recommendations.
// It is read-only and advisory: it never mutates policy — it suggests rules to
// add (commands run/approved despite the current policy denying them), rules
// that look dead (allow/deny patterns that never matched in the window), and
// friction (commands repeatedly blocked). The operator decides what to apply.
//
// Attribution is by re-evaluation: each observed command is re-decided against
// the current compiled policy (signer.PolicySet.Decide), so the recommender does
// not depend on the audit recording which rule matched.
package policyrec

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

// SuggestionType classifies a recommendation.
type SuggestionType string

const (
	// Promote: a command run or human-approved despite the current policy not
	// allowing it — candidate to add to the allowlist.
	Promote SuggestionType = "promote"
	// DeadRule: an allow/deny pattern in the current policy that never matched
	// any observed command in the window — candidate to remove (least privilege).
	DeadRule SuggestionType = "dead-rule"
	// Friction: a command repeatedly denied — surfaced for review.
	Friction SuggestionType = "friction"
)

// Suggestion is one advisory recommendation.
type Suggestion struct {
	Type      SuggestionType `json:"type"`
	Host      string         `json:"host"`
	Pattern   string         `json:"pattern"` // proposed (promote) or existing (dead-rule) rule
	Count     int            `json:"count"`
	Callers   int            `json:"distinct_callers"`
	Approved  int            `json:"approved,omitempty"` // entries that were human-approved
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Samples   []string       `json:"samples,omitempty"`
}

// Options tunes the analysis.
type Options struct {
	Host     string    // restrict to one host ("" = all)
	Since    time.Time // ignore entries before this (zero = all)
	MinCount int       // suppress suggestions with fewer occurrences (default 1)
}

// stat accumulates evidence for a (host, command) or (host, pattern) bucket.
type stat struct {
	count, approved int
	callers         map[string]struct{}
	first, last     time.Time
	samples         []string
}

func (s *stat) observe(e audit.Entry, approved bool) {
	if s.callers == nil {
		s.callers = map[string]struct{}{}
		s.first = e.Time
	}
	s.count++
	if approved {
		s.approved++
	}
	s.callers[e.Caller] = struct{}{}
	if e.Time.Before(s.first) {
		s.first = e.Time
	}
	if e.Time.After(s.last) {
		s.last = e.Time
	}
	if len(s.samples) < 3 && !contains(s.samples, e.Command) {
		s.samples = append(s.samples, e.Command)
	}
}

type key struct{ host, item string }

// Recommend analyses entries against the compiled policy and returns advisory
// suggestions, ranked by support (count) descending.
func Recommend(entries []audit.Entry, compiled signer.PolicyTable, opts Options) []Suggestion {
	if opts.MinCount < 1 {
		opts.MinCount = 1
	}
	promote := map[key]*stat{}
	friction := map[key]*stat{}
	usedRule := map[key]bool{} // (host, allow/deny pattern) seen as the matching rule

	for _, e := range entries {
		if e.Command == "" || e.Host == "" {
			continue
		}
		if opts.Host != "" && e.Host != opts.Host {
			continue
		}
		if !opts.Since.IsZero() && e.Time.Before(opts.Since) {
			continue
		}
		hp, ok := compiled[e.Host]
		if !ok {
			continue // command on a host not in this policy
		}
		allowed, _, rule, derr := hp.Policies.Decide(e.Command)
		if derr != nil {
			continue
		}
		if pat, ok := ruleArg(rule, "allow:"); ok {
			usedRule[key{e.Host, pat}] = true
		}
		if pat, ok := ruleArg(rule, "deny:"); ok {
			usedRule[key{e.Host, pat}] = true
		}
		approved := isApprovalGrant(e.Outcome)
		ran := approved || e.Outcome == "executed" || e.Outcome == "session_exec" || e.Outcome == "dry_run_allowed"
		switch {
		case !allowed && ran:
			at(promote, key{e.Host, e.Command}).observe(e, approved)
		case !allowed && (e.Outcome == "denied" || e.Outcome == "session_exec_denied" || e.Outcome == "dry_run_denied"):
			at(friction, key{e.Host, e.Command}).observe(e, approved)
		}
	}

	var out []Suggestion
	out = append(out, buildCmd(Promote, promote, opts.MinCount, true)...)
	out = append(out, buildCmd(Friction, friction, opts.MinCount, false)...)
	out = append(out, buildDeadRules(compiled, usedRule, opts)...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// buildCmd turns command-keyed stats into suggestions. When anchor is true the
// proposed pattern is the literal command anchored (the conservative default).
func buildCmd(t SuggestionType, m map[key]*stat, minCount int, anchor bool) []Suggestion {
	var out []Suggestion
	for k, s := range m {
		if s.count < minCount {
			continue
		}
		pat := k.item
		if anchor {
			pat = "^" + regexp.QuoteMeta(k.item) + "$"
		}
		out = append(out, Suggestion{
			Type: t, Host: k.host, Pattern: pat, Count: s.count,
			Callers: len(s.callers), Approved: s.approved,
			FirstSeen: s.first, LastSeen: s.last, Samples: s.samples,
		})
	}
	return out
}

// buildDeadRules flags allow/deny patterns in the compiled policy that never
// matched an observed command in the window.
func buildDeadRules(compiled signer.PolicyTable, used map[key]bool, opts Options) []Suggestion {
	var out []Suggestion
	for host, hp := range compiled {
		if opts.Host != "" && host != opts.Host {
			continue
		}
		for _, cp := range hp.Policies {
			for _, group := range [][]string{cp.Allow, cp.Deny} {
				for _, pat := range group {
					if used[key{host, pat}] {
						continue
					}
					out = append(out, Suggestion{Type: DeadRule, Host: host, Pattern: pat})
				}
			}
		}
	}
	return out
}

func at(m map[key]*stat, k key) *stat {
	s := m[k]
	if s == nil {
		s = &stat{}
		m[k] = s
	}
	return s
}

// isApprovalGrant reports whether an audit outcome represents a human approval
// that ALLOWED the command (so it ran or would run): the consumption outcome
// "approval-granted" and the decision outcomes "approval-decision-allow" and
// "approval-decision-allow-learn". It deliberately excludes "approval-denied",
// "approval-timeout" and "self-approval-rejected", which the control plane also
// stamps with ApprovedBy (the CN of the decider) — so keying on ApprovedBy != ""
// would misread a human-rejected command as approved and suggest promoting it to
// the allowlist, defeating least privilege.
func isApprovalGrant(outcome string) bool {
	switch outcome {
	case "approval-granted", "approval-decision-allow", "approval-decision-allow-learn":
		return true
	default:
		return false
	}
}

// ruleArg returns the pattern carried by a rule label like "allow:^uptime$".
func ruleArg(rule, prefix string) (string, bool) {
	if strings.HasPrefix(rule, prefix) {
		return strings.TrimPrefix(rule, prefix), true
	}
	return "", false
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
