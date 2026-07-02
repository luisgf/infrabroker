// Package redact masks secrets embedded in free text (typically command
// lines) before the text reaches a persistent or outbound sink: the audit
// log, a session recording, or an approval notification.
//
// Redaction is best-effort pattern matching, not DLP: it shrinks the blast
// radius of a secret typed into a command, it does not guarantee removal
// (see docs/SECURITY.md). It must NEVER run on the decision path — what the
// signer authorizes, what the certificate force-command enforces, and what
// the human approver reviews over mTLS is always the original text.
package redact

import (
	"fmt"
	"regexp"
	"strings"
)

// Marker is the prefix of the replacement written in place of a secret. The
// full replacement is "[REDACTED:<rule-name>]" so a redacted record points
// back at the rule that fired.
const Marker = "[REDACTED:"

// SecretGroup is the name of the capturing group that marks the secret part
// of a pattern. With the group, only its capture is masked and the rest of
// the match is preserved as forensic context; without it, the whole match is
// masked.
const SecretGroup = "secret"

// Config is the operator-facing redaction configuration, embedded in each
// service's config file under the "redact" key. Absent/empty = redaction
// disabled (current behaviour).
type Config struct {
	// Patterns are extra operator-defined rules, applied after the built-in
	// defaults. See Pattern for the regex contract.
	Patterns []Pattern `json:"patterns,omitempty"`
	// DisableDefaults turns off the built-in default rules, leaving only the
	// operator's Patterns. Escape hatch when a default rule produces false
	// positives that hurt forensics.
	DisableDefaults bool `json:"disable_defaults,omitempty"`
}

// Pattern is one named redaction rule.
type Pattern struct {
	// Name identifies the rule inside the [REDACTED:<name>] marker.
	Name string `json:"name"`
	// Regex is an RE2 expression (linear-time, no catastrophic backtracking —
	// same engine and rationale as the command-policy rules). If it defines a
	// capturing group named "secret", only that group is masked; otherwise the
	// whole match is masked.
	Regex string `json:"regex"`
}

// rule is one compiled redaction rule.
type rule struct {
	name string
	re   *regexp.Regexp
	// secretIdx is the index of the "secret" capturing group, or -1 when the
	// whole match is the secret.
	secretIdx int
}

// Redactor applies an ordered set of compiled redaction rules. It is
// immutable after New and safe for concurrent use. A nil *Redactor is valid
// and redacts nothing.
type Redactor struct {
	rules []rule
}

// reValidName constrains rule names so the [REDACTED:<name>] marker stays a
// single unambiguous token in logs.
var reValidName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// New compiles the configured rules (defaults first, operator extras after).
// Any invalid rule is a hard error: the caller is expected to fail startup
// (fail-closed) rather than run with a silently smaller rule set. A nil cfg
// selects the defaults only. Returns nil (redaction disabled) when the
// effective rule set is empty.
func New(cfg *Config) (*Redactor, error) {
	var pats []Pattern
	if cfg == nil || !cfg.DisableDefaults {
		pats = append(pats, Defaults...)
	}
	if cfg != nil {
		pats = append(pats, cfg.Patterns...)
	}
	if len(pats) == 0 {
		return nil, nil
	}
	r := &Redactor{rules: make([]rule, 0, len(pats))}
	for i, p := range pats {
		if !reValidName.MatchString(p.Name) {
			return nil, fmt.Errorf("redact: pattern %d: invalid name %q", i, p.Name)
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("redact: pattern %q: %w", p.Name, err)
		}
		r.rules = append(r.rules, rule{name: p.Name, re: re, secretIdx: re.SubexpIndex(SecretGroup)})
	}
	return r, nil
}

// Redact returns s with every rule applied in order. Each rule rewrites the
// output of the previous one, so a later rule can still fire on the context
// an earlier rule preserved.
func (r *Redactor) Redact(s string) string {
	if r == nil || s == "" {
		return s
	}
	for _, ru := range r.rules {
		s = ru.apply(s)
	}
	return s
}

// apply masks every non-overlapping occurrence of ru in s. A candidate whose
// content already is a redaction marker is skipped, so two rules that overlap
// (e.g. a flag rule and an assignment rule matching the same "--password=x")
// cannot cascade into masking each other's marker and losing the rule name.
func (ru rule) apply(s string) string {
	matches := ru.re.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		start, end := m[0], m[1]
		if gi := ru.secretIdx; gi > 0 && 2*gi+1 < len(m) && m[2*gi] >= 0 {
			start, end = m[2*gi], m[2*gi+1]
		}
		if start < last { // overlap with a segment this rule already rewrote
			continue
		}
		if strings.HasPrefix(s[start:], Marker) { // already redacted by an earlier rule
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(Marker)
		b.WriteString(ru.name)
		b.WriteString("]")
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}
