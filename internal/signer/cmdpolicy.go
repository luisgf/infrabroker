package signer

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"
)

// CommandPolicy modes.
const (
	CmdPolicyOff       = "off"       // no command restriction (also the empty value)
	CmdPolicyAllowlist = "allowlist" // the command MUST match one of the Allow regexes
	CmdPolicyDenylist  = "denylist"  // the command must NOT match any Deny regex
)

// CommandPolicy restricts which commands may run on a host. It is the basis of
// the "AI-action firewall": the signer applies it authoritatively for one-shot
// (the force-command baked into the cert by the CA key is unevadable).
//
// Rules are regular expressions (RE2: linear time, no catastrophic
// backtracking). They come from the operator config (signer.json), which is
// trusted.
//
// It must be copyable by value (it lives inside HostPolicy, which is copied in
// maps): that is why the compiled-regex cache is package-level, not a field.
//
// Evaluation lives in PolicySet (policyset.go): a single-element PolicySet
// reproduces a lone CommandPolicy exactly, so the request path always evaluates
// through PolicySet and there is a single source of truth for the rule logic.
type CommandPolicy struct {
	// Mode: "off" (or empty) | "allowlist" | "denylist". Controls allow/deny.
	Mode string `json:"mode,omitempty"`
	// Allow: in allowlist mode, the command must match at least one.
	Allow []string `json:"allow,omitempty"`
	// Deny: in denylist mode, the command must not match any.
	Deny []string `json:"deny,omitempty"`
	// RequireApproval: commands that match require out-of-band human approval.
	// Evaluated independently of the mode (orchestrated by the control plane).
	RequireApproval []string `json:"require_approval,omitempty"`
	// ShellParse: if true, the command is parsed as POSIX sh before evaluating
	// the policy. Each simple command is evaluated separately; dangerous nodes
	// (subshells, process substitution, file redirects) are rejected
	// unconditionally. Backward compatible: false by default.
	ShellParse bool `json:"shell_parse,omitempty"`
}

// Active reports whether the policy imposes an execution restriction
// (allow/deny). require_approval rules alone do not count as an execution
// restriction, but they do prevent the use of sessions (see Restricts).
func (cp CommandPolicy) Active() bool {
	return cp.Mode == CmdPolicyAllowlist || cp.Mode == CmdPolicyDenylist
}

// Restricts reports whether the host has any command rule (allow/deny or
// approval). If so, sessions are not verifiable (the command does not reach the
// signer at signing time) and must be rejected.
func (cp CommandPolicy) Restricts() bool {
	return cp.Active() || len(cp.RequireApproval) > 0
}

// Validate compiles every regex in the policy and checks the mode, so a
// malformed pattern or unknown mode is caught at config load/reload instead of
// at the first matching request (where it would surface as a per-host failure).
func (cp CommandPolicy) Validate() error {
	for _, group := range [][]string{cp.Allow, cp.Deny, cp.RequireApproval} {
		for _, pat := range group {
			if _, err := cachedRegex(pat); err != nil {
				return fmt.Errorf("invalid command_policy regex %q: %w", pat, err)
			}
		}
	}
	switch cp.Mode {
	case "", CmdPolicyOff, CmdPolicyAllowlist, CmdPolicyDenylist:
		return nil
	default:
		return fmt.Errorf("unknown command_policy mode: %q", cp.Mode)
	}
}

// extractCommands parses command as POSIX sh and returns the simple commands
// that compose it. It unconditionally rejects dangerous nodes:
//   - CmdSubst    $(...)   — arbitrary subshell
//   - ProcSubst   <(...)   — process substitution
//   - ArithmCmd   $((...)) — arithmetic with side effects
//   - file Redirect        — arbitrary write to the filesystem
//
// Allowed: pipes (|), sequences (&&, ||, ;) and fd→fd redirections (2>&1).
// Each CallExpr in the AST is printed back to its canonical string and returned
// as an independent element for separate evaluation.
func extractCommands(command string) ([]string, error) {
	parser := shellParserPool.Get().(*syntax.Parser)
	defer shellParserPool.Put(parser)
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, fmt.Errorf("shell parse: %w", err)
	}

	var cmds []string
	var walkErr error
	// One printer per call, reused across every CallExpr instead of allocating a
	// fresh one inside the walk.
	printer := syntax.NewPrinter()
	var buf strings.Builder

	syntax.Walk(f, func(node syntax.Node) bool {
		if walkErr != nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.CmdSubst:
			walkErr = errors.New("command substitution not allowed")
			return false
		case *syntax.ProcSubst:
			walkErr = errors.New("process substitution not allowed")
			return false
		case *syntax.ArithmCmd:
			walkErr = errors.New("arithmetic command not allowed")
			return false
		case *syntax.Redirect:
			// Allow only fd→fd redirections (e.g. 2>&1, 1>&2). A file redirect has
			// Hdoc or a Word pointing to a filename; we detect the safe case by
			// checking that the destination is also an fd (DplIn/DplOut).
			isDupFd := n.Op == syntax.DplOut || n.Op == syntax.DplIn
			if !isDupFd {
				walkErr = fmt.Errorf("file redirect not allowed: %s", n.Op)
				return false
			}
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				break
			}
			buf.Reset()
			if err2 := printer.Print(&buf, n); err2 != nil {
				walkErr = fmt.Errorf("printer: %w", err2)
				return false
			}
			cmds = append(cmds, buf.String())
		}
		return true
	})

	if walkErr != nil {
		return nil, walkErr
	}
	if len(cmds) == 0 {
		return nil, errors.New("no commands found after shell parse")
	}
	return cmds, nil
}

// shellParserPool reuses POSIX-shell parsers across requests with shell_parse
// enabled. A *syntax.Parser is not safe for concurrent use, so the pool hands
// each call its own; Parse resets parser state, so a pooled parser is safe to
// reuse.
var shellParserPool = sync.Pool{New: func() any { return syntax.NewParser() }}

// regexCache memoises compiled regexes by pattern (shared between the signer and
// the control plane). Keys are trusted patterns (operator config).
var regexCache sync.Map // string → *regexp.Regexp | error

func cachedRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		switch t := v.(type) {
		case *regexp.Regexp:
			return t, nil
		case error:
			return nil, t
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		regexCache.Store(pattern, err)
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}
