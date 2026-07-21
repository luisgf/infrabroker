package signer

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// CommandPolicy modes.
const (
	CmdPolicyOff       = "off"       // no command restriction (also the empty value)
	CmdPolicyAllowlist = "allowlist" // the command MUST match one of the Allow regexes
	CmdPolicyDenylist  = "denylist"  // the command must NOT match any Deny regex
)

// CommandPolicy enforcement modes.
const (
	CmdPolicyEnforce = "enforce" // default: deny/approval decisions are enforced
	CmdPolicyAudit   = "audit"   // observe only: would-deny/approval becomes a warning
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
	// Enforcement: "enforce" (or empty) blocks/gates matching commands; "audit"
	// lets them run and returns/audits a warning instead. In composed policies,
	// enforce wins over audit.
	Enforcement string `json:"enforcement,omitempty"`
	// Allow: in allowlist mode, the command must match at least one.
	Allow []string `json:"allow,omitempty"`
	// Deny: in denylist mode, the command must not match any.
	Deny []string `json:"deny,omitempty"`
	// RequireApproval: commands that match require out-of-band human approval.
	// Evaluated independently of the mode (orchestrated by the control plane).
	RequireApproval []string `json:"require_approval,omitempty"`
	// ShellParse controls POSIX-sh parsing of the command before the policy is
	// evaluated. When parsing is on, each simple command is evaluated separately
	// and dangerous nodes (subshells, process substitution, file redirects,
	// environment mutations) are rejected unconditionally, so a compound command
	// like "kubectl get pods; rm -rf /etc" cannot ride past an allowlist entry
	// that only matches its first word.
	//
	// Parsing is ON BY DEFAULT — a nil pointer, i.e. the "shell_parse" key
	// absent, parses — so an active command policy covers chained commands
	// without extra configuration. Set it explicitly to false
	// ("shell_parse": false) to restore the legacy raw-string matching for a
	// policy. The three-state pointer keeps the absent-means-on default
	// distinguishable from an explicit opt-out.
	ShellParse *bool `json:"shell_parse,omitempty"`
}

// parseCommands reports whether this policy parses the command as POSIX sh
// before evaluation. Parsing is on unless the operator explicitly opted out with
// "shell_parse": false (see the ShellParse field).
func (cp CommandPolicy) parseCommands() bool {
	return cp.ShellParse == nil || *cp.ShellParse
}

// Active reports whether the policy imposes an execution restriction
// (allow/deny). require_approval rules alone do not count as an execution
// restriction, but they do prevent the use of sessions (see Restricts).
func (cp CommandPolicy) Active() bool {
	return cp.Mode == CmdPolicyAllowlist || cp.Mode == CmdPolicyDenylist
}

// Restricts reports whether the host has any command rule (allow/deny or
// approval). If so, one-shot commands and exec-session commands must be checked
// against the policy; stateful shell/pty sessions are rejected.
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
	case "", CmdPolicyOff:
		// ok
	case CmdPolicyAllowlist:
		// decideOne consults Deny only for denylist members; a Deny parked on an
		// allowlist policy is silently ignored. Fail closed rather than drop it.
		if len(cp.Deny) > 0 {
			return fmt.Errorf("command_policy mode %q must not carry deny patterns (they are only evaluated in denylist mode)", cp.Mode)
		}
	case CmdPolicyDenylist:
		if len(cp.Allow) > 0 {
			return fmt.Errorf("command_policy mode %q must not carry allow patterns (they are only evaluated in allowlist mode)", cp.Mode)
		}
	default:
		return fmt.Errorf("unknown command_policy mode: %q", cp.Mode)
	}
	switch cp.Enforcement {
	case "", CmdPolicyEnforce, CmdPolicyAudit:
		return nil
	default:
		return fmt.Errorf("unknown command_policy enforcement: %q", cp.Enforcement)
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
// Each CallExpr is returned as its DECODED literal command (quoting and
// encoding removed), so the policy matches what the target shell will actually
// run — not the caller's quoting. A command whose value the policy cannot know
// statically (a parameter/command/arithmetic expansion, or an inline env
// assignment) is rejected rather than matched against an incomplete string.
func extractCommands(command string) ([]string, error) {
	parser := shellParserPool.Get().(*syntax.Parser)
	defer shellParserPool.Put(parser)
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, fmt.Errorf("shell parse: %w", err)
	}

	var cmds []string
	var walkErr error

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
			// Allow only fd→fd redirections (e.g. 2>&1, 1>&2, 2>&-). The operator
			// (>& / <&) is NOT sufficient: ">&FILE" is a file write in bash/zsh, so
			// the TARGET must also be a bare fd (a number, or "-" to close). Checking
			// the operator alone let ">&/etc/cron.d/x" pass as an fd dup while the
			// baked force-command wrote the file (arbitrary write / RCE).
			isDupFd := (n.Op == syntax.DplOut || n.Op == syntax.DplIn) && isFdRef(n.Word)
			if !isDupFd {
				walkErr = fmt.Errorf("file redirect not allowed: %s", n.Op)
				return false
			}
		case *syntax.DeclClause:
			// export / declare / readonly / typeset mutate the environment of a
			// FOLLOWING command (GIT_SSH_COMMAND, LD_PRELOAD, PATH, BASH_ENV, …) but
			// are not a command the allowlist evaluates, while the baked
			// force-command still runs them. They have no place in a force-command
			// allowlist, so reject rather than silently drop them.
			walkErr = errors.New("environment declaration (export/declare/…) not allowed")
			return false
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				// A CallExpr with assignments but no command word is a standalone
				// assignment (FOO=bar): invisible to the allowlist yet baked into the
				// force-command, where it changes how a following command runs. Reject
				// it; a truly empty CallExpr is a harmless no-op we skip.
				if len(n.Assigns) > 0 {
					walkErr = errors.New("standalone environment assignment not allowed")
					return false
				}
				break
			}
			// An inline env prefix (FOO=bar cmd, LD_PRELOAD=… cmd) mutates how cmd
			// runs but is invisible to the policy regexes — same danger as the
			// standalone assignment and export/declare above (a deny like "^rm " is
			// dodged by "FOO=bar rm -rf"). Reject it.
			if len(n.Assigns) > 0 {
				walkErr = errors.New("inline environment assignment before a command not allowed")
				return false
			}
			// Match against the DECODED literal command, not its quoting-preserving
			// source: the target shell removes quoting/encoding at exec time, so
			// matching the printed form let 'rm', r"m", $'\x72\x6d' and rm$IFS-rf
			// slip past a deny/allow rule that the executed command would hit (#277).
			lit, err2 := literalArgs(n.Args)
			if err2 != nil {
				walkErr = err2
				return false
			}
			cmds = append(cmds, lit)
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

// literalArgs returns a simple command's argument words decoded to their literal
// values and joined by single spaces — the form the target shell will actually
// execute, with all quoting/encoding removed so the command policy matches what
// runs instead of the caller's quoting (#277). It fails closed on any word whose
// value is not statically knowable (a parameter/command/arithmetic expansion,
// process substitution or extended glob): such a word is rejected rather than
// matched against an incomplete string.
func literalArgs(args []*syntax.Word) (string, error) {
	// A fresh config per call: expand.Literal mutates the *Config it is given
	// (prepareConfig sets Env/ifs in place), so a shared instance would race
	// under concurrent Decide calls. NoUnset makes any parameter reference that
	// slips past isStaticWord an error rather than a silent "" expansion; a nil
	// ReadDir disables globbing so a bare "*" stays literal.
	cfg := &expand.Config{NoUnset: true}
	parts := make([]string, 0, len(args))
	for _, w := range args {
		if !isStaticWord(w) {
			return "", errors.New("command word with a parameter/command/arithmetic expansion not allowed")
		}
		if err := rejectShellExpansion(w); err != nil {
			return "", err
		}
		lit, err := expand.Literal(cfg, w)
		if err != nil {
			return "", fmt.Errorf("decoding command word: %w", err)
		}
		parts = append(parts, lit)
	}
	return strings.Join(parts, " "), nil
}

// directArgv reports whether command is one simple command whose words are all
// statically known, returning its decoded argv. That is the shape that can be
// elevated by handing the words straight to sudo — "sudo -n -- systemctl
// restart nginx.service" — so the host's sudoers rule authorizes the real
// binary with its literal arguments (least privilege, mirroring
// command_policies) instead of a generic /bin/sh (#306). Anything with shell
// semantics reports false and keeps the /bin/sh -c wrapper: pipes/sequences
// (>1 statement or a non-CallExpr), redirects (fd-dups included — without a
// shell nothing interprets them), env assignments, expansions, globs. The
// checks mirror extractCommands/literalArgs; both fail closed on anything the
// signer cannot resolve statically.
func directArgv(command string) ([]string, bool) {
	parser := shellParserPool.Get().(*syntax.Parser)
	defer shellParserPool.Put(parser)
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, false
	}
	if len(f.Stmts) != 1 {
		return nil, false
	}
	stmt := f.Stmts[0]
	if stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) > 0 {
		return nil, false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 {
		return nil, false
	}
	// Fresh config per call: expand.Literal mutates it (see literalArgs).
	cfg := &expand.Config{NoUnset: true}
	argv := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		if !isStaticWord(w) || rejectShellExpansion(w) != nil || hasUnquotedBackslash(w) {
			return nil, false
		}
		lit, err := expand.Literal(cfg, w)
		if err != nil {
			return nil, false
		}
		argv = append(argv, lit)
	}
	// sudo classifies a LEADING word containing '=' as a command-line environment
	// assignment (its is_envar test is a bare strchr, with no identifier check),
	// so such a word would silently shift which argv[0] runs as root. The shell
	// parser only diverts NAME=value with a VALID identifier into call.Assigns
	// ("9=x cmd" stays a plain word), so catch the rest here and let the wrapper
	// keep the historical semantics.
	if strings.Contains(argv[0], "=") {
		return nil, false
	}
	// A shell-only builtin has no binary for sudo to exec: running it directly
	// would fail where the wrapper's `sh -c` succeeded. Keep the wrapper so the
	// direct form is never a capability regression.
	if shellOnlyBuiltins[argv[0]] {
		return nil, false
	}
	return argv, true
}

// hasUnquotedBackslash reports whether w carries a backslash in an UNQUOTED
// literal part. `expand.Literal` keeps such a backslash verbatim while the
// target shell would consume it as an escape, so the direct argv would differ
// from what `sh -c` executes ("touch a\ b" is one argument to the shell, two
// literal words here). Fail closed to the wrapper rather than run a different
// command. (The same decode gap affects the policy layer for non-elevated
// commands — tracked separately.)
func hasUnquotedBackslash(w *syntax.Word) bool {
	for _, part := range w.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.Contains(lit.Value, `\`) {
			return true
		}
	}
	return false
}

// shellOnlyBuiltins are commands implemented by the shell with no external
// binary sudo could exec. Elevating them directly would break what the
// `/bin/sh -c` wrapper ran, so they stay wrapped.
var shellOnlyBuiltins = map[string]bool{
	".": true, ":": true, "alias": true, "bg": true, "break": true,
	"builtin": true, "cd": true, "command": true, "continue": true,
	"declare": true, "dirs": true, "disown": true, "eval": true, "exec": true,
	"exit": true, "export": true, "fc": true, "fg": true, "getopts": true,
	"hash": true, "jobs": true, "let": true, "local": true, "logout": true,
	"popd": true, "pushd": true, "read": true, "readonly": true,
	"return": true, "set": true, "shift": true, "shopt": true, "source": true,
	"suspend": true, "times": true, "trap": true, "type": true, "typeset": true,
	"ulimit": true, "umask": true, "unalias": true, "unset": true, "wait": true,
}

// rejectShellExpansion fails closed on a word carrying a shell expansion that the
// signer cannot resolve at decision time but the target shell performs at exec
// time: pathname globbing (* ? [ ]), brace expansion ({...}), or a leading tilde
// (~). The value such a word expands to depends on the target's filesystem and
// home directories, which the signer cannot see — so expand.Literal keeps the
// metacharacter literal and the policy would match a DIFFERENT string than the
// one the remote `$SHELL -c` runs. That is a deny/require_approval bypass:
// "/bin/r[m] -rf x" dodges a `rm` deny (the shell globs r[m]->rm), and
// "cat /etc/{a,shadow}" dodges a "/etc/shadow" deny (the shell brace-expands it).
// Only UNQUOTED literal parts expand; quoted parts ('...', "...", $'...') are
// left to expand.Literal, which decodes them verbatim (the shell won't expand a
// quoted glob either). Rejecting here, before matching, closes the class the same
// way #211/#277 closed quoting/$IFS/encoding obfuscation.
func rejectShellExpansion(w *syntax.Word) error {
	for i, part := range w.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			continue // '...', "...", $'...' don't glob/brace/tilde-expand
		}
		if strings.ContainsAny(lit.Value, "*?[{}") {
			return fmt.Errorf("command word %q contains an unquoted shell glob or brace metacharacter that the target shell would expand; quote it or use an explicit value", lit.Value)
		}
		// Tilde expansion applies only at the very start of a word.
		if i == 0 && strings.HasPrefix(lit.Value, "~") {
			return fmt.Errorf("command word %q begins with an unquoted tilde that the target shell would expand to a home directory; use an explicit path", lit.Value)
		}
	}
	return nil
}

// isStaticWord reports whether w's value is fully determined at policy-decision
// time: it is built only from literals and quoted literals ('...', "...",
// $'...'). Any expansion node — parameter ($x, ${x}, $IFS, $@), command
// substitution, arithmetic, process substitution or extended glob — makes the
// runtime value unknowable to the policy, so the word is treated as non-static
// (the caller rejects it, fail-closed).
func isStaticWord(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
			// Bare literal, '...' , or $'...' (ANSI-C) — all statically known.
		case *syntax.DblQuoted:
			// A double-quoted string is static only if it contains no expansion
			// (e.g. "$x", "$(...)" inside the quotes make it dynamic).
			for _, inner := range p.Parts {
				if _, ok := inner.(*syntax.Lit); !ok {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// isFdRef reports whether w is a bare file-descriptor reference — a decimal fd
// number, or "-" to close the descriptor — the only safe target for a >& / <&
// duplication. Any other word (a filename, or an expansion whose value the
// policy cannot know) means the redirect touches a file and must be rejected; a
// word that is not a single literal is treated as non-fd (fail-closed).
func isFdRef(w *syntax.Word) bool {
	if w == nil || len(w.Parts) != 1 {
		return false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return false
	}
	if lit.Value == "-" {
		return true
	}
	for _, r := range lit.Value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return lit.Value != ""
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
