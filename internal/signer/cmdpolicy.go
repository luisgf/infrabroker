package signer

import (
	"errors"
	"fmt"
	"path"
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
	// and every shell construct outside a small accepted surface (simple
	// commands, pipes, && / || / ;, fd→fd redirects, ( ) / { } grouping, if and
	// while) is rejected unconditionally — command/process substitution,
	// arithmetic, parameter expansion, for/case/[[ ]]/let, file redirects,
	// environment mutations — so a compound command like
	// "kubectl get pods; rm -rf /etc" cannot ride past an allowlist entry that
	// only matches its first word.
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
// that compose it, each as its DECODED literal command (quoting and encoding
// removed), so the policy matches what the target shell will actually run — not
// the caller's quoting.
//
// The accepted surface is deliberately small, and it is an ALLOWLIST of syntax
// node types (#820): anything not named below is rejected, including a node
// type a future parser version adds.
//
// Accepted:
//   - simple commands whose words are all statically known (literalArgs)
//   - pipes (|) and sequences (&&, ||, ;), `!` negation and a trailing `&`
//   - fd→fd redirections between numeric descriptors (2>&1, 1>&2, 2>&-)
//   - the pure grouping / flow constructs whose children are ONLY statements,
//     and which therefore introduce no word the policy does not vet: ( … ),
//     { …; }, if/elif/else and while/until
//
// Rejected, fail closed: every other construct — for / select / C-style for
// (the loop variable is an assignment, the item list is unvetted words), case,
// [[ ]], let, (( )), $(( )), ${…}, $(…), <(…), function declarations, time,
// coproc, |&, file redirects, here-documents, export/declare/… and inline or
// standalone FOO=bar assignments — plus, among simple commands:
//   - command-hiding wrappers (bash -c, env, timeout, python -c, …): the outer
//     CallExpr would under-match denylist/require_approval (#352)
//   - the declaration / arithmetic builtins spelled as an ordinary word
//     ('export' A=1, "let" …), builtins that write a shell variable (read,
//     getopts, unset, printf -v, …) and builtins that would arithmetic-evaluate
//     an argument carrying command-substitution syntax (vetBuiltin)
//
// A command whose value the policy cannot know statically (a parameter /
// command / arithmetic expansion) is rejected rather than matched against an
// incomplete string.
func extractCommands(command string) ([]string, error) {
	// The parser silently DROPS NUL bytes (as bash does when reading a script),
	// so "reboot\x00x" would be decided as "rebootx" — while nothing that
	// executes a command can carry a NUL past its C-string boundary: the best
	// case is a refusal downstream, the worst a truncation to "reboot". Either
	// way the policy would have decided on a string that is not the one run.
	if strings.IndexByte(command, 0) >= 0 {
		return nil, errors.New("command contains a NUL byte")
	}
	// The command reaches the target as ONE argument after "-c" (`$SHELL -c
	// <command>`, `/bin/sh -c <command>`). A string that begins with "-" or "+"
	// is read there as shell OPTIONS, not as a command — and ksh93, given a "+…"
	// string, then reads its commands from standard input (#821, observed with
	// a tracer on stdin). The policy would have decided on a command named
	// "+x" while the shell ran whatever arrived on stdin.
	if strings.HasPrefix(command, "-") || strings.HasPrefix(command, "+") {
		return nil, errors.New("command must not start with '-' or '+': `sh -c` reads such a string as shell options, not as a command (ksh then takes commands from standard input)")
	}
	parser := shellParserPool.Get().(*syntax.Parser)
	defer shellParserPool.Put(parser)
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, fmt.Errorf("shell parse: %w", err)
	}

	var v commandVetter
	syntax.Walk(f, v.visit)
	if v.err != nil {
		return nil, v.err
	}
	if len(v.cmds) == 0 {
		return nil, errors.New("no commands found after shell parse")
	}
	return v.cmds, nil
}

// commandVetter is the syntax.Walk visitor behind extractCommands: it collects
// the decoded simple commands and stops at the first node it does not accept.
type commandVetter struct {
	cmds []string // decoded simple commands, in source order
	err  error    // first rejection; the walk stops there
}

// visit adapts vet to the syntax.Walk callback.
func (v *commandVetter) visit(node syntax.Node) bool {
	if v.err != nil {
		return false
	}
	descend, err := v.vet(node)
	if err != nil {
		v.err = err
		return false
	}
	return descend
}

// vet decides one node. It is a fail-closed ALLOWLIST: a node type is accepted
// only if it has a case below, and the default rejects — that default is the
// #820 fix. The previous walker was a denylist of node types that vetted only
// CallExpr.Args, so a word in any other position (a for-list or loop variable,
// a case subject or pattern, a [[ ]] operand, a let / C-style-for expression, a
// $((…)) outside a simple command's arguments) was never inspected, and a
// command substitution the target shell performs there ran while the policy saw
// only the allowed command next to it.
//
// descend tells syntax.Walk whether to visit the node's children. The two
// word-bearing nodes that are accepted — CallExpr and Redirect — vet their own
// words and return false, so the walker never descends into a word: any Word /
// Lit / quoted part it does reach sits in a position nothing vetted and falls
// to the default. The grouping/flow nodes return true; their children are
// statements only (syntax/nodes.go: Subshell, Block, IfClause and WhileClause
// carry []*Stmt and comments, no Word).
func (v *commandVetter) vet(node syntax.Node) (descend bool, err error) {
	switch n := node.(type) {
	case nil:
		// syntax.Walk calls the visitor with nil after a node's children.
		return true, nil
	case *syntax.File, *syntax.Comment,
		*syntax.Subshell, *syntax.Block, *syntax.IfClause, *syntax.WhileClause:
		return true, nil
	case *syntax.Stmt:
		// `!` negation and a trailing `&` hide no word: the statement's command
		// is vetted either way. A coprocess (mksh `|&`) or zsh disown (`&|`,
		// `&!`) is not produced by the bash-dialect parser; refuse it should
		// that ever change.
		if n.Coprocess || n.Disown {
			return false, errShellConstruct("coprocess / disown statement")
		}
		// A redirection with no command is not a no-op in every shell: zsh runs
		// $NULLCMD (cat) for it — a command the policy never saw (#821).
		if n.Cmd == nil && len(n.Redirs) > 0 {
			return false, errors.New("redirect without a command not allowed (zsh runs $NULLCMD, cat, for it)")
		}
		return true, nil
	case *syntax.BinaryCmd:
		switch n.Op {
		case syntax.AndStmt, syntax.OrStmt, syntax.Pipe:
			return true, nil
		}
		// `|&` is bash-only shorthand for `2>&1 |`, which is accepted; a POSIX
		// sh does not read `|&` as a pipe at all.
		return false, errShellConstruct(n.Op.String() + " pipe")
	case *syntax.Redirect:
		return false, vetRedirect(n)
	case *syntax.CallExpr:
		lit, ok, err := vetCall(n)
		if err != nil {
			return false, err
		}
		if ok {
			v.cmds = append(v.cmds, lit)
		}
		return false, nil
	case *syntax.CmdSubst:
		return false, errors.New("command substitution not allowed")
	case *syntax.ProcSubst:
		return false, errors.New("process substitution not allowed")
	case *syntax.ArithmCmd:
		return false, errors.New("arithmetic command not allowed")
	case *syntax.DeclClause:
		// export / declare / readonly / typeset mutate the environment of a
		// FOLLOWING command (GIT_SSH_COMMAND, LD_PRELOAD, PATH, BASH_ENV, …) but
		// are not a command the allowlist evaluates, while the baked
		// force-command still runs them. They have no place in a force-command
		// allowlist, so reject rather than silently drop them.
		return false, errEnvDeclaration
	default:
		return false, errShellConstruct(shellConstructName(node))
	}
}

// errEnvDeclaration rejects export / declare / readonly / typeset / local,
// whether the parser read the keyword (DeclClause) or an ordinary word that
// decodes to the same builtin (vetBuiltin).
var errEnvDeclaration = errors.New("environment declaration (export/declare/…) not allowed")

// errShellConstruct is the fail-closed rejection of a shell construct outside
// the accepted surface. It names the construct and the remedy, so a caller
// hitting it on a legitimate command knows what to do.
func errShellConstruct(kind string) error {
	return fmt.Errorf("shell construct not allowed by command policy: %s (accepted: simple commands joined by | && || ;, fd-to-fd redirects, ( ) and { } groups, if and while; put anything else in a script on the host)", kind)
}

// shellConstructName names a rejected node for the error message. Node types
// without an entry — including any a future parser version adds — are reported
// by their Go type name; they are rejected all the same.
func shellConstructName(node syntax.Node) string {
	switch n := node.(type) {
	case *syntax.ForClause:
		if n.Select {
			return "select loop"
		}
		return "for loop"
	case *syntax.WordIter, *syntax.CStyleLoop:
		return "for loop"
	case *syntax.CaseClause, *syntax.CaseItem:
		return "case"
	case *syntax.TestClause, *syntax.BinaryTest, *syntax.UnaryTest, *syntax.ParenTest:
		return "[[ ]] test"
	case *syntax.LetClause:
		return "let"
	case *syntax.ArithmExp:
		return "arithmetic expansion $((…))"
	case *syntax.BinaryArithm, *syntax.UnaryArithm, *syntax.ParenArithm, *syntax.FlagsArithm:
		return "arithmetic expression"
	case *syntax.ParamExp:
		return "parameter expansion"
	case *syntax.ExtGlob:
		return "extended glob"
	case *syntax.BraceExp:
		return "brace expansion"
	case *syntax.FuncDecl:
		return "function declaration"
	case *syntax.TimeClause:
		return "time"
	case *syntax.CoprocClause:
		return "coproc"
	case *syntax.Assign, *syntax.ArrayExpr, *syntax.ArrayElem:
		return "assignment"
	case *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
		return "word outside a simple command"
	}
	return strings.TrimPrefix(fmt.Sprintf("%T", node), "*syntax.")
}

// vetRedirect accepts only fd→fd redirections between NUMERIC descriptors
// (2>&1, 1>&2, 2>&-). The operator (>& / <&) is NOT sufficient: ">&FILE" is a
// file write in bash/zsh, so the TARGET must also be a bare fd (a number, or
// "-" to close). Checking the operator alone let ">&/etc/cron.d/x" pass as an
// fd dup while the baked force-command wrote the file (arbitrary write / RCE).
//
// The SOURCE must be numeric too (#820): bash, zsh and ksh read "{NAME}>&2" as
// "open a new descriptor and ASSIGN its number to NAME", so "{PATH}>&2 true"
// rewrites PATH for the commands that follow — an assignment the policy never
// saw, like the standalone FOO=bar it already rejects.
//
// And both descriptors must be a SINGLE digit (#821). The bash-dialect parser
// reads "10>&1" as "duplicate fd 10", but dash, zsh and ksh only take one digit
// before the operator: there it is the ARGUMENT 10 followed by ">&1", so
// `kill -9 10>&1` ran with an argument the policy never saw ("01>&2" likewise).
// A multi-digit target (">&10") is refused for the same reason, fail closed:
// no shell tested ran anything different for it, but dash rejects it outright.
func vetRedirect(r *syntax.Redirect) error {
	isDupFd := (r.Op == syntax.DplOut || r.Op == syntax.DplIn) && isFdRef(r.Word)
	if !isDupFd || r.Hdoc != nil {
		return fmt.Errorf("file redirect not allowed: %s", r.Op)
	}
	if r.N != nil && !isDecimal(r.N.Value) {
		return fmt.Errorf("redirect to a named file descriptor %s not allowed (it assigns a shell variable the policy cannot see; use a numeric descriptor)", r.N.Value)
	}
	if (r.N != nil && len(r.N.Value) != 1) || len(r.Word.Lit()) != 1 {
		return fmt.Errorf("redirect %s%s%s not allowed: only single-digit file descriptors (0-9) mean the same in every shell", litValue(r.N), r.Op, r.Word.Lit())
	}
	return nil
}

// litValue returns l's value, or "" for a nil literal.
func litValue(l *syntax.Lit) string {
	if l == nil {
		return ""
	}
	return l.Value
}

// vetCall vets one simple command and returns its decoded literal form. ok is
// false for an empty CallExpr (no words and no assignments), which is a
// harmless no-op the policy has nothing to match against.
func vetCall(n *syntax.CallExpr) (lit string, ok bool, err error) {
	if len(n.Args) == 0 {
		// A CallExpr with assignments but no command word is a standalone
		// assignment (FOO=bar): invisible to the allowlist yet baked into the
		// force-command, where it changes how a following command runs. Reject
		// it; a truly empty CallExpr is a harmless no-op we skip.
		if len(n.Assigns) > 0 {
			return "", false, errors.New("standalone environment assignment not allowed")
		}
		return "", false, nil
	}
	// An inline env prefix (FOO=bar cmd, LD_PRELOAD=… cmd) mutates how cmd
	// runs but is invisible to the policy regexes — same danger as the
	// standalone assignment and export/declare above (a deny like "^rm " is
	// dodged by "FOO=bar rm -rf"). Reject it.
	if len(n.Assigns) > 0 {
		return "", false, errors.New("inline environment assignment before a command not allowed")
	}
	// Match against the DECODED literal command, not its quoting-preserving
	// source: the target shell removes quoting/encoding at exec time, so
	// matching the printed form let 'rm', r"m" and rm$IFS-rf slip past a
	// deny/allow rule that the executed command would hit (#277). Words whose
	// decoding depends on the shell — $'\x72\x6d' among them — are refused
	// instead (vetWord, #821).
	argv, err := literalArgv(n.Args)
	if err != nil {
		return "", false, err
	}
	if err := vetCommandName(n.Args[0]); err != nil {
		return "", false, err
	}
	lit = strings.Join(argv, " ")
	// Command-hiding wrappers (#352): extractCommands returns the OUTER
	// CallExpr only, so a denylist/require_approval rule anchored on the
	// real binary ("^rm ") never sees "bash -c 'rm …'" / "env rm …" /
	// "timeout 1 rm …". Reject the known wrapper/interpreter set the same
	// way we reject inline env assignments — the policy cannot know which
	// inner argv[0] will run, so fail closed rather than under-match.
	if w, ok := commandHidingWrapper(lit); ok {
		return "", false, fmt.Errorf("command-hiding wrapper %q not allowed (policy cannot see the inner command; quote a direct binary or use an explicit path)", w)
	}
	// find -exec/-execdir/-ok/-okdir (#463) hide the real argv behind
	// `find`, which is routinely allowlisted; the rest of find stays usable.
	if a, ok := findExecAction(lit); ok {
		return "", false, fmt.Errorf("find %s not allowed (policy cannot see the command it runs; run the command directly)", a)
	}
	if err := vetBuiltin(argv); err != nil {
		return "", false, err
	}
	return lit, true, nil
}

// declarationBuiltins are the shell builtins that declare or assign variables.
// Unquoted, the parser reads the bash ones as keywords (DeclClause) and vet
// rejects that node; QUOTED ('export' A=1, ex"port" A=1) the parser reads an
// ordinary simple command, while the shell still runs the same builtin on the
// decoded name. Rejecting the decoded argv[0] keeps the two spellings
// consistent — the policy decides on the decoded command (#277), and a pair of
// quotes must not turn a refused construct into an accepted one. integer /
// float / private / compound are the zsh and ksh typeset variants (builtins in
// zsh, preset aliases of typeset in ksh93), which the bash-dialect parser never
// treats as a keyword. `let` is the same case for LetClause and is handled
// next to this set (vetBuiltin).
var declarationBuiltins = map[string]bool{
	"export": true, "readonly": true, "declare": true, "typeset": true,
	"local": true, "nameref": true, "integer": true, "float": true,
	"private": true, "compound": true,
}

// arithmeticBuiltins are shell builtins observed to ARITHMETIC-EVALUATE one of
// their arguments (a variable name with a subscript, or a number) on at least
// one of bash 3.2 / bash 5.3 / zsh 5.9 / ksh93. Arithmetic evaluation performs
// command substitution on the text it is given, so a statically known, quoted
// argument such as 'a[$(cmd)]' runs cmd even though no CmdSubst node exists in
// the parsed command (#820) — `test 'a[$(cmd)]' -eq 0` and `printf %d
// 'a[$(cmd)]'` on ksh, `exit 'path[$(cmd)]'` on zsh.
//
// This is a BLOCKLIST of names, verified with a benign canary, not a proof: a
// shell, a version or a loadable builtin that was not tested may evaluate an
// argument too. The control that holds is an anchored allowlist with explicit
// paths, which admits none of these builtins unless the operator names them.
var arithmeticBuiltins = map[string]bool{
	"test": true, "[": true, "printf": true, "shift": true, "ulimit": true,
	"exit": true, "return": true, "break": true, "continue": true,
	// zsh / ksh only.
	"print": true, "bye": true, "logout": true, "vared": true, "alarm": true,
	"zparseopts": true,
}

// commandSubstMarkers are the spellings of a command substitution a target
// shell recognises inside arithmetic: $(…), `…`, and the ${ cmd; } / ${|cmd; }
// value substitutions of ksh93, mksh and bash ≥ 5.3. "${" is matched whole — no
// literal argument of an arithmeticBuiltins command needs it.
var commandSubstMarkers = []string{"$(", "`", "${"}

// variableWritingBuiltins are builtins whose only effect is to WRITE (or
// remove) a shell variable. Parameter expansion is rejected everywhere under
// shell_parse, so a variable such a command sets can never be legitimately USED
// by a policy-vetted command: these builtins can only serve to mutate the
// environment of a LATER command — `echo /tmp/evil | read PATH; ls`,
// `getopts a PATH -a; ls`, `unset PATH; ls` — the same class as the FOO=bar
// assignments already refused (#175). They also carried the #820 primitive on
// their own (`read 'a[$(cmd)]'` runs cmd on bash and zsh) and fed it to another
// builtin through a variable (`… | read x; test x -eq 0` on ksh). Refused
// outright. getln, zformat and zregexparse are the zsh equivalents.
var variableWritingBuiltins = map[string]bool{
	"read": true, "getopts": true, "unset": true,
	"getln": true, "zformat": true, "zregexparse": true,
}

// variableWritingFlags are builtins that write a variable only when given one
// option: `printf -v NAME` (bash, zsh), `print -v NAME` (zsh), `wait -p NAME`
// (bash ≥ 5.1), `set -A NAME` (ksh, zsh). Same class as
// variableWritingBuiltins — `printf -v PATH /tmp/evil; ls` — but the builtin
// stays usable without the option. leadingOnly restricts the match to the
// options before the first operand: printf takes no option but -v, and its
// operands may legitimately start with a dash (printf '%s\n' -v).
var variableWritingFlags = map[string]struct {
	flag        byte
	leadingOnly bool
}{
	"printf": {'v', true},
	"print":  {'v', false},
	"wait":   {'p', false},
	"set":    {'A', false},
}

// shellOptionBuiltins change shell OPTIONS, and with them how the words of a
// LATER command are expanded on the target — after the policy has decided on
// those words as literals (#821): `setopt extendedglob; cat /etc/shad#ow` reads
// /etc/shadow on zsh while the policy saw the literal "/etc/shad#ow". Refused
// outright; `set` is held to errorHandlingSet, and `emulate` is refused by the
// wrapper gate.
var shellOptionBuiltins = map[string]bool{
	"setopt": true, "unsetopt": true, "shopt": true,
}

// setLongOptions are the only `set -o NAME` names accepted.
var setLongOptions = map[string]bool{"pipefail": true, "errexit": true, "nounset": true}

// errorHandlingSet reports whether args (the words after `set`) only switch the
// error-handling options on or off — the one use of `set` that changes neither
// how later words expand nor any variable:
//
//	set -e    set -u    set -eu    set -o pipefail    set -o errexit
//	set -o nounset      set +e …   and several of these in one command
//	                               (set -e -u, set -euo pipefail)
//
// The grammar is closed: each argument is "-" or "+" followed by letters from
// {e, u}, optionally ending in "o", which must be followed by one of
// setLongOptions. Everything else is rejected — other options (`set -f`
// disables globbing, `set -k` turns a later NAME=value ARGUMENT into an
// assignment, observed on bash; `set -a`, `set -o <anything else>`), `set -A`,
// `set --` and positional arguments, and a bare `set`.
func errorHandlingSet(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || (a[0] != '-' && a[0] != '+') {
			return false
		}
		letters := a[1:]
		wantsName := strings.HasSuffix(letters, "o")
		if wantsName {
			letters = letters[:len(letters)-1]
		}
		if strings.Trim(letters, "eu") != "" {
			return false
		}
		if wantsName {
			i++
			if i >= len(args) || !setLongOptions[args[i]] {
				return false
			}
		}
	}
	return true
}

// hasOptionLetter reports whether args (the words after argv[0]) carry the
// option letter flag: alone (-v), attached to its value (-vNAME) or bundled
// with other letters (-rv, +A). It stops at "--". With leadingOnly it also
// stops at the first word that is not an option.
func hasOptionLetter(args []string, flag byte, leadingOnly bool) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		isOption := len(a) > 1 && (a[0] == '-' || a[0] == '+')
		if !isOption {
			if leadingOnly {
				return false
			}
			continue
		}
		if strings.IndexByte(a[1:], flag) >= 0 {
			return true
		}
	}
	return false
}

// vetBuiltin rejects, by decoded argv[0] basename (matched like
// commandHidingWrapper: /usr/bin/test and a login-shell "-name" included), the
// builtin classes through which a shell variable is written or the #820
// primitive survives in an ordinary simple command: declaration builtins, let
// and the variable writers outright, and arithmetic-evaluating builtins when
// the decoded command carries command-substitution syntax.
func vetBuiltin(argv []string) error {
	if len(argv) == 0 || argv[0] == "" {
		return nil
	}
	base := strings.TrimPrefix(path.Base(argv[0]), "-")
	if declarationBuiltins[base] {
		return errEnvDeclaration
	}
	if base == "let" {
		return errShellConstruct("let")
	}
	const whyNoVariable = "it writes a shell variable, which under shell_parse no command can read: it could only alter how a later command runs (PATH, IFS, …)"
	if variableWritingBuiltins[base] {
		return fmt.Errorf("%s not allowed (%s)", base, whyNoVariable)
	}
	if f, ok := variableWritingFlags[base]; ok && hasOptionLetter(argv[1:], f.flag, f.leadingOnly) {
		return fmt.Errorf("%s -%c not allowed (%s)", base, f.flag, whyNoVariable)
	}
	if shellOptionBuiltins[base] {
		return fmt.Errorf("%s not allowed (it changes how the shell expands the words of later commands, which the policy has already decided on)", base)
	}
	if base == "set" && !errorHandlingSet(argv[1:]) {
		return errors.New("set is limited to the error-handling options (set -e, set -u, set -o pipefail, set -o errexit, set -o nounset, and + to turn them off): any other form changes how the shell expands or assigns the words of later commands")
	}
	if !arithmeticBuiltins[base] {
		return nil
	}
	for _, a := range argv[1:] {
		for _, m := range commandSubstMarkers {
			if strings.Contains(a, m) {
				return fmt.Errorf("%s argument contains %q: command-substitution syntax that this shell builtin would evaluate and run; pass a literal value", base, m)
			}
		}
	}
	return nil
}

// literalArgs returns a simple command's argument words decoded to their literal
// values and joined by single spaces — the form the target shell will actually
// execute, with all quoting/encoding removed so the command policy matches what
// runs instead of the caller's quoting (#277). It fails closed on any word whose
// value is not statically knowable (a parameter/command/arithmetic expansion,
// process substitution or extended glob): such a word is rejected rather than
// matched against an incomplete string. It equally fails closed on a word the
// decode would resolve DIFFERENTLY from the target shell — an unquoted glob /
// brace / tilde (GHSA-937v-rmqp-j3hx) or an unquoted backslash escape (#308).
func literalArgs(args []*syntax.Word) (string, error) {
	argv, err := literalArgv(args)
	if err != nil {
		return "", err
	}
	return strings.Join(argv, " "), nil
}

// literalArgv is literalArgs before the join: one decoded string per word, so
// a caller that must tell the words apart (vetBuiltin's option matching) is not
// misled by a quoted argument that contains a space.
func literalArgv(args []*syntax.Word) ([]string, error) {
	// A fresh config per call: expand.Literal mutates the *Config it is given
	// (prepareConfig sets Env/ifs in place), so a shared instance would race
	// under concurrent Decide calls. NoUnset makes any parameter reference that
	// slips past isStaticWord an error rather than a silent "" expansion; a nil
	// ReadDir disables globbing so a bare "*" stays literal.
	cfg := &expand.Config{NoUnset: true}
	parts := make([]string, 0, len(args))
	for _, w := range args {
		if err := vetWord(w); err != nil {
			return nil, err
		}
		lit, err := expand.Literal(cfg, w)
		if err != nil {
			return nil, fmt.Errorf("decoding command word: %w", err)
		}
		parts = append(parts, lit)
	}
	return parts, nil
}

// vetWord is THE static-word predicate: it reports why w's value cannot be
// known at decision time, or would be read differently by a shell the command
// may run under, and nil when the word is safe to decode with expand.Literal.
// literalArgv (the policy) and directArgv (elevation) both go through it, so
// the two cannot drift: a word the policy refuses is never handed to sudo as a
// decoded argv either.
//
// The signer does not know which shell parses the command — the account's login
// shell for the force-command, /bin/sh for the sudo wrapper and the sealed-exec
// shim — so a word is accepted only if dash, bash, zsh and ksh all read it as
// the same literal. In order:
//
//   - $'…' and $"…" (#821): bash ANSI-C / locale quoting. dash has neither and
//     zsh no $"…": there "$" is a literal dollar followed by an ordinary quoted
//     string, in which a backslash does not escape a quote — so the \' that
//     sits INSIDE the string for bash ENDS it for dash, and the rest of the
//     "argument" is shell syntax. The #277 decode of $'\x72\x6d' is superseded:
//     such a word is refused, not decoded.
//   - any expansion node (isStaticWord);
//   - an unquoted glob / brace / tilde / leading "=" (rejectShellExpansion);
//   - an unquoted backslash escape (unquotedBackslash, #308);
//   - a "$" the parser left literal but zsh expands (rejectLiteralDollar).
func vetWord(w *syntax.Word) error {
	if dollarQuoted(w) {
		return errors.New(`command word uses $'…' or $"…" quoting, which not every shell implements (dash has neither, zsh no $"…") and which such a shell reads as different words or commands; use plain '…' or "…" quotes`)
	}
	if !isStaticWord(w) {
		return errors.New("command word with a parameter/command/arithmetic expansion not allowed")
	}
	if err := rejectShellExpansion(w); err != nil {
		return err
	}
	if bs, ok := unquotedBackslash(w); ok {
		return fmt.Errorf("command word %q contains an unquoted backslash escape that the target shell would consume; quote it or use an explicit value", bs)
	}
	return rejectLiteralDollar(w)
}

// vetCommandName fails closed on three spellings of a command NAME (the first
// word of a simple command) that one shell reads as syntax, so that the words
// after it — which the policy took for that command's arguments, or for part
// of its name — are what actually runs (#821, each observed with a tracer):
//
//   - a trailing unquoted ":" — ksh93 reads `NAME: cmd args` as a LABEL
//     followed by the command `cmd args`. `x: rm -rf /srv` was the command "x:"
//     for the policy and `rm -rf /srv` for ksh. The no-op builtin ":" itself is
//     not a label and stays accepted.
//
//   - a leading unquoted "!" — zsh reads "&!" as ONE operator (background and
//     disown), so in `true &!rm -rf /srv` the policy saw the command "!rm" and
//     zsh ran `rm -rf /srv`. (`! cmd`, with a space, is negation and never
//     reaches here as a word.)
//
//   - an unquoted "=" anywhere in the name — the parser turns NAME=value into
//     an assignment (which is rejected) only when NAME is a bash identifier,
//     and reads any other "x=y" first word as a command name. Other shells
//     assign to more names: zsh to positional parameters, so `1=x rm -rf /srv`
//     was the command "1=x" for the policy and `rm -rf /srv` for zsh; ksh to
//     dotted names (`a.b=c cmd`, `.sh.x=1 cmd`), which ksh93u+ then refuses
//     for an unknown variable, running nothing — that being its variable
//     table deciding, not the syntax, the rule is not limited to digits.
//
// A quoted ":", "!" or "=" is literal in every shell and is not affected.
func vetCommandName(w *syntax.Word) error {
	if w == nil || len(w.Parts) == 0 {
		return nil
	}
	for _, part := range w.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.Contains(lit.Value, "=") {
			return fmt.Errorf("command name %q contains an unquoted '=': zsh (1=x cmd) and ksh (a.b=c cmd) read such a word as an assignment in front of the real command; quote it", lit.Value)
		}
	}
	if first, ok := w.Parts[0].(*syntax.Lit); ok && strings.HasPrefix(first.Value, "!") {
		return fmt.Errorf("command name %q begins with an unquoted '!': zsh reads \"&!\" as one operator, so after a backgrounded command it runs the rest of the word as the command; quote it", first.Value)
	}
	if last, ok := w.Parts[len(w.Parts)-1].(*syntax.Lit); ok && strings.HasSuffix(last.Value, ":") && (len(w.Parts) > 1 || last.Value != ":") {
		return fmt.Errorf("command name %q ends with an unquoted ':': ksh reads NAME: as a label and runs the words after it as the command; quote it", last.Value)
	}
	return nil
}

// dollarQuoted reports whether w carries a $'…' (ANSI-C) or $"…" (locale)
// quoted part.
func dollarQuoted(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted:
			if p.Dollar {
				return true
			}
		case *syntax.DblQuoted:
			if p.Dollar {
				return true
			}
		}
	}
	return false
}

// rejectLiteralDollar fails closed on a "$" that the bash-dialect parser kept
// as a LITERAL character but that is not the last character of its literal.
// The parser treats "$" as an expansion only before a name, a digit, a special
// parameter or an opening ( { [ ' " — every other "$" stays in the word. zsh
// has more forms: $^name, $=name, $~name and $+name are parameter expansions
// there, unquoted and inside double quotes alike, so `cat $~HOME/.ssh/id_rsa`
// read a file under the home directory while the policy decided on the literal
// "$~HOME/.ssh/id_rsa" (#821; the same reason $HOME is refused).
//
// Rather than enumerate one shell's forms, any such "$" followed by another
// character is refused. A "$" that ends the word or a double-quoted string
// (`grep foo$ file`, "100$") is literal in every shell and stays accepted, and
// so is an escaped one: inside double quotes the literal keeps its backslashes,
// so "\$x" is skipped as an escape pair while "\\$x" (an escaped backslash,
// then a live "$") is not. Single-quoted text is never touched.
func rejectLiteralDollar(w *syntax.Word) error {
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			// Unquoted: unquotedBackslash has already refused any backslash, so
			// every "$" here is unescaped.
			if hasLiveDollar(p.Value, false, i == len(w.Parts)-1) {
				return errLiteralDollar(p.Value)
			}
		case *syntax.DblQuoted:
			for j, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok && hasLiveDollar(lit.Value, true, j == len(p.Parts)-1) {
					return errLiteralDollar(lit.Value)
				}
			}
		}
	}
	return nil
}

// hasLiveDollar reports whether s holds an unescaped "$" that something
// follows. The parser may hand a literal "$" over as a part of its own ("$" then
// "^PATH"), so a "$" that ends s is followed by something unless s is the last
// part of its word or double-quoted string. With escapes, a backslash and the
// character after it are skipped as a pair (the double-quote rule).
func hasLiveDollar(s string, escapes, last bool) bool {
	for i := 0; i < len(s); i++ {
		switch {
		case escapes && s[i] == '\\':
			i++
		case s[i] == '$' && (i != len(s)-1 || !last):
			return true
		}
	}
	return false
}

func errLiteralDollar(lit string) error {
	return fmt.Errorf(`command word %q contains a '$' that is not at the end of the word: zsh expands $^name, $=name, $~name and $+name where other shells keep a literal dollar; single-quote it, or write \$ inside double quotes`, lit)
}

// directArgv reports whether command is one simple command whose words are all
// statically known, returning its decoded argv. That is the shape that can be
// elevated by handing the words straight to sudo — "sudo -n -- systemctl
// restart nginx.service" — so the host's sudoers rule authorizes the real
// binary with its literal arguments (least privilege, mirroring
// command_policies) instead of a generic /bin/sh (#306). Anything with shell
// semantics reports false and keeps the /bin/sh -c wrapper: pipes/sequences
// (>1 statement or a non-CallExpr), redirects (fd-dups included — without a
// shell nothing interprets them), env assignments, expansions, globs. Its words
// go through the same predicate as the policy's (vetWord), so both fail closed
// on anything the signer cannot resolve statically or that a shell may read
// differently.
func directArgv(command string) ([]string, bool) {
	// The parser drops NUL bytes (see extractCommands): never decode around one.
	if strings.IndexByte(command, 0) >= 0 {
		return nil, false
	}
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
	if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 || vetCommandName(call.Args[0]) != nil {
		return nil, false
	}
	// Fresh config per call: expand.Literal mutates it (see literalArgs).
	cfg := &expand.Config{NoUnset: true}
	argv := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		if vetWord(w) != nil {
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

// commandHidingWrappers are argv[0] basenames that re-introduce a different
// real command after the outer CallExpr the policy matches. Under shell_parse,
// denylist and require_approval regexes see only the outer string — so
// "bash -c 'rm -rf /'" would dodge a "^rm " deny the way FOO=bar rm once did
// (#175). Rejecting the wrapper class at extract time is fail-closed for both
// denylist and allowlist (operators who need an interpreter use a direct path
// to a script file, or opt out with shell_parse:false for that host).
//
// The set is the common shells, pure wrappers that always exec another argv,
// privilege wrappers (sudo/su/… — the product's own elevation path), the
// eval-class source builtins (. / source), and scripting interpreters whose
// -c/-e forms are the usual smuggle path. Path forms (/bin/bash, /usr/bin/sudo)
// match via path.Base. "." is listed so ` . /tmp/evil` is rejected the same
// way eval is (#371, sibling of #352).
var commandHidingWrappers = map[string]bool{
	// Shells / login shells
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"csh": true, "tcsh": true, "fish": true, "ash": true,
	// Pure wrappers (always run another command)
	"env": true, "eval": true, "exec": true, "command": true,
	"nice": true, "nohup": true, "timeout": true, "stdbuf": true,
	"xargs": true, "busybox": true, "ionice": true, "chrt": true,
	"setarch": true, "linux32": true, "linux64": true, "catchsegv": true,
	"rlwrap": true, "script": true, "watch": true, "time": true,
	// Privilege wrappers: the outer argv[0] is sudo/su/… so an anchored
	// deny/require_approval on the real binary ("^rm ") never matches.
	// Elevation belongs on the Sudo intent flag, not in the command string.
	"sudo": true, "su": true, "doas": true, "pkexec": true,
	"runuser": true, "sg": true,
	// Source builtins — same class as eval (already listed): they run a
	// file the policy cannot see.
	".": true, "source": true,
	// Deferred / indirect execution builtins (#461): trap runs its argument
	// on a signal or at EXIT, builtin re-dispatches to eval/source/exec by
	// name, hash -p and enable bind a name to an arbitrary binary or .so,
	// mapfile/readarray -C run a callback per line. The policy sees argv[0]
	// as the builtin, so an anchored deny/require_approval on the real
	// command never matches — reject them like eval.
	"trap": true, "builtin": true, "hash": true, "enable": true,
	"mapfile": true, "readarray": true,
	// compgen -C <cmd> / -F <func> run their argument to produce completions
	// (complete -C/-F registers the same callbacks); bash-only, same class.
	"compgen": true, "complete": true,
	// #463: the shells, interpreters and pure wrappers #352/#371/#377 still
	// missed. ssh is listed because `ssh other cmd` runs cmd on a host the
	// policy of THIS host never sees (lateral move); hosts are reached through
	// the broker, not from each other.
	"mksh": true, "lksh": true, "pdksh": true, "rbash": true, "yash": true,
	"posh": true, "pypy": true, "pypy3": true, "ipython": true,
	"ipython3": true, "Rscript": true, "julia": true, "bun": true,
	"deno": true, "elixir": true, "erl": true, "escript": true,
	"guile": true, "racket": true,
	"setsid": true, "flock": true, "taskset": true, "chroot": true,
	"unshare": true, "nsenter": true, "strace": true, "ltrace": true,
	"systemd-run": true, "setpriv": true, "prlimit": true, "cpulimit": true,
	"daemonize": true, "expect": true, "tmux": true, "screen": true,
	"ssh": true,
	// #820: words that run the command FOLLOWING them and so defeat every gate
	// keyed on argv[0] — this one and the builtin gates in vetBuiltin
	// (`noglob exit 'path[$(cmd)]'` on zsh). zsh precommand modifiers and
	// reserved words (noglob cmd, nocorrect cmd, repeat N cmd, emulate sh -c
	// '…'; the bare "-" modifier is matched in commandHidingWrapper), the
	// ksh93 preset alias redirect (= `command exec`), zsh's deferred-eval
	// `zstyle -e`, its autoloadable xargs (`autoload zargs; zargs -- … --
	// cmd`) and its pty runner (`zmodload zsh/zpty; zpty x cmd`), and macOS
	// caffeinate.
	"noglob": true, "nocorrect": true, "repeat": true, "emulate": true,
	"redirect": true, "zstyle": true, "autoload": true, "zargs": true,
	"zpty": true, "caffeinate": true,
	// Scripting interpreters (typical -c/-e smuggle)
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "node": true, "nodejs": true,
	"php": true, "lua": true, "tclsh": true,
	"awk": true, "gawk": true, "nawk": true, "mawk": true,
}

// commandHidingWrapper reports whether the decoded simple-command string begins
// with a known wrapper/interpreter basename. lit is the space-joined form from
// literalArgs; the first field is argv[0] (static words only, so no IFS tricks).
func commandHidingWrapper(lit string) (string, bool) {
	argv0, _, _ := strings.Cut(lit, " ")
	if argv0 == "" {
		return "", false
	}
	// zsh's bare "-" precommand modifier (`- cmd` runs cmd with a "-" prepended
	// to its argv[0]); the dash-stripping below would reduce it to "".
	if argv0 == "-" {
		return "-", true
	}
	base := path.Base(argv0)
	// Login shells may appear as "-bash"; strip one leading dash.
	base = strings.TrimPrefix(base, "-")
	if commandHidingWrappers[base] {
		return base, true
	}
	// Versioned interpreters (#377): python3.12, ruby3.2, node18, php8.3.
	// Exact unversioned names live in the map; a trailing version suffix is
	// the same smuggle path and is what current distros actually ship.
	if fam, ok := versionedInterpreter(base); ok {
		return fam, true
	}
	return "", false
}

// findExecAction reports whether lit is a `find` invocation carrying an
// action that executes another command (-exec, -execdir, -ok, -okdir). The
// command after the action is the one that runs, so an anchored
// deny/require_approval on it would never match (#463).
func findExecAction(lit string) (string, bool) {
	fields := strings.Fields(lit)
	if len(fields) == 0 || path.Base(fields[0]) != "find" {
		return "", false
	}
	for _, f := range fields[1:] {
		switch f {
		case "-exec", "-execdir", "-ok", "-okdir":
			return f, true
		}
	}
	return "", false
}

// versionedInterpreterPrefixes are argv[0] families whose unversioned
// basename is already in commandHidingWrappers. Longer prefixes first so
// python3.12 matches python3, not python.
var versionedInterpreterPrefixes = []string{
	// python is not listed: python3 would otherwise look like python+"3".
	// Unversioned `python` lives in the exact map; versioned CPython is
	// always python2.N / python3.N.
	"python3", "python2",
	"nodejs", "node",
	"ruby", "php", "perl", "lua",
	// #463: distros ship versioned shell binaries too (zsh5, ksh93, bash5).
	"mksh", "zsh", "ksh", "bash",
}

// versionedInterpreter reports whether base is a known interpreter plus a
// version suffix (python3.12, ruby3.2, node18). It does not match
// python3-config or other hyphenated helpers.
func versionedInterpreter(base string) (string, bool) {
	for _, p := range versionedInterpreterPrefixes {
		if !strings.HasPrefix(base, p) || base == p {
			continue
		}
		if isVersionSuffix(base[len(p):]) {
			return p, true
		}
	}
	return "", false
}

// isVersionSuffix reports whether s is a trailing interpreter version:
// optional leading '.', then digits and dots only (".12", "18", "3.2", "5.36").
func isVersionSuffix(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '.' {
		if len(s) < 2 {
			return false
		}
		i = 1
	}
	if s[i] < '0' || s[i] > '9' {
		return false
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// unquotedBackslash returns the first UNQUOTED literal part of w that carries a
// backslash. `expand.Literal` keeps such a backslash verbatim while the target
// shell consumes it as an escape, so the decoded value differs from what the
// shell runs ("touch a\ b" is one argument to the shell, two literal words
// here; "r\m" decodes to `r\m` but executes as `rm`). Both callers fail closed
// on it, for the two consequences of that divergence:
//
//   - literalArgs (#308): the policy would decide against a string the shell
//     never runs, so a deny / require_approval rule the executed command hits is
//     dodged — the same bypass class as #277 (quoting/encoding) and
//     GHSA-937v-rmqp-j3hx (glob/brace/tilde). The command is rejected.
//   - directArgv (#306): the direct sudo argv would differ from what the
//     historical `sh -c` wrapper executed, so the wrapper is kept.
//
// Only UNQUOTED parts diverge: expand.Literal decodes '...' and "..." exactly as
// every shell does (`"a\b"`→`a\b`, `"a\$b"`→`a$b`; checked on dash, bash, zsh
// and ksh for \\ \" \$ \` and for a backslash before any other character, which
// all of them keep), so inspecting the top-level *syntax.Lit parts is the
// precise predicate and quoted backslashes keep working. ($'...' is not decoded
// at all any more: vetWord refuses it, #821.)
func unquotedBackslash(w *syntax.Word) (string, bool) {
	for _, part := range w.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.Contains(lit.Value, `\`) {
			return lit.Value, true
		}
	}
	return "", false
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
// Only UNQUOTED literal parts expand; quoted parts ('...', "...") are left to
// expand.Literal, which decodes them verbatim (the shell won't expand a quoted
// glob either). Rejecting here, before matching, closes the class the same
// way #211/#277 closed quoting/$IFS/encoding obfuscation.
func rejectShellExpansion(w *syntax.Word) error {
	// The "start of the word" the shell sees is the first part that is not an
	// empty quoted string: "" and '' contribute nothing, so ""=rm and ""~/x
	// expand exactly like =rm and ~/x (#544). Checking w.Parts[0] alone let
	// those, and ="rm" (a one-character Lit followed by a quoted part), through.
	first := 0
	for first < len(w.Parts) && isEmptyQuoted(w.Parts[first]) {
		first++
	}
	for i, part := range w.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			continue // '...' and "..." don't glob/brace/tilde-expand
		}
		if strings.ContainsAny(lit.Value, "*?[{}") {
			return fmt.Errorf("command word %q contains an unquoted shell glob or brace metacharacter that the target shell would expand; quote it or use an explicit value", lit.Value)
		}
		// Tilde expansion applies only at the very start of a word — including
		// ~"root"/x, where the quoted part merely ends the user name.
		if i == first && strings.HasPrefix(lit.Value, "~") {
			return fmt.Errorf("command word %q begins with an unquoted tilde that the target shell would expand to a home directory; use an explicit path", lit.Value)
		}
		// bash (outside POSIX mode) also expands a tilde in the middle of an
		// ARGUMENT shaped like an assignment, after the "=" and after each ":"
		// — `dd if=~root/.ssh/id_rsa` reads /root/.ssh/id_rsa and `x PATH=/a:~`
		// expands too, while the policy decided on the literal "~" (#821). It
		// happens only inside one unquoted literal (PATH=""~ and PATH"="~ are
		// left alone), so the substring test is the precise predicate; it is
		// applied to every such literal, whatever precedes the "=".
		if strings.Contains(lit.Value, "=~") || strings.Contains(lit.Value, ":~") {
			return fmt.Errorf("command word %q has an unquoted tilde after '=' or ':' that bash would expand to a home directory; quote it or use an explicit path", lit.Value)
		}
		// zsh EQUALS expansion (#462): an unquoted word that begins with "="
		// and names something ("=rm", in ANY argument position) is replaced by
		// the resolved path of that command before exec, so the policy would
		// decide on "=rm" while the target account's login shell runs /bin/rm.
		// A bare "=" (test a = b) is left alone by zsh and stays allowed; a
		// fully quoted "'=rm'" is not a Lit and is decoded verbatim. ="rm" is
		// the Lit "=" plus a quoted part, and zsh expands it too (#544), hence
		// the len(w.Parts) > 1 clause. The sudo direct-argv path already quotes
		// such words (shellSafeWord).
		if i == first && strings.HasPrefix(lit.Value, "=") && (len(lit.Value) > 1 || len(w.Parts) > 1) {
			return fmt.Errorf("command word %q begins with an unquoted '=' that zsh (EQUALS) would expand to a command path; quote it or use an explicit path", lit.Value)
		}
	}
	return nil
}

// isEmptyQuoted reports whether part is an empty ” or "" — a quoted part
// the shell drops before expansion, so it does not move the start of the word.
func isEmptyQuoted(part syntax.WordPart) bool {
	switch p := part.(type) {
	case *syntax.SglQuoted:
		return p.Value == ""
	case *syntax.DblQuoted:
		return len(p.Parts) == 0
	}
	return false
}

// isStaticWord reports whether w's value is fully determined at policy-decision
// time: it is built only from literals and plainly quoted literals ('...',
// "..."). Any expansion node — parameter ($x, ${x}, $IFS, $@), command
// substitution, arithmetic, process substitution or extended glob — makes the
// runtime value unknowable to the policy, so the word is treated as non-static
// (the caller rejects it, fail-closed). So does a dollar-quoted part ($'...',
// $"..."): its value depends on whether the target shell implements that
// quoting (#821; vetWord reports it with its own message first).
func isStaticWord(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			// Bare literal.
		case *syntax.SglQuoted:
			if p.Dollar {
				return false
			}
		case *syntax.DblQuoted:
			if p.Dollar {
				return false
			}
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
	return lit.Value == "-" || isDecimal(lit.Value)
}

// isDecimal reports whether s is a non-empty run of ASCII digits — a numeric
// file descriptor.
func isDecimal(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
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
