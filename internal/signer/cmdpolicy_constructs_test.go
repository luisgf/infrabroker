package signer

import (
	"strings"
	"testing"
)

// hiddenWordWrappers are the #820 reproductions, parameterised on the payload
// hidden in a word the walker never vetted and on the simple command the policy
// does see. Each one is a compound command whose only CallExpr is `visible`,
// while the target shell also runs (or is steered by) `hidden`:
//
//	0  $(( '…' ))   — the shell performs command substitution on the text inside
//	                  arithmetic even though the parser models it as an inert '…'
//	                  (runs on dash, bash, zsh and ksh)
//	1  $((x))       — re-evaluates the for-list item as arithmetic
//	2  [[ … -eq ]]  — arithmetic-evaluates a quoted operand
//	3  let          — ditto
//	4  for ((…))    — ditto
//	5  for NAME in  — the loop variable is an assignment the policy never saw
func hiddenWordWrappers(hidden, visible string) []string {
	return []string{
		`case $(( '$(` + hidden + `)' )) in *) ` + visible + `;; esac`,
		`for x in 'a[$(` + hidden + `)]'; do for y in $((x)); do ` + visible + `; done; done`,
		`[[ 'a[$(` + hidden + `)]' -eq 0 ]]; ` + visible,
		`let 'a[$(` + hidden + `)]=1'; ` + visible,
		`for ((i='a[$(` + hidden + `)]'; i<0; i++)); do ` + visible + `; done`,
		`for PATH in /tmp/evil; do ` + visible + `; done`,
	}
}

// TestShellParseHiddenWordBypassClosed is the #820 regression. The walker used
// to be a DENYLIST of node types that vetted only CallExpr.Args, so a word in a
// for-list, a case subject, [[ ]], let, a C-style for or a $((…)) outside a
// simple command's arguments was never inspected: the policy decided on the one
// allowed command it could see while the signed force-command carried the whole
// string. Every reproduction must now fail closed, on every policy mode.
func TestShellParseHiddenWordBypassClosed(t *testing.T) {
	t.Parallel()

	const okCmd = `/usr/bin/systemctl status nginx`
	policies := []struct {
		name    string
		ps      PolicySet
		hidden  string
		visible string
	}{
		// The control ARCHITECTURE.md says "holds": a fully anchored allowlist
		// with an explicit path.
		{"anchored allowlist", PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`^/usr/bin/systemctl status nginx$`}}}, `touch /tmp/pwn`, okCmd},
		// Denylist: the hidden command is one a deny rule names.
		{"denylist", PolicySet{{Mode: CmdPolicyDenylist, Deny: []string{`rm`, `shadow`}}}, `rm -rf /srv/data`, `true`},
		{"denylist (shadow)", PolicySet{{Mode: CmdPolicyDenylist, Deny: []string{`rm`, `shadow`}}}, `cat /etc/shadow`, `true`},
		// require_approval only: the hidden command must not run unapproved.
		{"require_approval", PolicySet{{RequireApproval: []string{`reboot`}}}, `reboot`, `true`},
	}
	for _, p := range policies {
		for i, cmd := range hiddenWordWrappers(p.hidden, p.visible) {
			allowed, needsApproval, rule, err := p.ps.Decide(cmd)
			if allowed || err == nil {
				t.Errorf("%s, repro %d: Decide(%q) = allowed=%v needsApproval=%v rule=%q err=%v; want a fail-closed rejection",
					p.name, i, cmd, allowed, needsApproval, rule, err)
				continue
			}
			if !strings.Contains(err.Error(), "shell construct not allowed by command policy") {
				t.Errorf("%s, repro %d: error must name the rejected construct, got: %v", p.name, i, err)
			}
			if !strings.HasPrefix(rule, "shell-parse:") {
				t.Errorf("%s, repro %d: rule = %q, want a shell-parse: rule", p.name, i, rule)
			}
		}
	}

	// The plain form of the same payload was (and stays) rejected: the control.
	ctl := PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`^/usr/bin/systemctl status nginx$`}}}
	if allowed, _, _, err := ctl.Decide(`$(touch /tmp/pwn); ` + okCmd); allowed || err == nil {
		t.Errorf("plain command substitution must stay rejected (allowed=%v err=%v)", allowed, err)
	}
	// And the allowed command alone still passes.
	if allowed, _, rule, err := ctl.Decide(okCmd); !allowed || err != nil || rule != `allow:^/usr/bin/systemctl status nginx$` {
		t.Errorf("the allowed command must still pass (allowed=%v rule=%q err=%v)", allowed, rule, err)
	}

	// Elevation consistency: none of the reproductions is a "simple command"
	// that BuildElevatedCommand would hand to sudo as a direct argv.
	for i, cmd := range hiddenWordWrappers(`touch /tmp/pwn`, okCmd) {
		if argv, ok := directArgv(cmd); ok {
			t.Errorf("repro %d: directArgv(%q) must not classify as simple, got %q", i, cmd, argv)
		}
	}
}

// TestShellParseRejectsConstructs pins one sample per shell construct the
// command policy refuses. Each row asserts the error NAMES the construct (not
// merely that the command was denied), so a row cannot pass through some other
// rule. The policy is a catch-all allowlist: only the parse can reject.
func TestShellParseRejectsConstructs(t *testing.T) {
	t.Parallel()

	const construct = "shell construct not allowed by command policy: "
	tests := []struct {
		name    string
		command string
		wantErr string
	}{
		// Rejected by the fail-closed default of the node allowlist (#820).
		{"for loop", `for x in a b; do true; done`, construct + "for loop"},
		{"for loop variable (env mutation)", `for PATH in /tmp/evil; do true; done`, construct + "for loop"},
		{"for without in", `for x; do true; done`, construct + "for loop"},
		{"select loop", `select x in a; do true; done`, construct + "select loop"},
		{"C-style for", `for ((i=0; i<1; i++)); do true; done`, construct + "for loop"},
		{"case", `case x in x) true;; esac`, construct + "case"},
		{"case with arithmetic subject", `case $((1)) in *) true;; esac`, construct + "case"},
		{"[[ ]] test", `[[ a == a ]]`, construct + "[[ ]] test"},
		{"[[ ]] then command", `[[ a -eq 0 ]]; true`, construct + "[[ ]] test"},
		{"let", `let x=1`, construct + "let"},
		{"function declaration", `f() { true; }; f`, construct + "function declaration"},
		{"function keyword", `function f { true; }`, construct + "function declaration"},
		{"time", `time true`, construct + "time"},
		{"coproc", `coproc true`, construct + "coproc"},
		{"|& pipe", `true |& true`, construct + "|&"},
		{"nested in an accepted group", `{ true; for x in a; do true; done; }`, construct + "for loop"},
		{"nested in if", `if true; then case x in x) true;; esac; fi`, construct + "case"},
		{"nested in while condition", `while [[ a -eq 0 ]]; do true; done`, construct + "[[ ]] test"},
		{"nested in a subshell", `( let x=1 )`, construct + "let"},
		// A named-fd redirect assigns a shell variable ({PATH}>&2 sets PATH to the
		// new descriptor number): an assignment the policy never saw.
		{"named-fd redirect before", `{PATH}>&2 true`, "redirect to a named file descriptor"},
		{"named-fd redirect after", `true {fd}>&1`, "redirect to a named file descriptor"},
		// Already rejected before #820, with their own messages (kept).
		{"(( )) command", `(( 1 ))`, "arithmetic command not allowed"},
		{"(( )) with a quoted payload", `(( 'a[$(touch /tmp/pwn)]' ))`, "arithmetic command not allowed"},
		{"(( )) in an if condition", `if ((1)); then true; fi`, "arithmetic command not allowed"},
		// The parser always reads "((" as the start of arithmetic — never as
		// two nested subshells (an accepted node), the reading bash falls back
		// to. So a "((" the shell would evaluate arithmetically can never be
		// accepted as ( ( … ) ); these fail to parse instead.
		{"(( that is not arithmetic", `((echo 'a[$(touch /tmp/pwn)]'))`, "shell parse"},
		{"(( closed as nested subshells", `((true); true)`, "shell parse"},
		{"export", `export A=1; true`, "environment declaration"},
		{"declare", `declare -x A=1; true`, "environment declaration"},
		{"standalone assignment", `A=1; true`, "standalone environment assignment"},
		{"array assignment", `x=(a b); true`, "standalone environment assignment"},
		{"inline assignment", `A=1 true`, "inline environment assignment"},
		{"file redirect", `true > /tmp/out`, "file redirect not allowed"},
		{"here-string", `true <<< x`, "file redirect not allowed"},
		{"here-document", "true <<EOF\nx\nEOF", "file redirect not allowed"},
		{"$(( )) in an argument", `echo $((1+1))`, "expansion not allowed"},
		{"${} in an argument", `echo ${HOME}`, "expansion not allowed"},
		{"$( ) in an argument", `echo $(id)`, "expansion not allowed"},
		{"backticks in an argument", "echo `id`", "expansion not allowed"},
		{"process substitution", `cat <(id)`, "expansion not allowed"},
		{"extended glob", `ls @(a|b)`, "expansion not allowed"},
		{"brace expansion", `ls {a,b}`, "glob or brace"},
	}
	ps := PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`.*`}}}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allowed, _, rule, err := ps.Decide(tc.command)
			if allowed || err == nil {
				t.Fatalf("Decide(%q) = allowed=%v rule=%q err=%v; want a rejection", tc.command, allowed, rule, err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Decide(%q) error = %q, want it to contain %q", tc.command, err, tc.wantErr)
			}
		})
	}
}

// TestShellParseAcceptedFormsUnchanged is the other half of #820: the accepted
// surface — simple commands, pipes, && / || / ;, fd→fd redirects, quoting,
// ( ) and { } grouping, if and while/until — keeps deciding exactly as before,
// with every inner simple command still checked individually.
func TestShellParseAcceptedFormsUnchanged(t *testing.T) {
	t.Parallel()

	ps := PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`^a( |$)`, `^b( |$)`, `^c$`, `^d$`}}}
	tests := []struct {
		command     string
		wantCmds    []string // what extractCommands returns
		wantAllowed bool
	}{
		{`a`, []string{"a"}, true},
		{`a x y`, []string{"a x y"}, true},
		{`a | b`, []string{"a", "b"}, true},
		{`a | b | c`, []string{"a", "b", "c"}, true},
		{`a && b || c; d`, []string{"a", "b", "c", "d"}, true},
		{`a 2>&1`, []string{"a"}, true},
		{`a 1>&2 2>&-`, []string{"a"}, true},
		{`a 2>&1 | b`, []string{"a", "b"}, true},
		{`a 'x y' "z w"`, []string{"a x y z w"}, true},
		{`'a' "x"`, []string{"a x"}, true},
		{`( a; b )`, []string{"a", "b"}, true},
		{`{ a; b; }`, []string{"a", "b"}, true},
		{`( a; b ) 2>&1 | c`, []string{"a", "b", "c"}, true},
		{`if a; then b; fi`, []string{"a", "b"}, true},
		{`if a; then b; elif c; then d; else a; fi`, []string{"a", "b", "c", "d", "a"}, true},
		{`while a; do b; done`, []string{"a", "b"}, true},
		{`until a; do b; done`, []string{"a", "b"}, true},
		{`! a`, []string{"a"}, true},
		{`a &`, []string{"a"}, true},
		{`a; b &`, []string{"a", "b"}, true},
		{`a # trailing comment`, []string{"a"}, true},
		// One inner command is NOT allowed: the whole command is denied, in every
		// accepted position.
		{`a | evil`, []string{"a", "evil"}, false},
		{`a && evil`, []string{"a", "evil"}, false},
		{`a || evil`, []string{"a", "evil"}, false},
		{`a; evil`, []string{"a", "evil"}, false},
		{`( a; evil )`, []string{"a", "evil"}, false},
		{`{ a; evil; }`, []string{"a", "evil"}, false},
		{`if evil; then a; fi`, []string{"evil", "a"}, false},
		{`if a; then evil; fi`, []string{"a", "evil"}, false},
		{`if a; then b; else evil; fi`, []string{"a", "b", "evil"}, false},
		{`if a; then b; elif evil; then c; fi`, []string{"a", "b", "evil", "c"}, false},
		{`while evil; do a; done`, []string{"evil", "a"}, false},
		{`while a; do evil; done`, []string{"a", "evil"}, false},
		{`until a; do evil; done`, []string{"a", "evil"}, false},
		{`! evil`, []string{"evil"}, false},
		{`evil &`, []string{"evil"}, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.command, func(t *testing.T) {
			t.Parallel()
			cmds, err := extractCommands(tc.command)
			if err != nil {
				t.Fatalf("extractCommands(%q): unexpected error: %v", tc.command, err)
			}
			if strings.Join(cmds, "\x00") != strings.Join(tc.wantCmds, "\x00") {
				t.Errorf("extractCommands(%q) = %q, want %q", tc.command, cmds, tc.wantCmds)
			}
			allowed, _, rule, err := ps.Decide(tc.command)
			if err != nil {
				t.Fatalf("Decide(%q): unexpected error: %v", tc.command, err)
			}
			if allowed != tc.wantAllowed {
				t.Errorf("Decide(%q) allowed=%v rule=%q, want allowed=%v", tc.command, allowed, rule, tc.wantAllowed)
			}
			if !tc.wantAllowed && rule != "allowlist:no-match" {
				t.Errorf("Decide(%q) rule=%q, want allowlist:no-match for the inner command", tc.command, rule)
			}
		})
	}
}

// TestShellParseArithmeticBuiltins covers the residual of the #820 primitive
// that needs no compound construct: a shell BUILTIN that arithmetic-evaluates
// one of its (quoted, statically known) arguments runs a command substitution
// written inside it — `test 'a[$(cmd)]' -eq 0`, `read 'a[$(cmd)]'`,
// `printf -v 'a[$(cmd)]' x` … on bash, zsh and/or ksh. The policy sees an
// ordinary `test …` / `read …` command. This gate is a BLOCKLIST of the builtin
// names for which the execution was observed; the control that holds is an
// anchored explicit-path allowlist that does not admit those builtins at all.
func TestShellParseArithmeticBuiltins(t *testing.T) {
	t.Parallel()

	// Catch-all policies: before the fix every row below was allowed.
	allowAll := PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`.*`}}}
	denyRM := PolicySet{{Mode: CmdPolicyDenylist, Deny: []string{`^rm `, `^touch `}}}

	substitution := []string{
		`test 'a[$(touch /tmp/pwn)]' -eq 0`,
		`test 0 -ne 'a[$(touch /tmp/pwn)]'`,
		`test -v 'a[$(touch /tmp/pwn)]'`,
		`'[' 'a[$(touch /tmp/pwn)]' -eq 0 ']'`,
		`/usr/bin/test 'a[$(touch /tmp/pwn)]' -eq 0`,
		`echo 1 | read 'a[$(touch /tmp/pwn)]'`,
		`read -r x 'a[$(touch /tmp/pwn)]'`,
		`printf -v 'a[$(touch /tmp/pwn)]' x`,
		`printf %d 'a[$(touch /tmp/pwn)]'`,
		`unset 'path[$(touch /tmp/pwn)]'`,
		`shift 'a[$(touch /tmp/pwn)]'`,
		`ulimit -n 'a[$(touch /tmp/pwn)]'`,
		`exit 'path[$(touch /tmp/pwn)]'`,
		`bye 'path[$(touch /tmp/pwn)]'`,
		`logout 'path[$(touch /tmp/pwn)]'`,
		`return 'path[$(touch /tmp/pwn)]'`,
		`break 'path[$(touch /tmp/pwn)]'`,
		`continue 'path[$(touch /tmp/pwn)]'`,
		`set -A 'a[$(touch /tmp/pwn)]' x`,
		`print -v 'a[$(touch /tmp/pwn)]' x`,
		`getopts a 'path[$(touch /tmp/pwn)]' -a`,
		`true & wait -n -p 'a[$(touch /tmp/pwn)]'`,
		`vared 'path[$(touch /tmp/pwn)]'`,
		`alarm 'a[$(touch /tmp/pwn)]'`,
		`getln 'a[$(touch /tmp/pwn)]'`,
		`zparseopts 'a[$(touch /tmp/pwn)]'`,
		`zregexparse 'a[$(touch /tmp/pwn)]' x y`,
		// Every spelling of a command substitution the target shell knows.
		"test 'a[`touch /tmp/pwn`]' -eq 0",
		`test 'a[${ touch /tmp/pwn; }]' -eq 0`,
		`test 'a[${|touch /tmp/pwn; }]' -eq 0`,
		`test "a[\$(touch /tmp/pwn)]" -eq 0`,
		`test 'a[$'"(touch /tmp/pwn)]" -eq 0`, // the marker is split across two quoted parts
	}
	for _, cmd := range substitution {
		for name, ps := range map[string]PolicySet{"allowlist": allowAll, "denylist": denyRM} {
			allowed, _, rule, err := ps.Decide(cmd)
			if allowed || err == nil {
				t.Errorf("%s: Decide(%q) = allowed=%v rule=%q err=%v; want a rejection", name, cmd, allowed, rule, err)
				continue
			}
			if !strings.Contains(err.Error(), "command-substitution syntax") {
				t.Errorf("%s: Decide(%q) error must name the cause, got: %v", name, cmd, err)
			}
		}
	}

	// The declaration / arithmetic builtins are refused as KEYWORDS (DeclClause,
	// LetClause). Quoting the name makes the parser read an ordinary simple
	// command, which must be refused just the same — the shell runs the builtin
	// either way, and the policy decides on the decoded command (#277).
	declarations := []string{
		`'export' PATH=/tmp/evil; true`,
		`"export" LD_PRELOAD=/tmp/e.so; true`,
		`ex"port" PATH=/tmp/evil; true`,
		`'readonly' PATH=/tmp/evil; true`,
		`'declare' 'a[$(touch /tmp/pwn)]=1'; true`,
		`'typeset' -i x='a[$(touch /tmp/pwn)]'; true`,
		`'local' 'a[$(touch /tmp/pwn)]=1'; true`,
		`'nameref' x=PATH; true`,
		`'integer' x='path[$(touch /tmp/pwn)]'; true`,
		`'float' x='path[$(touch /tmp/pwn)]'; true`,
		`'private' x='path[$(touch /tmp/pwn)]'; true`,
		`integer x='a[$(touch /tmp/pwn)]'; true`, // unquoted: a ksh93 alias of typeset
		`compound x; true`,
		`"let" 'a[$(touch /tmp/pwn)]=1'; true`,
		`'let' x=1`,
	}
	for _, cmd := range declarations {
		for name, ps := range map[string]PolicySet{"allowlist": allowAll, "denylist": denyRM} {
			allowed, _, rule, err := ps.Decide(cmd)
			if allowed || err == nil {
				t.Errorf("%s: Decide(%q) = allowed=%v rule=%q err=%v; want a rejection", name, cmd, allowed, rule, err)
				continue
			}
			if !strings.Contains(err.Error(), "environment declaration") && !strings.Contains(err.Error(), "shell construct not allowed by command policy: let") {
				t.Errorf("%s: Decide(%q) error must name the builtin class, got: %v", name, cmd, err)
			}
		}
	}

	// The gate is narrow: ordinary uses of those builtins, and a quoted "$(" in
	// the argument of a command that does NOT evaluate it, keep working.
	legit := []string{
		`test -f /etc/hosts`,
		`test 1 -eq 1`,
		`test a = b`,
		`'[' -d /tmp ']'`,
		`printf '%s\n' hello`,
		`printf 'cost: $5\n'`,
		`echo 1 | read x`,
		`unset x`,
		`exit 0`,
		`echo 'literal $(not run) text'`,
		`grep '$(CC)' Makefile`,
		"grep 'a`b' file",
		`echo '${HOME}'`,
		`/usr/bin/exportfs -v`, // a different binary: only the exact names are builtins
		`letsencrypt renew`,
	}
	for _, cmd := range legit {
		if allowed, _, rule, err := allowAll.Decide(cmd); !allowed || err != nil {
			t.Errorf("legitimate command %q must stay allowed (allowed=%v rule=%q err=%v)", cmd, allowed, rule, err)
		}
	}
}
