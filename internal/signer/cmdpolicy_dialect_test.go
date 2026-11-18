package signer

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestShellParseRejectsDollarQuoting is the #821 regression. The policy parser
// reads the bash dialect, in which $'…' is ANSI-C quoting (backslash escapes
// are decoded, so \' is an escaped quote INSIDE the string) and $"…" is locale
// quoting. A shell without them reads the same bytes differently: dash has
// neither, zsh has no $"…". There, "$" is a literal dollar followed by an
// ordinary quoted string — and in an ordinary '…' string a backslash is not an
// escape, so the \' the policy saw as part of the argument actually ENDS it.
// Everything up to the next quote is then unquoted shell syntax:
//
//	echo $'\' ; touch /tmp/pwn ; \'' #'
//
// was ONE command for the policy (echo with the argument " ; touch /tmp/pwn ; ")
// and three for /bin/dash, the middle one never vetted. The signer cannot know
// which shell parses the force-command (the account's login shell, the sudo
// wrapper's /bin/sh, the sealed-exec shim's /bin/sh), so dollar-quoted words
// are refused; plain '…' and "…" mean the same in every shell.
func TestShellParseRejectsDollarQuoting(t *testing.T) {
	t.Parallel()

	allow := PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`^echo `, `^true$`}}}
	deny := PolicySet{{Mode: CmdPolicyDenylist, Deny: []string{`^rm `, `shadow`}}}
	approval := PolicySet{{RequireApproval: []string{`^reboot`}}}

	rejected := []struct {
		name    string
		ps      PolicySet
		command string
	}{
		// The issue's reproduction, and its denylist / approval forms.
		{"repro, allowlist with a free argument", allow, `echo $'\' ; touch /tmp/pwn ; \'' #'`},
		{"repro behind the sudo wrapper trigger", allow, `true; echo $'\' ; touch /tmp/pwn ; \'' #'`},
		{"repro, denylist", deny, `echo $'\' ; rm -rf /srv/data ; \'' #'`},
		{"repro, require_approval", approval, `echo $'\' ; reboot ; \'' #'`},
		// Every position and both forms.
		{"ANSI-C argument", allow, `echo $'a'`},
		{"ANSI-C escape", allow, `echo $'a\tb'`},
		{"ANSI-C command name", deny, `$'\x72\x6d' -rf /data`},
		{"ANSI-C inside a word", allow, `echo a$'b'c`},
		{"empty ANSI-C", allow, `echo $''`},
		{"locale-quoted argument", allow, `echo $"a"`},
		{"locale-quoted command name", deny, `$"rm" -rf /data`},
		{"locale-quoted inside a word", allow, `echo a$"b"c`},
		{"in a later command", allow, `true; echo $'a'`},
		{"inside a group", allow, `{ true; echo $'a'; }`},
	}
	for _, tc := range rejected {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allowed, needsApproval, rule, err := tc.ps.Decide(tc.command)
			if allowed || err == nil {
				t.Fatalf("Decide(%q) = allowed=%v needsApproval=%v rule=%q err=%v; want a fail-closed rejection",
					tc.command, allowed, needsApproval, rule, err)
			}
			// The rejection names the cause and the remedy.
			for _, want := range []string{"$'…'", `plain '…' or "…"`} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Decide(%q) error = %q, want it to contain %q", tc.command, err, want)
				}
			}
		})
	}

	// Plain quoting is unaffected, including a literal dollar sign inside it.
	accepted := []struct {
		command  string
		wantCmds []string
	}{
		{`echo 'a b'`, []string{"echo a b"}},
		{`echo "a b"`, []string{"echo a b"}},
		{`echo 'it costs $5'`, []string{"echo it costs $5"}},
		{`echo "it costs \$5"`, []string{"echo it costs $5"}},
		{`echo '$'"'"'a'"'"`, []string{"echo $'a'"}}, // the literal text $'a', spelled with plain quotes
		{`echo 'a\tb'`, []string{`echo a\tb`}},
	}
	for _, tc := range accepted {
		cmds, err := extractCommands(tc.command)
		if err != nil {
			t.Errorf("extractCommands(%q): unexpected error: %v", tc.command, err)
			continue
		}
		if strings.Join(cmds, "\x00") != strings.Join(tc.wantCmds, "\x00") {
			t.Errorf("extractCommands(%q) = %q, want %q", tc.command, cmds, tc.wantCmds)
		}
		if allowed, _, _, err := allow.Decide(tc.command); !allowed || err != nil {
			t.Errorf("Decide(%q) = allowed=%v err=%v; want allowed", tc.command, allowed, err)
		}
	}
}

// TestDollarQuotingNotElevatedDirectly: directArgv shares the static-word
// predicate, so a dollar-quoted command is never classified as a simple command
// whose DECODED argv is handed to sudo — the value it decodes to depends on the
// shell. It keeps the /bin/sh -c wrapper, which carries the caller's bytes.
func TestDollarQuotingNotElevatedDirectly(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		`echo $'a'`,
		`echo $"a"`,
		`$'id'`,
		`echo $'\' ; touch /tmp/pwn ; \'' #'`,
		`echo $^PATH`, // zsh reads $^NAME as a parameter expansion
		`dd if=~root/x`,
	} {
		if argv, ok := directArgv(cmd); ok {
			t.Errorf("directArgv(%q) must not classify as simple, got argv=%q", cmd, argv)
		}
		got := BuildElevatedCommand("sudo -n", cmd)
		if want := "sudo -n -- /bin/sh -c " + ShellQuote(cmd); got != want {
			t.Errorf("BuildElevatedCommand(%q) = %q, want the wrapper %q", cmd, got, want)
		}
	}
	// Plain quoting keeps the direct form.
	if got, want := BuildElevatedCommand("sudo -n", `echo 'a b'`), `sudo -n -- echo 'a b'`; got != want {
		t.Errorf("BuildElevatedCommand = %q, want %q", got, want)
	}
}

// TestShellParseDialectDivergences pins the other places found by the #821
// dialect review where a shell the command may run under reads — or could read
// — an ACCEPTED command differently from the bash-dialect parser. Rows marked
// "observed" were seen with a tracer on dash, bash 3.2 / 5.3, zsh 5.9 or ksh93:
// the shell named ran an argv the policy had not seen. The other rows are the
// fail-closed remainder of the same rule (nothing different was observed for
// them, they are refused because the rule is not a list of one shell's forms).
func TestShellParseDialectDivergences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		wantErr string
	}{
		// Observed on zsh: $^NAME, $=NAME, $~NAME and $+NAME are parameter
		// expansions (also inside double quotes); the parser reads a literal "$".
		// `cat $~HOME/x` reads a file under the home directory while the policy
		// saw "$~HOME/x".
		{"zsh $^NAME", `echo $^PATH`, "contains a '$'"},
		{"zsh $=NAME", `echo $=PATH`, "contains a '$'"},
		{"zsh $~NAME", `cat $~HOME/.ssh/id_rsa`, "contains a '$'"},
		{"zsh $+NAME", `echo $+PATH`, "contains a '$'"},
		{"zsh $^NAME in double quotes", `echo "$^PATH"`, "contains a '$'"},
		{"zsh $+NAME in double quotes", `echo "a $+PATH b"`, "contains a '$'"},
		// Observed on zsh: "\\" is an escaped backslash, so the "$" after it is live.
		{"zsh $^NAME after an escaped backslash", `echo "\\$^PATH"`, "contains a '$'"},
		{"zsh $^NAME after two escaped backslashes", `echo "\\\\$^PATH"`, "contains a '$'"},
		// Fail-closed remainder: every shell tested keeps these dollars literal.
		{"a dollar the parser left literal", `echo $/x`, "contains a '$'"},
		{"a dollar before text in double quotes", `echo "$ x"`, "contains a '$'"},
		{"a dollar before a quote inside double quotes", `echo "$'a'"`, "contains a '$'"},
		// Observed on bash: a tilde after "=" or ":" in a NAME=value-shaped
		// ARGUMENT is expanded like in an assignment. `dd if=~root/.ssh/id_rsa`
		// reads /root/.ssh/id_rsa while the policy saw "if=~root/.ssh/id_rsa".
		{"bash tilde after =", `dd if=~root/.ssh/id_rsa`, "tilde"},
		{"bash tilde after = (home)", `tar --file x PATH=~`, "tilde"},
		{"bash tilde after +=", `x PATH+=~`, "tilde"},
		{"bash tilde after :", `rsync x PATH=/a:~/b`, "tilde"},
		// Fail-closed remainder: bash leaves these alone (not a valid NAME=).
		{"tilde after = in an option", `tar --file=~/x`, "tilde"},
		// Observed on dash, zsh and ksh: a redirect's source descriptor is ONE
		// digit. "10>&1" is the argument 10 followed by ">&1", so the command
		// ran with an argument the policy never saw.
		{"multi-digit source descriptor", `kill -9 10>&1`, "single-digit"},
		{"zero-padded source descriptor", `kill -9 01>&2`, "single-digit"},
		// Fail-closed remainder: no shell ran anything different; dash refuses it.
		{"multi-digit target descriptor", `ps >&10`, "single-digit"},
		// Observed on ksh93: `NAME: cmd` is a LABEL followed by the command cmd.
		// The policy saw one command named "x:"; ksh ran `rm -rf /srv/data`.
		{"ksh label", `x: rm -rf /srv/data`, "ends with an unquoted ':'"},
		{"ksh label with a dot", `a.b: rm -rf /srv/data`, "ends with an unquoted ':'"},
		{"ksh label in a later command", `true; x: rm -rf /srv/data`, "ends with an unquoted ':'"},
		// Fail-closed remainder: ksh does not read these as labels.
		{"quoted name, unquoted colon", `"x": true`, "ends with an unquoted ':'"},
		{"path ending in a colon", `/x: true`, "ends with an unquoted ':'"},
		// Observed on zsh: a positional parameter can be assigned, so "1=x" is an
		// assignment in front of the command. The policy saw a command named
		// "1=x"; zsh ran `rm -rf /srv/data`.
		{"zsh positional assignment prefix", `1=x rm -rf /srv/data`, "contains an unquoted '='"},
		{"zsh positional assignment prefix (empty)", `2= rm -rf /srv/data`, "contains an unquoted '='"},
		// Fail-closed remainder: ksh variable names may contain dots, so it reads
		// these as an assignment in front of the command (ksh93u+ then refuses
		// the name and runs nothing; the parser saw a command named "a.b=c").
		{"ksh dotted assignment prefix", `a.b=c rm -rf /srv/data`, "contains an unquoted '='"},
		{"ksh .sh assignment prefix", `.sh.x=1 rm -rf /srv/data`, "contains an unquoted '='"},
		{"= inside a command name", `x"a"=b true`, "contains an unquoted '='"},
		// Observed on zsh: "&!" is ONE operator (background + disown), so the
		// word the policy read as the command "!rm" is the command rm.
		{"zsh &! before a command", `true &!rm -rf /srv/data`, "begins with an unquoted '!'"},
		// Fail-closed remainder: without the "&" every shell runs a command named "!rm".
		{"command name starting with !", `!rm -rf /srv/data`, "begins with an unquoted '!'"},
		// bash-only operators a POSIX sh reads differently were already outside
		// the accepted surface (#820); pinned here as part of the dialect review.
		{"&> redirect", `true &> /dev/null`, "file redirect not allowed"},
		{"&>> redirect", `true &>> /tmp/x`, "file redirect not allowed"},
		{">& file redirect", `true >& /tmp/x`, "file redirect not allowed"},
		{"here-string", `true <<< x`, "file redirect not allowed"},
		{"|& pipe", `true |& true`, "|& pipe"},
		{";& case fall-through", `case x in x) true;& esac`, "case"},
		{";;& case fall-through", `case x in x) true;;& esac`, "case"},
		{"{…} without spaces (zsh runs it)", `{true;}`, "shell parse"},
		{"double negation (bash 5 / ksh run it)", `! ! true`, "shell parse"},
		{"negation inside a pipeline (ksh runs it)", `true | ! true`, "shell parse"},
		// The command is ONE argument after `sh -c`: a string starting with "-"
		// or "+" is read as shell options. Observed on ksh93: given "+x" it
		// then runs the commands that arrive on STANDARD INPUT.
		{"command string starting with +", `+x`, "must not start with '-' or '+'"},
		{"command string starting with + (longer)", `+-e; true`, "must not start with '-' or '+'"},
		// Fail-closed remainder: no shell tested ran anything for a "-…" string.
		{"command string starting with -", `-s`, "must not start with '-' or '+'"},
		{"command string starting with --", `--version`, "must not start with '-' or '+'"},
		// A redirect's word goes through the same gate as any other word.
		{"dollar-quoted redirect target", `true 2>&$'1'`, "file redirect not allowed"},
		// The parser drops NUL bytes: "reboot\x00x" was decided as "rebootx",
		// dodging an anchored `^reboot$` rule, while an exec layer can at best
		// refuse the string and at worst truncate it to "reboot".
		{"NUL byte", "reboot\x00x", "NUL byte"},
		{"NUL byte in an argument", "echo a\x00b", "NUL byte"},
		// Observed on zsh: a redirection with no command runs $NULLCMD (cat).
		{"redirect without a command", `true; <&0`, "redirect without a command"},
		{"redirect without a command in a group", `{ >&2; true; }`, "redirect without a command"},
		// Options that change how the words of a LATER command expand. Observed:
		// `setopt extendedglob; echo /etc/host#s` prints /etc/hosts on zsh, and
		// `set -k; cmd a=b` runs cmd WITHOUT the argument on bash.
		{"setopt", `setopt extendedglob; cat /etc/shad#ow`, "setopt not allowed"},
		{"unsetopt", `unsetopt nomatch; true`, "unsetopt not allowed"},
		{"shopt", `shopt -s extglob; true`, "shopt not allowed"},
		{"quoted setopt", `'setopt' extendedglob; true`, "setopt not allowed"},
		{"/usr/bin/shopt", `/usr/bin/shopt -s extglob`, "shopt not allowed"},
		{"set -k", `set -k; true a=b`, "set is limited"},
		{"set -o with another option", `set -o extendedglob; true`, "set is limited"},
		{"set -f", `set -f; true`, "set is limited"},
		{"set -a", `set -a; true`, "set is limited"},
		{"set --", `set -- a b; true`, "set is limited"},
		{"set with positional arguments", `set a b; true`, "set is limited"},
		{"bare set", `set`, "set is limited"},
		{"set -", `set -; true`, "set is limited"},
		{"set +", `set +; true`, "set is limited"},
		{"set -o alone", `set -o`, "set is limited"},
		{"set -eo without a name", `set -eo; true`, "set is limited"},
		{"set -oe pipefail", `set -oe pipefail; true`, "set is limited"},
		{"set -e pipefail", `set -e pipefail; true`, "set is limited"},
		{"set -ef", `set -ef; true`, "set is limited"},
		{"set -o pipefail extra", `set -o pipefail x; true`, "set is limited"},
		{"set -o noglob", `set -o noglob; true`, "set is limited"},
		{"set +o other", `set +o braceexpand; true`, "set is limited"},
		{"set -e then another option", `set -e -f; true`, "set is limited"},
		// `set -A` writes a variable: refused by the variable-writer gate first.
		{"set -A", `set -A PATH /x; true`, "writes a shell variable"},
	}
	ps := PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`.*`}}}
	denyRM := PolicySet{{Mode: CmdPolicyDenylist, Deny: []string{`^rm `}}}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for name, p := range map[string]PolicySet{"allowlist": ps, "denylist": denyRM} {
				allowed, _, rule, err := p.Decide(tc.command)
				if allowed || err == nil {
					t.Fatalf("%s: Decide(%q) = allowed=%v rule=%q err=%v; want a rejection", name, tc.command, allowed, rule, err)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("%s: Decide(%q) error = %q, want it to contain %q", name, tc.command, err, tc.wantErr)
				}
			}
		})
	}

	// What stays accepted: the forms every shell tested reads the same way.
	accepted := []struct {
		command  string
		wantCmds []string
	}{
		{`echo $`, []string{"echo $"}}, // a lone dollar is literal everywhere
		{`grep foo$ file`, []string{"grep foo$ file"}},
		{`echo "100$"`, []string{"echo 100$"}},
		{`: no-op`, []string{": no-op"}},              // the ":" builtin is not a label
		{`'x:' a`, []string{"x: a"}},                  // a quoted colon is literal in ksh too
		{`echo x: y`, []string{"echo x: y"}},          // a colon on an ARGUMENT
		{`true & ! false`, []string{"true", "false"}}, // "! cmd" is negation in every shell
		{`echo !x '!y'`, []string{"echo !x !y"}},      // a bang on an ARGUMENT (no history under -c)
		{`'a.b=c' x`, []string{"a.b=c x"}},            // quoted: a command really named a.b=c
		{`echo a.b=c`, []string{"echo a.b=c"}},        // an = on an ARGUMENT
		{`'!x' a`, []string{"!x a"}},                  // quoted: a command really named !x
		{`echo "\$HOME"`, []string{"echo $HOME"}},
		{`echo "\$^PATH"`, []string{"echo $^PATH"}},    // escaped: literal everywhere
		{`echo "\\\$^PATH"`, []string{`echo \$^PATH`}}, // escaped backslash, escaped dollar
		{`echo "\\$"`, []string{`echo \$`}},            // a live dollar that ends the string
		{`echo "$"a`, []string{"echo $a"}},             // ditto, then an unquoted part
		{`echo a:b=c~d`, []string{"echo a:b=c~d"}},     // a tilde not right after = or :
		{`echo '$^PATH'`, []string{"echo $^PATH"}},     // single-quoted: literal everywhere
		{`ls file~`, []string{"ls file~"}},             // a tilde that starts nothing
		{`echo a~b`, []string{"echo a~b"}},
		{`dd 'if=~root/x'`, []string{"dd if=~root/x"}}, // quoted: no shell expands it
		{`ps aux 2>&1`, []string{"ps aux"}},
		{`ps aux >&2`, []string{"ps aux"}},
		{`ps aux 2>&-`, []string{"ps aux"}},
		{`>&2 ps aux`, []string{"ps aux"}},
		{`ps aux # a trailing comment`, []string{"ps aux"}},
		{`ps aux;# a comment after a semicolon`, []string{"ps aux"}},
		{`echo a#b`, []string{"echo a#b"}},
		{`echo -n +x`, []string{"echo -n +x"}}, // a dash / plus on an ARGUMENT
		{` -x a`, []string{"-x a"}},            // after a space the string is a command for every shell
		{`set -e; true`, []string{"set -e", "true"}},
		{`set -u; true`, []string{"set -u", "true"}},
		{`set -eu; true`, []string{"set -eu", "true"}},
		{`set -ue; true`, []string{"set -ue", "true"}},
		{`set +e; true`, []string{"set +e", "true"}},
		{`set -o pipefail; true`, []string{"set -o pipefail", "true"}},
		{`set -o errexit; true`, []string{"set -o errexit", "true"}},
		{`set -o nounset; true`, []string{"set -o nounset", "true"}},
		{`set +o pipefail; true`, []string{"set +o pipefail", "true"}},
		{`set -e -u; true`, []string{"set -e -u", "true"}},
		{`set -euo pipefail; true`, []string{"set -euo pipefail", "true"}},
		{`set -e -o pipefail; true`, []string{"set -e -o pipefail", "true"}},
	}
	for _, tc := range accepted {
		cmds, err := extractCommands(tc.command)
		if err != nil {
			t.Errorf("extractCommands(%q): unexpected error: %v", tc.command, err)
			continue
		}
		if strings.Join(cmds, "\x00") != strings.Join(tc.wantCmds, "\x00") {
			t.Errorf("extractCommands(%q) = %q, want %q", tc.command, cmds, tc.wantCmds)
		}
	}
}

// TestDialectRejectionCoversEverySigningPath: the predicate is shared, so a
// command the policy refuses for its dialect must not be signable through ANY
// path that carries a command — the one-shot force-command, its sudo forms
// (direct argv and the /bin/sh -c wrapper), the session-exec preflight, and
// the sealed-exec envelope (whose shim runs the command with /bin/sh, i.e.
// dash on Debian/Ubuntu: exactly the shell the #821 reproduction targets).
func TestDialectRejectionCoversEverySigningPath(t *testing.T) {
	t.Parallel()

	cp := CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{`^echo `, `^true$`}}
	table := PolicyTable{
		"web": {
			Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web",
			AllowSudo: true, CommandPolicy: cp,
		},
		"sealed": {
			Addr: "10.0.0.2:22", User: "deploy", Principal: "host:sealed",
			SealedExec: true, AllowSudo: true, CommandPolicy: cp,
		},
	}
	l := NewLocal(testCASigner(t), table, 5*time.Minute).WithEnvelopeKey(envelopeTestKey(t))

	const repro = `echo $'\' ; touch /tmp/pwn ; \'' #'`
	paths := []struct {
		name   string
		intent Intent
	}{
		{"one-shot", Intent{Host: "web", Purpose: PurposeOneshot}},
		{"one-shot + sudo", Intent{Host: "web", Purpose: PurposeOneshot, Sudo: true}},
		{"session exec preflight", Intent{Host: "web", Purpose: PurposeSession, SessionMode: SessionModeExec, Preflight: true, DryRun: true}},
		{"session exec preflight + sudo", Intent{Host: "web", Purpose: PurposeSession, SessionMode: SessionModeExec, Sudo: true, Preflight: true, DryRun: true}},
		{"sealed one-shot", Intent{Host: "sealed", Purpose: PurposeOneshot}},
		{"sealed exec envelope", Intent{Host: "sealed", Purpose: PurposeSession, SessionMode: SessionModeExec, Preflight: true, DryRun: true}},
		{"sealed exec envelope + sudo", Intent{Host: "sealed", Purpose: PurposeSession, SessionMode: SessionModeExec, Sudo: true, Preflight: true, DryRun: true}},
	}
	commands := []string{
		repro,
		`true; ` + repro, // more than one statement: the sudo form is the /bin/sh -c wrapper
		`echo $"a"`,
		`echo $^PATH`,
		`echo if=~root/x`,
		`echo a 10>&1`,
		`setopt extendedglob; echo a`,
	}
	for _, p := range paths {
		for _, cmd := range commands {
			in := p.intent
			in.Caller, in.Role, in.Command, in.RequestedTTL = "x", RoleTarget, cmd, time.Minute
			in.PublicKey = testEphemeralPub(t)

			if d, err := table.Resolve(in, 5*time.Minute); err == nil {
				t.Errorf("%s: Resolve(%q) must fail, got force-command %q", p.name, cmd, d.Constraints.ForceCommand)
			}
			issued, err := l.SignIntent(context.Background(), in)
			if err != nil {
				continue // refused outright: nothing was signed
			}
			if issued.Certificate != nil || issued.Envelope != "" {
				t.Errorf("%s: SignIntent(%q) issued a credential (cert=%v envelope=%q)", p.name, cmd, issued.Certificate != nil, issued.Envelope)
			}
			if issued.Decision == nil || issued.Decision.Allowed {
				t.Errorf("%s: SignIntent(%q) decision = %+v, want not allowed", p.name, cmd, issued.Decision)
			}
		}
	}

	// Control: the plainly quoted form of the same shape is signed on every
	// path, so the rows above fail for the dialect and nothing else.
	for _, p := range paths {
		in := p.intent
		in.Caller, in.Role, in.Command, in.RequestedTTL = "x", RoleTarget, `echo ' ; not run ; '`, time.Minute
		in.PublicKey = testEphemeralPub(t)
		if _, err := table.Resolve(in, 5*time.Minute); err != nil {
			t.Errorf("%s: Resolve of the plainly quoted control must succeed: %v", p.name, err)
		}
		issued, err := l.SignIntent(context.Background(), in)
		if err != nil {
			t.Errorf("%s: SignIntent of the plainly quoted control must succeed: %v", p.name, err)
			continue
		}
		if issued.Decision != nil && !issued.Decision.Allowed {
			t.Errorf("%s: the plainly quoted control must be allowed, got %+v", p.name, issued.Decision)
		}
	}
}
