package ssh

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestPTYInitCmdIsSingleLineAndDisablesHistory(t *testing.T) {
	if strings.ContainsAny(ptyInitCmd, "\n\r") {
		t.Fatal("ptyInitCmd must be a single line")
	}
	for _, want := range []string{"set +H", "set +o histexpand", "set +o history", "unset HISTFILE"} {
		if !strings.Contains(ptyInitCmd, want) {
			t.Errorf("ptyInitCmd missing %q", want)
		}
	}
}

var localShells = []string{"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh"}

// runInteractive feeds script to `sh -i` over a pipe (interactive mode forced,
// which is what enables bash history expansion) and returns combined output.
func runInteractive(sh, script string) string {
	cmd := exec.Command(sh, "-i")
	cmd.Stdin = strings.NewReader(script)
	out, _ := cmd.CombinedOutput() // exit status is irrelevant; output is asserted
	return string(out)
}

var histexpandRe = regexp.MustCompile(`(?m)^HE=histexpand\s+(on|off)\s*$`)

// TestPTYInitDisablesHistoryExpansion runs the real init string under every
// locally available shell. Shells with histexpand must report it off afterwards
// (it must be on without the init, so the test proves something); shells
// without it are skipped.
func TestPTYInitDisablesHistoryExpansion(t *testing.T) {
	probe := "echo HE=$(set -o 2>/dev/null | grep '^histexpand')\n"
	for _, sh := range localShells {
		t.Run(sh, func(t *testing.T) {
			if _, err := exec.LookPath(sh); err != nil {
				t.Skipf("%s not available", sh)
			}
			m := histexpandRe.FindStringSubmatch(runInteractive(sh, probe))
			if m == nil || m[1] != "on" {
				t.Skipf("%s interactive shell has no histexpand enabled by default", sh)
			}
			out := runInteractive(sh, ptyInitCmd+"\n"+probe)
			m = histexpandRe.FindStringSubmatch(out)
			if m == nil || m[1] != "off" {
				t.Fatalf("histexpand not disabled after init; output:\n%s", out)
			}
		})
	}
}

var diagRe = regexp.MustCompile(`(?i)bad option|invalid option|illegal option|not found|syntax error|unknown option`)

// TestPTYInitSilentAndShellSurvives checks the init emits no diagnostics (which
// would desynchronise the first marker read) on every shell, including those
// lacking the history options.
func TestPTYInitSilentAndShellSurvives(t *testing.T) {
	for _, sh := range localShells {
		t.Run(sh, func(t *testing.T) {
			if _, err := exec.LookPath(sh); err != nil {
				t.Skipf("%s not available", sh)
			}
			out := runInteractive(sh, ptyInitCmd+"\necho INIT_OK_$((1+1))\n")
			if !strings.Contains(out, "INIT_OK_2") {
				t.Fatalf("shell did not survive init; output:\n%s", out)
			}
			if diagRe.MatchString(out) {
				t.Fatalf("init produced diagnostics:\n%s", out)
			}
		})
	}
}
