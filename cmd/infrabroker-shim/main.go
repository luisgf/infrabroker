// Command infrabroker-shim is the host-side half of sealed exec (#144,
// THREAT_MODEL gap #1). On a host whose signer policy sets sealed_exec, the
// session certificate carries force-command=infrabroker-shim, so sshd runs this
// binary for every channel on that connection and hands the broker's requested
// command to it in $SSH_ORIGINAL_COMMAND.
//
// That command must be a signed infrabroker envelope. The shim runs the command
// inside it only if the envelope verifies against the pinned public key, has not
// expired, and its nonce has not been used before. A broker that skipped the
// signer's per-command preflight therefore holds nothing this host will run:
// per-command authorization that survives broker compromise.
//
// Every failure is fail-closed — nothing runs and the exit status is non-zero.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/luisgf/infrabroker/internal/sealed"
)

const (
	// pubKeyPath is where the pinned envelope public key lives (the one-line
	// base64 the signer logs at startup). Deliberately a FIXED path, never
	// overridable by the environment: sshd can be configured to pass
	// client-supplied variables (AcceptEnv / PermitUserEnvironment), so an env-var
	// override would let the very broker this shim defends against point it at a
	// key the broker controls — defeating the whole control.
	pubKeyPath = "/etc/infrabroker/envelope.pub"

	// nonceDir holds one file per consumed envelope nonce, which bounds replay
	// within an envelope's (short) validity window. Must be writable by the SSH
	// account(s) this host exposes.
	nonceDir = "/var/lib/infrabroker-shim/nonces"

	// exitRefused mirrors the shell's "command found but not executable" status,
	// distinguishing a shim refusal from the inner command's own exit code.
	exitRefused = 126
)

// nonceRe pins the nonce to a plain hex token before it is used as a filename.
// The nonce arrives inside a signature-verified envelope, so this is defence in
// depth against a signer bug rather than an attacker — but it is what makes
// path traversal structurally impossible here.
var nonceRe = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

func main() {
	// The host this shim must enforce arrives as argv, which sshd takes verbatim
	// from the certificate's force-command — signed by the signer and unforgeable
	// by the broker. It is load-bearing: every sealed host pins the same envelope
	// key, so without this binding an envelope minted for a permissive host would
	// execute here just as happily.
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "infrabroker-shim: refused: expected exactly one argument "+
			"(the host name, from the certificate's force-command), got %d\n", len(os.Args)-1)
		os.Exit(exitRefused)
	}
	command, err := authorize(pubKeyPath, nonceDir, os.Args[1], os.Getenv("SSH_ORIGINAL_COMMAND"), time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "infrabroker-shim: refused: %v\n", err)
		os.Exit(exitRefused)
	}
	// Hand off to the shell so pipes, quoting and redirection behave exactly as
	// they do on a non-sealed host. SSH_ORIGINAL_COMMAND is dropped: the inner
	// command has no business reading the envelope that authorised it.
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "SSH_ORIGINAL_COMMAND=") {
			continue
		}
		env = append(env, kv)
	}
	if err := syscall.Exec("/bin/sh", []string{"sh", "-c", command}, env); err != nil {
		fmt.Fprintf(os.Stderr, "infrabroker-shim: exec: %v\n", err)
		os.Exit(exitRefused)
	}
}

// authorize verifies the envelope in wire against the pinned public key at
// pubPath, binds it to expectedHost, claims its nonce exactly once under nonces,
// and returns the command the envelope authorises. Every error path means: run
// nothing.
func authorize(pubPath, nonces, expectedHost, wire string, now time.Time) (string, error) {
	if strings.TrimSpace(wire) == "" {
		return "", errors.New("no command envelope presented; this host requires a signed infrabroker envelope (sealed_exec)")
	}
	raw, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("reading pinned envelope public key %s: %w", pubPath, err)
	}
	pub, err := sealed.ParsePublicKey(string(raw))
	if err != nil {
		return "", err
	}
	env, err := sealed.Verify(pub, wire, expectedHost, now)
	if err != nil {
		return "", err
	}
	if !nonceRe.MatchString(env.Nonce) {
		return "", fmt.Errorf("envelope nonce %q is not a plain hex token", env.Nonce)
	}
	if err := claimNonce(nonces, env.Nonce, now); err != nil {
		return "", err
	}
	return env.Command, nil
}

// claimNonce records the nonce exactly once. O_EXCL makes the claim atomic, so a
// replayed envelope loses the race even against a concurrent copy of itself. A
// store that cannot be created or written fails the claim: without single-use
// there is no replay bound, so the honest answer is to refuse.
func claimNonce(dir, nonce string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		// Fail closed and say exactly what host setup is missing: the shim runs as
		// the unprivileged SSH account, which cannot create a directory under a
		// root-owned /var/lib. The directory must be pre-created and owned by that
		// account during host setup (tracked in #291).
		return fmt.Errorf("nonce store %s is unusable (%w); sealed_exec needs this directory to exist and be writable by this SSH account — create it during host setup", dir, err)
	}
	sweepNonces(dir, now)
	f, err := os.OpenFile(filepath.Join(dir, nonce), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errors.New("envelope already used (replay)")
		}
		return fmt.Errorf("claiming envelope nonce: %w", err)
	}
	return f.Close()
}

// sweepNonces drops entries that no envelope could still be validated against:
// nothing older than the maximum envelope lifetime can pass sealed.Verify, so
// keeping its nonce buys nothing. Best-effort — a failed sweep must never block
// a legitimate command, and it cannot weaken the replay bound (an unswept nonce
// only ever means a stricter store).
func sweepNonces(dir string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > 2*sealed.MaxTTL {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
