// Package audit writes an append-only, tamper-evident record of every
// certificate issuance and execution: it chains entries by hash (blockchain
// style) and signs each one with an Ed25519 audit key, so the history cannot
// be altered or reordered without detection.
package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/luisgf/infrabroker/internal/monitor"
)

// logFile is the subset of *os.File that Log needs. It is an interface so tests
// can inject I/O faults (e.g. a Sync that fails after a successful Write) at the
// write boundary; in production it is always an *os.File.
type logFile interface {
	io.Writer
	Sync() error
	Stat() (os.FileInfo, error)
	Close() error
}

// openFile opens the audit file. It is a package var so tests can inject open
// failures at a rotation boundary; in production it is os.OpenFile.
var openFile = os.OpenFile

// auditFileFlag/auditFileMode are the flags and mode used to open the append-
// only audit file (owner read/write only).
const (
	auditFileFlag = os.O_CREATE | os.O_APPEND | os.O_WRONLY
	auditFileMode = 0o600
)

// AuditLogMaxSize is the maximum audit file size before rotating to a file
// with a timestamp suffix. 0 disables rotation. The default (100 MiB) prevents
// the disk from filling up and writes from failing silently.
const AuditLogMaxSize int64 = 100 * 1024 * 1024 // 100 MiB

// Entry is an audit record. It never contains the key or the certificate, only
// metadata (including the cert fingerprint and its serial).
type Entry struct {
	Time      time.Time `json:"time"`
	Caller    string    `json:"caller"`               // agent identity (mTLS cert CN)
	Host      string    `json:"host"`                 // destination
	User      string    `json:"user"`                 // remote account
	Principal string    `json:"principal"`            // principal of the ephemeral cert
	Command   string    `json:"command"`              // requested command (canonical action for k8s)
	TTL       string    `json:"ttl"`                  // issued validity window
	Serial    uint64    `json:"serial"`               // cert serial (correlates with sshd), or k8s issuance serial
	SessionID string    `json:"session_id,omitempty"` // persistent session, if applicable

	// TargetType distinguishes the target family: "" (SSH, backward compatible)
	// or "k8s". BodySHA256 records the sha256 of a request body that must never
	// be logged verbatim — a k8s_apply manifest can carry a Secret — mirroring
	// the file-transfer entries.
	TargetType string `json:"target_type,omitempty"`
	BodySHA256 string `json:"body_sha256,omitempty"`
	Outcome    string `json:"outcome"`   // executed|denied|error|session_*|dry_run_*|approval_*|grant_*|...
	ExitCode   int    `json:"exit_code"` // exit code if executed
	Err        string `json:"err,omitempty"`

	// Elevation and PTY (privilege traceability).
	Elevation string `json:"elevation,omitempty"` // e.g. "sudo:root" or "sudo:deploy"
	PTY       bool   `json:"pty,omitempty"`       // true if PTY was used

	// AI-action firewall: command policy decision traceability.
	PolicyRule string `json:"policy_rule,omitempty"` // command_policy rule that matched
	DryRun     bool   `json:"dry_run,omitempty"`     // true if this was a simulation (not executed)
	Warning    string `json:"warning,omitempty"`     // advisory warning, e.g. audit-mode policy hit

	// Human approval (control plane).
	ApprovalID string `json:"approval_id,omitempty"` // approval request id
	ApprovedBy string `json:"approved_by,omitempty"` // CN of the approver

	// Behaviour guardrails (control plane).
	Anomaly string `json:"anomaly,omitempty"` // detected anomalies (rate-exceeded, new-host:..., new-command:...)

	// Integrity fields (populated by Log.Append).
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Sig      string `json:"sig"`
}

// Redactor masks secrets in free-text entry fields before an entry is signed
// and persisted. It is satisfied by *redact.Redactor; declared here so audit
// does not import the redact package (the dependency stays one-way, wired by
// each service at startup).
type Redactor interface {
	Redact(string) string
}

// Log is a concurrent audit writer that chains and signs entries.
type Log struct {
	mu          sync.Mutex
	f           logFile
	path        string
	signKey     ed25519.PrivateKey
	redactor    Redactor // nil = no redaction
	prevHash    string
	seq         uint64
	maxFileSize int64 // 0 = no rotation
	// needsNewline is set by restoreChain when the existing file's last record
	// has no trailing newline (a torn write, e.g. power loss). The next Append
	// then prepends a newline so it cannot concatenate two JSON records on one
	// physical line.
	needsNewline bool
}

// Open opens (or creates) the audit file in append mode and prepares signing.
// A4: restores seq and prevHash from the last existing entry to preserve the
// integrity chain across process restarts.
// L2: applies automatic rotation when the file exceeds AuditLogMaxSize.
func Open(path string, signKey ed25519.PrivateKey) (*Log, error) {
	l := &Log{
		path:        path,
		signKey:     signKey,
		maxFileSize: AuditLogMaxSize,
	}
	// A4: restore the chain from the existing log (if any).
	if err := l.restoreChain(); err != nil {
		return nil, fmt.Errorf("restoring audit chain: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	l.f = f
	return l, nil
}

// restoreChain reads the last line of the existing log and restores seq and
// prevHash. This ensures the chain is not broken when the process restarts.
func (l *Log) restoreChain() error {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil // new file — chain starts from zero
	}
	if err != nil {
		return fmt.Errorf("reading existing log: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024) // entries up to 256 KiB
	var lastLine []byte
	for sc.Scan() {
		if b := sc.Bytes(); len(b) > 0 {
			lastLine = make([]byte, len(b))
			copy(lastLine, b)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scanning existing log: %w", err)
	}
	if len(lastLine) == 0 {
		return nil // empty file — chain starts from zero
	}

	// Detect a torn final write: if the file does not end with a newline, the
	// previous Append's trailing '\n' never landed (e.g. power loss after the
	// JSON bytes were flushed). Flag it so the next Append re-terminates that
	// record with a leading '\n' instead of concatenating two JSON objects on one
	// physical line — which would corrupt the chain and break verification.
	if fi, statErr := f.Stat(); statErr == nil && fi.Size() > 0 {
		var last [1]byte
		if _, rerr := f.ReadAt(last[:], fi.Size()-1); rerr == nil && last[0] != '\n' {
			l.needsNewline = true
		}
	}

	var e Entry
	if err := json.Unmarshal(lastLine, &e); err != nil {
		return fmt.Errorf("parsing last log entry: %w", err)
	}
	l.seq = e.Seq
	sum := sha256.Sum256(lastLine)
	l.prevHash = hex.EncodeToString(sum[:])
	return nil
}

// maybeRotate rotates the log if it exceeds maxFileSize. Must be called under
// l.mu. L2: creates a file with a timestamp suffix and opens a new one. The
// new file's chain seeds from the rotated file's last hash: its first entry
// carries prev_hash = hash of the previous file's last line, so deleting or
// truncating files at rotation boundaries is detectable. Seq restarts per
// file; integrity rests on the prev_hash chain.
func (l *Log) maybeRotate() {
	// l.f == nil means a previous open failed; skip rotation and let Append's
	// ensureOpen re-establish the handle before writing (no nil Stat panic).
	if l.maxFileSize <= 0 || l.f == nil {
		return
	}
	info, err := l.f.Stat()
	if err != nil || info.Size() < l.maxFileSize {
		return
	}
	rotPath := l.path + "." + time.Now().UTC().Format("20060102T150405Z")
	// Close and drop the handle up front. From here l.f is either reassigned to
	// a valid file or left nil — it is NEVER left pointing at the closed handle,
	// so a reopen failure cannot silently turn every later Append into a write
	// to a dead FD. ensureOpen (called by Append) recovers on the next write.
	_ = l.f.Close()
	l.f = nil
	if err := os.Rename(l.path, rotPath); err != nil {
		// Rename failed: the original file is intact. Reopen it and continue.
		f, e2 := openFile(l.path, auditFileFlag, auditFileMode)
		if e2 != nil {
			log.Printf("warning: audit log rotation failed (%v) and reopen failed (%v); retrying on next write", err, e2)
			return
		}
		l.f = f
		log.Printf("warning: audit log rotation failed (%v); continuing with original file", err)
		return
	}
	// Rename succeeded: the new file starts a fresh per-file sequence; the
	// prev_hash chain still links across the boundary via l.prevHash. Reset seq
	// now (before the reopen) so a recovered reopen still starts the file at 1.
	// The new file is empty, so any pending torn-line repair no longer applies
	// (the truncated record stays in the rotated file, harmlessly, as its last
	// line).
	l.seq = 0
	l.needsNewline = false
	f, err := openFile(l.path, auditFileFlag, auditFileMode)
	if err != nil {
		log.Printf("warning: could not open new audit log after rotation: %v; retrying on next write", err)
		return
	}
	l.f = f
	log.Printf("audit log rotated: %s → %s", l.path, rotPath)
}

// ensureOpen re-establishes l.f if a previous rotation/open left it nil, so a
// transient open failure at a rotation boundary self-heals on the next write
// instead of permanently disabling the (fail-open) audit log. Must be called
// under l.mu.
func (l *Log) ensureOpen() error {
	if l.f != nil {
		return nil
	}
	f, err := openFile(l.path, auditFileFlag, auditFileMode)
	if err != nil {
		return fmt.Errorf("reopening audit log: %w", err)
	}
	l.f = f
	return nil
}

// SetRedactor installs a secret redactor applied to the free-text fields of
// every subsequent entry (Command, Err, Warning, Anomaly) BEFORE the entry is
// signed — the Ed25519 signature and the hash chain cover the redacted
// content, so verification is unaffected and the original text is never
// persisted. Redaction must only run on this sink: the decision path (what
// the signer authorizes) always sees the original command.
func (l *Log) SetRedactor(r Redactor) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.redactor = r
}

// appendFailures counts Append errors across every log this process holds, so
// operators can alert on audit-trail gaps. In audit_fail_mode=open a failed
// Append is only logged and the operation continues; in the default closed mode
// the action is denied instead and also counted by blockedActions.
var appendFailures = monitor.GetCounter("audit_append_failures_total",
	"Audit log Append errors (mode=open: the operation continues; mode=closed: the action is denied).")

// blockedActions counts actions denied because the audit log could not be
// written and the service is in fail-closed mode (audit_fail_mode=closed, the
// default). The alerting hook operators watch alongside audit_append_failures_total.
var blockedActions = monitor.GetCounter("audit_blocked_total",
	"Actions denied because the audit log could not be written (audit_fail_mode=closed).")

// RecordBlocked increments audit_blocked_total. Broker and signer call it when
// fail-closed mode turns an Append failure into a denied action.
func RecordBlocked() { blockedActions.Inc() }

// FailClosed parses an audit_fail_mode config value. "" and "closed" fail closed
// (deny the audited action when the log cannot be written — the secure default);
// "open" fails open (log the error and proceed, the pre-2.0 behaviour); any
// other value is a configuration error.
func FailClosed(mode string) (bool, error) {
	switch mode {
	case "", "closed":
		return true, nil
	case "open":
		return false, nil
	default:
		return false, fmt.Errorf("invalid audit_fail_mode %q (want \"closed\" or \"open\")", mode)
	}
}

// Append signs and writes an entry. It computes prev_hash/seq and signs over
// the canonical content (with the Sig field empty).
func (l *Log) Append(e Entry) error {
	err := l.doAppend(e)
	if err != nil {
		appendFailures.Inc()
	}
	return err
}

func (l *Log) doAppend(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Gap #8: mask secrets in the free-text fields before signing, so neither
	// the signature nor the persisted line ever contains the original secret.
	// The other fields are broker/signer-generated metadata, not user text.
	if l.redactor != nil {
		e.Command = l.redactor.Redact(e.Command)
		e.Err = l.redactor.Redact(e.Err)
		e.Warning = l.redactor.Redact(e.Warning)
		e.Anomaly = l.redactor.Redact(e.Anomaly)
	}

	// L2: rotate if the file has reached the size limit.
	l.maybeRotate()
	// A reopen failure during rotation (or a prior write) can leave l.f nil;
	// re-establish a handle before writing so a transient open error self-heals
	// instead of silently dropping every subsequent audit record.
	if err := l.ensureOpen(); err != nil {
		return err
	}

	// Compute the next seq and chain head locally; do NOT commit them to
	// l.seq/l.prevHash until the line is actually on disk, so a Write or Sync
	// failure cannot desync the in-memory chain state from the bytes written.
	seq := l.seq + 1
	e.Seq = seq
	e.PrevHash = l.prevHash
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}

	// Sign the canonical content with Sig empty; then fill Sig.
	e.Sig = ""
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("serialising payload: %w", err)
	}
	sig := ed25519.Sign(l.signKey, payload)
	e.Sig = base64.StdEncoding.EncodeToString(sig)

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("serialising line: %w", err)
	}
	out := append(line, '\n')
	if l.needsNewline {
		// A prior torn write left the last record without its trailing newline;
		// prepend one so this record starts on its own physical line instead of
		// being concatenated onto the truncated record.
		out = append([]byte{'\n'}, out...)
	}
	if _, err := l.f.Write(out); err != nil {
		// Nothing committed: l.seq/l.prevHash/needsNewline are unchanged, so the
		// next Append reuses this seq and chain head — no seq gap and no desync.
		return fmt.Errorf("writing log: %w", err)
	}
	l.needsNewline = false
	// The line is now in the file and visible to readers (including the chain
	// verifier) via the page cache even before fsync. Commit the chain state
	// from the committed bytes BEFORE Sync, so a transient fsync error stays
	// transient instead of permanently breaking the verifiable hash chain for
	// the rest of this process's run (restoreChain re-seeds on restart).
	l.seq = seq
	sum := sha256.Sum256(line)
	l.prevHash = hex.EncodeToString(sum[:])

	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("fsync log: %w", err)
	}
	return nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil { // a prior open failure left no handle to close
		return nil
	}
	return l.f.Close()
}
