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
	"log"
	"os"
	"sync"
	"time"
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
	Command   string    `json:"command"`              // requested command
	TTL       string    `json:"ttl"`                  // issued validity window
	Serial    uint64    `json:"serial"`               // cert serial (correlates with sshd)
	SessionID string    `json:"session_id,omitempty"` // persistent session, if applicable
	Outcome   string    `json:"outcome"`              // executed|denied|error|session_*|dry_run_*|approval_*|grant_*|...
	ExitCode  int       `json:"exit_code"`            // exit code if executed
	Err       string    `json:"err,omitempty"`

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

// Log is a concurrent audit writer that chains and signs entries.
type Log struct {
	mu          sync.Mutex
	f           *os.File
	path        string
	signKey     ed25519.PrivateKey
	prevHash    string
	seq         uint64
	maxFileSize int64 // 0 = no rotation
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
	if l.maxFileSize <= 0 {
		return
	}
	info, err := l.f.Stat()
	if err != nil || info.Size() < l.maxFileSize {
		return
	}
	rotPath := l.path + "." + time.Now().UTC().Format("20060102T150405Z")
	_ = l.f.Close()
	if err := os.Rename(l.path, rotPath); err != nil {
		// If the rename fails, reopen the current file and continue.
		f, e2 := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if e2 == nil {
			l.f = f
		}
		log.Printf("warning: audit log rotation failed (%v); continuing with original file", err)
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("warning: could not open new audit log after rotation: %v", err)
		return
	}
	l.f = f
	// Carry l.prevHash over: the new file's first entry links to the rotated
	// file's last line, preserving chain continuity across files.
	l.seq = 0
	log.Printf("audit log rotated: %s → %s", l.path, rotPath)
}

// Append signs and writes an entry. It computes prev_hash/seq and signs over
// the canonical content (with the Sig field empty).
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// L2: rotate if the file has reached the size limit.
	l.maybeRotate()

	l.seq++
	e.Seq = l.seq
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
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing log: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("fsync log: %w", err)
	}

	sum := sha256.Sum256(line)
	l.prevHash = hex.EncodeToString(sum[:])
	return nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
