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
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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

// readerBufferSize is the bufio.Scanner token cap the audit readers allocate
// (restoreChain, Verify, FileBounds). A written line MUST fit it, or the reader
// returns bufio.ErrTooLong and — since audit is required and fail-closed — the
// service refuses to start. maxEntryBytes bounds the writer strictly below it.
const readerBufferSize = 256 * 1024

// maxEntryBytes bounds a serialized audit line so every line the writer emits is
// readable. Redaction can EXPAND a free-text field ("AUTH=a" ->
// "AUTH=[REDACTED:env-assignment]") and the command is otherwise bounded only by
// the request-body cap, so without this a crafted command could inflate an entry
// past readerBufferSize and brick fail-closed startup on the next restart (#278).
const maxEntryBytes = readerBufferSize

// truncatedMarker is appended to a free-text field trimmed to fit maxEntryBytes,
// so the truncation is visible (and still covered by the entry signature).
const truncatedMarker = "...[TRUNCATED]"

// rotationTimeFormat is the timestamp suffix a rotated segment carries
// (<log>.<rotationTimeFormat>). Single-sourced with rotatedSegmentPath (writer)
// and isRotatedSegment (reader, used by verify.go's discovery) so DISCOVERY
// recognises exactly what rotation WRITES — and nothing else (e.g. the
// `audit repair` quarantine file <log>.corrupt-<ts>). The format is second
// resolution, so rotatedSegmentPath disambiguates same-second rotations.
const rotationTimeFormat = "20060102T150405Z"

// rotatedSegmentPath returns a NON-EXISTENT segment path for rotating logPath at
// t. The base name is <logPath>.<rotationTimeFormat>; if that already exists —
// another rotation within the same second, possible with a small max_file_size or
// a coarse wall clock — a ".<n>" suffix is appended so os.Rename never overwrites
// (and silently destroys) a prior segment (#257). The audit log is single-writer
// (maybeRotate holds l.mu), so there is no rename TOCTOU here.
func rotatedSegmentPath(logPath string, t time.Time) string {
	base := logPath + "." + t.Format(rotationTimeFormat)
	if _, err := os.Stat(base); errors.Is(err, os.ErrNotExist) {
		return base
	}
	for n := 1; ; n++ {
		candidate := fmt.Sprintf("%s.%d", base, n)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
}

// isRotatedSegment reports whether suffix (the part after "<logPath>.") names a
// rotated segment: the rotationTimeFormat timestamp, optionally followed by a
// ".<n>" same-second disambiguation suffix. The timestamp format contains no dot,
// so a dot unambiguously introduces the numeric suffix. Excludes the audit-repair
// quarantine file (<logPath>.corrupt-<ts>), which does not parse as the format.
func isRotatedSegment(suffix string) bool {
	ts := suffix
	if i := strings.IndexByte(suffix, '.'); i >= 0 {
		tail := suffix[i+1:]
		if tail == "" || strings.TrimLeft(tail, "0123456789") != "" {
			return false // a dot, but not a ".<digits>" collision suffix
		}
		ts = suffix[:i]
	}
	_, err := time.Parse(rotationTimeFormat, ts)
	return err == nil
}

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

	// Group-commit fsync state (all under mu). Append writes the line and advances
	// the hash chain under mu — in strict total order — then batches the durability
	// fsync: one goroutine (the leader) fsyncs while the rest wait, so N concurrent
	// appends cost ~1 fsync instead of N and throughput is no longer capped at
	// 1/fsync (#209). Fail-closed durability is preserved: an Append returns success
	// only once syncedCount has advanced past its own writeCount, i.e. its bytes are
	// on disk. writeCount is monotonic across rotations (unlike the per-file seq).
	syncCond    *sync.Cond
	writeCount  uint64 // committed writes so far (never resets)
	syncedCount uint64 // highest writeCount durably fsynced
	syncing     bool   // a leader is fsyncing right now
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
	l.syncCond = sync.NewCond(&l.mu)
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
		// No active file. A crash right at a rotation boundary can leave this state
		// with rotated segments present (maybeRotate renamed the old file and had
		// not yet written the new one), so seed the chain head from the newest
		// rotated segment instead of genesis (#279).
		return l.seedFromRotatedSegments()
	}
	if err != nil {
		return fmt.Errorf("reading existing log: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, readerBufferSize), readerBufferSize)
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
		// Empty active file: maybeRotate creates the new segment empty and carries
		// the chain forward only via the in-memory prevHash, so a crash after the
		// rename but before the first record landed leaves an empty active file with
		// the real chain head in the newest rotated segment. Seed from it, or the
		// next Append would write prev_hash="" and break cross-segment linkage (#279).
		return l.seedFromRotatedSegments()
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

// seedFromRotatedSegments sets prevHash from the newest rotated segment's last
// line, for the case where the active file is empty or absent but rotated
// segments exist — the on-disk state a crash right at a rotation boundary leaves
// behind. seq stays 0: it restarts per file, so the new active file's first entry
// is seq 1 regardless; only the prevHash link across the boundary must be
// recovered so VerifySegments does not see a broken chain (#279). No rotated
// segment means a genuine fresh start (genesis).
func (l *Log) seedFromRotatedSegments() error {
	segments, err := discoverSegments(l.path)
	if err != nil {
		return fmt.Errorf("discovering rotated segments: %w", err)
	}
	// discoverSegments appends the active file (l.path) last when it exists; the
	// rotated segments are everything else, ordered oldest→newest.
	newest := ""
	for _, s := range segments {
		if s != l.path {
			newest = s
		}
	}
	if newest == "" {
		return nil // no rotated segments — genuine genesis
	}
	_, lastHash, err := FileBounds(newest)
	if err != nil {
		return fmt.Errorf("seeding chain from rotated segment %s: %w", newest, err)
	}
	l.prevHash = lastHash
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
	// Group-commit barrier: a leader may be fsyncing l.f right now (mu released),
	// and appends whose bytes are in this file may not be fsynced yet. Wait for the
	// leader to finish, then flush the file ourselves before closing it — otherwise
	// closing would lose those un-fsynced bytes (Close does not fsync). If the flush
	// fails, DEFER rotation (do not close an unsynced file): the pending appends'
	// own syncTo retries on the still-open file, and rotation retries next append.
	for l.syncing {
		l.syncCond.Wait()
	}
	if err := l.f.Sync(); err != nil {
		log.Printf("warning: audit log rotation deferred: pre-rotation fsync failed: %v", err)
		l.syncCond.Broadcast()
		return
	}
	l.syncedCount = l.writeCount
	l.syncCond.Broadcast()
	rotPath := rotatedSegmentPath(l.path, time.Now().UTC())
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

	// Bound the serialized entry so the line stays readable by the fixed-size
	// reader buffer: redaction can expand a free-text field past readerBufferSize,
	// which would otherwise wedge fail-closed startup on the next restart (#278).
	fitEntry(&e)

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
	l.writeCount++
	myCount := l.writeCount

	return l.syncTo(myCount)
}

// fitEntry trims e's free-text fields (Command/Err/Warning/Anomaly, longest
// first) so the serialized, signed line fits within maxEntryBytes and stays
// readable by the reader buffer. Only these four fields carry unbounded /
// redaction-expanded text; every other field is short metadata and is never
// trimmed. The loop terminates because each source byte contributes at least one
// JSON byte, so removing the overage from the longest field always makes
// progress; once all four are empty the entry is pure metadata and fits.
func fitEntry(e *Entry) {
	// Reserve headroom for the fields set (or grown) AFTER this measurement:
	// seq, prev_hash (64 hex), the base64 signature (88), time, and the newline.
	const reserve = 1024
	budget := maxEntryBytes - reserve
	fields := []*string{&e.Command, &e.Err, &e.Warning, &e.Anomaly}
	// At most a couple of passes are needed (each trim removes the full overage);
	// the bound is a generous backstop covering marker re-add and rune rounding.
	for i := 0; i < 8; i++ {
		b, err := json.Marshal(e)
		if err != nil || len(b) <= budget {
			return
		}
		longest := longestField(fields)
		if longest == nil || *longest == "" {
			return // only metadata remains; nothing left to trim
		}
		*longest = truncateField(*longest, len(b)-budget)
	}
}

// longestField returns the field pointer with the longest current value.
func longestField(fields []*string) *string {
	var longest *string
	for _, f := range fields {
		if longest == nil || len(*f) > len(*longest) {
			longest = f
		}
	}
	return longest
}

// truncateField shortens s by at least `over` bytes and appends truncatedMarker
// so the trim is visible in the (still-signed) record. It cuts on a UTF-8 rune
// boundary so the field stays valid text.
func truncateField(s string, over int) string {
	keep := len(s) - over - len(truncatedMarker)
	if keep < 0 {
		keep = 0
	}
	for keep > 0 && !utf8.RuneStart(s[keep]) {
		keep--
	}
	return s[:keep] + truncatedMarker
}

// syncTo blocks until every write up to and including count is durably fsynced,
// then returns nil (fail-closed: an Append returns success only once its bytes
// are on disk). Group commit: the first waiter becomes the leader and fsyncs with
// mu RELEASED, so concurrent Appends queue behind one fsync instead of each
// paying their own; the rest wait and return once the leader's sync covered them.
// If the leader's own fsync fails it returns that error; a follower woken by a
// failed sync retries as the next leader. Called with mu held; returns with mu
// held so the caller's deferred Unlock runs exactly once.
func (l *Log) syncTo(count uint64) error {
	for l.syncedCount < count {
		if l.syncing {
			l.syncCond.Wait() // a leader is syncing; wait and re-check
			continue
		}
		// Become the leader. Capture the file and target under mu; maybeRotate and
		// Close wait for l.syncing to clear, so l.f stays valid across the unlocked
		// fsync and cannot be closed under us.
		l.syncing = true
		f := l.f
		target := l.writeCount
		l.mu.Unlock()
		serr := f.Sync()
		l.mu.Lock()
		l.syncing = false
		if serr == nil && target > l.syncedCount {
			l.syncedCount = target
		}
		l.syncCond.Broadcast()
		if serr != nil {
			return fmt.Errorf("fsync log: %w", serr)
		}
	}
	return nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Wait for any in-flight group-commit fsync so we do not close the file out
	// from under the leader.
	for l.syncing {
		l.syncCond.Wait()
	}
	if l.f == nil { // a prior open failure left no handle to close
		return nil
	}
	return l.f.Close()
}
