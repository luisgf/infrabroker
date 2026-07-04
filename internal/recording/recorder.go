// Package recording writes interactive session output in ASCIIcast v2 format.
// One .cast file is produced per session, named <session_id>.cast inside the
// configured recording directory.
//
// ASCIIcast v2 spec: https://docs.asciinema.org/manual/asciicast/v2/
// The header includes a private "infrabroker" extension field with session
// metadata, so the file is self-describing without the audit log.
package recording

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Meta holds the session metadata written to the ASCIIcast header.
type Meta struct {
	SessionID string
	Caller    string
	Host      string
	Serial    uint64
	PTY       bool
	Term      string // terminal type, e.g. "xterm-256color"
	Width     int    // terminal columns
	Height    int    // terminal rows
	StartedAt time.Time
}

// header is the ASCIIcast v2 header (first line of the file).
type header struct {
	Version     int            `json:"version"`
	Width       int            `json:"width"`
	Height      int            `json:"height"`
	Timestamp   int64          `json:"timestamp"`
	Title       string         `json:"title"`
	Env         map[string]any `json:"env,omitempty"`
	Infrabroker brokerMeta     `json:"infrabroker"`
}

type brokerMeta struct {
	SessionID string `json:"session_id"`
	Caller    string `json:"caller"`
	Host      string `json:"host"`
	Serial    uint64 `json:"serial"`
	StartedAt string `json:"started_at"`
}

// DefaultMaxBytes caps the size of a single recording so a long-running or
// abusive session cannot fill the disk. It mirrors the audit log's rotation
// size; unlike the audit log, recordings are not rotated — they stop once the
// cap is reached. 0 disables the cap.
const DefaultMaxBytes int64 = 100 * 1024 * 1024 // 100 MiB

// Redactor masks secrets in event data before it is written to the .cast
// file. It is satisfied by *redact.Redactor; declared here so recording does
// not import the redact package (the dependency stays one-way, wired by the
// broker at session open).
type Redactor interface {
	Redact(string) string
}

// Recorder writes an ASCIIcast v2 recording file for a single session.
// All methods are safe for concurrent use.
type Recorder struct {
	mu       sync.Mutex
	f        *os.File
	started  time.Time
	redactor Redactor // nil = no redaction
	written  int64    // bytes written to the file so far (header + events)
	maxBytes int64    // 0 = unlimited
	capped   bool     // true once the cap was reached and the truncation note written
}

// Open creates a new recording file at path and writes the ASCIIcast header.
func Open(path string, m Meta) (*Recorder, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("recording: open %s: %w", path, err)
	}

	width := m.Width
	if width <= 0 {
		width = 220
	}
	height := m.Height
	if height <= 0 {
		height = 40
	}
	term := m.Term
	if term == "" {
		term = "xterm-256color"
	}

	now := m.StartedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	h := header{
		Version:   2,
		Width:     width,
		Height:    height,
		Timestamp: now.Unix(),
		Title:     fmt.Sprintf("session %s — %s@%s", m.SessionID, m.Caller, m.Host),
		Env:       map[string]any{"TERM": term},
		Infrabroker: brokerMeta{
			SessionID: m.SessionID,
			Caller:    m.Caller,
			Host:      m.Host,
			Serial:    m.Serial,
			StartedAt: now.Format(time.RFC3339),
		},
	}

	hLine, err := json.Marshal(h)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("recording: marshal header: %w", err)
	}
	n, err := fmt.Fprintf(f, "%s\n", hLine)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("recording: write header: %w", err)
	}

	// Deltas are relative to the actual wall-clock start, not the header
	// timestamp (which may be a fixed value in tests or a replayed session).
	return &Recorder{f: f, started: time.Now(), written: int64(n), maxBytes: DefaultMaxBytes}, nil
}

// SetRedactor installs a secret redactor applied to every subsequent event's
// data before it is written. Input events carry one full command line per
// event (reliable matching); output arrives in arbitrary chunks, so a secret
// split across two chunks can escape a pattern — redaction here is
// best-effort by design (see docs/SECURITY.md).
func (r *Recorder) SetRedactor(rd Redactor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.redactor = rd
}

// WriteOutput records a chunk of stdout (or merged PTY output) as type "o".
func (r *Recorder) WriteOutput(data string) error {
	return r.write("o", data)
}

// WriteInput records a chunk of stdin as type "i".
func (r *Recorder) WriteInput(data string) error {
	return r.write("i", data)
}

// WriteStderr records a chunk of stderr as type "e".
func (r *Recorder) WriteStderr(data string) error {
	return r.write("e", data)
}

// Close flushes and closes the recording file.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// write appends one ASCIIcast event line: [delta, type, data].
// Delta is in seconds relative to session start, with millisecond precision.
func (r *Recorder) write(eventType, data string) error {
	if data == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	if r.redactor != nil {
		data = r.redactor.Redact(data)
	}
	if r.maxBytes > 0 && r.written >= r.maxBytes {
		// Cap reached: write a single truncation note as an output event, then
		// stop recording (the file stays valid ASCIIcast, just incomplete).
		if !r.capped {
			r.capped = true
			r.writeLine("o", fmt.Sprintf("\r\n[recording truncated: %d-byte limit reached]\r\n", r.maxBytes))
		}
		return nil
	}
	return r.writeLine(eventType, data)
}

// writeLine marshals and appends one ASCIIcast event line, updating the byte
// counter. Must be called with r.mu held and r.f non-nil.
func (r *Recorder) writeLine(eventType, data string) error {
	delta := time.Since(r.started).Seconds()
	line, err := json.Marshal([]any{delta, eventType, data})
	if err != nil {
		return fmt.Errorf("recording: marshal event: %w", err)
	}
	n, err := fmt.Fprintf(r.f, "%s\n", line)
	r.written += int64(n)
	return err
}
