// File transfer (ssh_put_file / ssh_get_file) built on the one-shot
// certificate machinery: the transfer is a force-command one-shot whose
// content travels over stdin (upload) or stdout (download), so no SFTP
// subsystem or extra dependency is involved. The signer gates the capability
// per host via allow_file_transfer (default false), and the generated command
// is subject to the host's command policy like any other one-shot — note that
// a shell_parse policy in enforce mode rejects the stream redirects these
// commands use, which is the deliberately conservative outcome.

package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/luisgf/ssh-broker/internal/audit"
)

// DefaultFileTransferMaxBytes caps transfer content when
// file_transfer_max_bytes is not configured. Sized so that base64-encoded
// content plus the MCP envelope fits the HTTP frontend's 1 MiB body bound.
const DefaultFileTransferMaxBytes = 512 * 1024

// FileTransferMaxBytes returns the effective per-transfer size cap.
func (e *Engine) FileTransferMaxBytes() int {
	if e.cfg.FileTransferMaxBytes > 0 {
		return e.cfg.FileTransferMaxBytes
	}
	return DefaultFileTransferMaxBytes
}

// FileTransferResult is the outcome of a PutFile or GetFile.
type FileTransferResult struct {
	Content  []byte // downloaded content (GetFile only)
	Size     int    // bytes written (put) or read (get)
	SHA256   string // hex sha256 of the transferred content
	Serial   uint64 // certificate serial, correlates the audit entries
	Warnings []string
}

// modeRe validates the optional chmod mode: 3-4 octal digits.
var modeRe = regexp.MustCompile(`^[0-7]{3,4}$`)

// validateTransferPath rejects paths the transfer commands cannot quote into a
// single-line force-command safely.
func validateTransferPath(path string) error {
	switch {
	case path == "":
		return fmt.Errorf("%w: path is required", ErrBadRequest)
	case strings.ContainsRune(path, 0):
		return fmt.Errorf("%w: path contains null bytes", ErrBadRequest)
	case strings.ContainsAny(path, "\n\r"):
		return fmt.Errorf("%w: path contains newline characters", ErrBadRequest)
	}
	return nil
}

// PutFile uploads content to path on host: a one-shot `cat > path` (plus an
// optional chmod) with the bytes streamed over stdin. The signer must allow
// file transfer on the host (allow_file_transfer=true). mode, when non-empty,
// is an octal chmod mode like "0644".
func (e *Engine) PutFile(ctx context.Context, c Caller, host, path string, content []byte, mode string, ttlSeconds int) (*FileTransferResult, error) {
	if err := validateTransferPath(path); err != nil {
		return nil, err
	}
	if max := e.FileTransferMaxBytes(); len(content) > max {
		return nil, fmt.Errorf("%w: content is %d bytes, the transfer limit is %d", ErrBadRequest, len(content), max)
	}
	q := shellQuoteSession(path)
	command := "cat > " + q
	if mode != "" {
		if !modeRe.MatchString(mode) {
			return nil, fmt.Errorf("%w: invalid mode %q (expect 3-4 octal digits)", ErrBadRequest, mode)
		}
		command += " && chmod " + mode + " " + q
	}
	res, err := e.Execute(ctx, c, host, command, ttlSeconds, ExecOptions{Stdin: content, FileTransfer: true})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%w: remote write failed (exit %d): %s", ErrUpstream, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	e.auditE(audit.Entry{
		Caller: c.ID, Host: host, Serial: res.Serial, Outcome: "file_put",
		Command: fmt.Sprintf("path=%s bytes=%d sha256=%s", path, len(content), digest),
	})
	return &FileTransferResult{Size: len(content), SHA256: digest, Serial: res.Serial, Warnings: res.Warnings}, nil
}

// GetFile downloads up to maxBytes of path from host via a one-shot
// `head -c maxBytes+1 < path`. A file larger than the cap is an error rather
// than a silent truncation (the extra byte detects it). maxBytes <= 0 or above
// the configured cap selects the cap.
func (e *Engine) GetFile(ctx context.Context, c Caller, host, path string, maxBytes, ttlSeconds int) (*FileTransferResult, error) {
	if err := validateTransferPath(path); err != nil {
		return nil, err
	}
	max := e.FileTransferMaxBytes()
	if maxBytes > 0 && maxBytes < max {
		max = maxBytes
	}
	command := fmt.Sprintf("head -c %d < %s", max+1, shellQuoteSession(path))
	res, err := e.Execute(ctx, c, host, command, ttlSeconds, ExecOptions{FileTransfer: true})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%w: remote read failed (exit %d): %s", ErrUpstream, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	data := []byte(res.Stdout)
	if len(data) > max {
		return nil, fmt.Errorf("%w: file exceeds the transfer limit of %d bytes", ErrBadRequest, max)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	e.auditE(audit.Entry{
		Caller: c.ID, Host: host, Serial: res.Serial, Outcome: "file_get",
		Command: fmt.Sprintf("path=%s bytes=%d sha256=%s", path, len(data), digest),
	})
	return &FileTransferResult{Content: data, Size: len(data), SHA256: digest, Serial: res.Serial, Warnings: res.Warnings}, nil
}
