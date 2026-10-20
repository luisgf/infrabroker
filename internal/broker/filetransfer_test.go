package broker

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	sshrun "github.com/luisgf/infrabroker/internal/ssh"
)

// transferTestEngine builds an engine sufficient for the validation paths that
// fail before any signing or connection is attempted.
func transferTestEngine(maxBytes int) *Engine {
	return &Engine{cfg: &Config{FileTransferMaxBytes: maxBytes}}
}

func TestFileTransferMaxBytesDefault(t *testing.T) {
	t.Parallel()
	if got := transferTestEngine(0).FileTransferMaxBytes(); got != DefaultFileTransferMaxBytes {
		t.Errorf("default cap = %d, want %d", got, DefaultFileTransferMaxBytes)
	}
	if got := transferTestEngine(1024).FileTransferMaxBytes(); got != 1024 {
		t.Errorf("configured cap = %d, want 1024", got)
	}
}

// TestNewEngineRejectsFileTransferMaxBytesAboveOutputCap pins #580: a
// file_transfer_max_bytes above the SSH per-stream output cap (minus the
// truncation marker) is refused at load with an error naming the field and the
// ceiling, before any signer, CA or audit log is touched; the ceiling itself
// and the default pass the check.
func TestNewEngineRejectsFileTransferMaxBytesAboveOutputCap(t *testing.T) {
	t.Parallel()
	if MaxFileTransferMaxBytes != 10*1024*1024-sshrun.TruncationMarkerLen || MaxFileTransferMaxBytes >= sshrun.MaxOutputBytes {
		t.Fatalf("MaxFileTransferMaxBytes = %d, want the %d-byte cap minus the %d-byte marker", MaxFileTransferMaxBytes, sshrun.MaxOutputBytes, sshrun.TruncationMarkerLen)
	}
	// The number quoted in the FileTransferMaxBytes field comment (and so in
	// docs/reference/config.md) and in docs/USAGE.md §9.
	if MaxFileTransferMaxBytes != 10485706 {
		t.Fatalf("MaxFileTransferMaxBytes = %d; update the documented ceiling (10485706)", MaxFileTransferMaxBytes)
	}
	_, err := NewEngine(&Config{FileTransferMaxBytes: 20 * 1024 * 1024})
	if err == nil {
		t.Fatal("file_transfer_max_bytes of 20 MiB must be rejected at load")
	}
	if !strings.Contains(err.Error(), "file_transfer_max_bytes") || !strings.Contains(err.Error(), strconv.Itoa(MaxFileTransferMaxBytes)) {
		t.Errorf("error should name the field and the ceiling, got: %v", err)
	}
	_, err = NewEngine(&Config{FileTransferMaxBytes: MaxFileTransferMaxBytes + 1})
	if err == nil || !strings.Contains(err.Error(), "file_transfer_max_bytes") {
		t.Errorf("one byte above the ceiling must be rejected, got: %v", err)
	}
	for _, ok := range []int{0, DefaultFileTransferMaxBytes, MaxFileTransferMaxBytes} {
		if err := validateFileTransferMaxBytes(&Config{FileTransferMaxBytes: ok}); err != nil {
			t.Errorf("file_transfer_max_bytes %d must be accepted: %v", ok, err)
		}
	}
}

func TestPutFileValidation(t *testing.T) {
	t.Parallel()
	e := transferTestEngine(8)
	c := Caller{ID: "test"}

	for name, tc := range map[string]struct {
		path, mode string
		content    []byte
		wantSubstr string
	}{
		"empty path":      {path: "", content: []byte("x"), wantSubstr: "path is required"},
		"null byte":       {path: "/tmp/\x00f", content: []byte("x"), wantSubstr: "null bytes"},
		"newline in path": {path: "/tmp/a\nb", content: []byte("x"), wantSubstr: "newline"},
		// #331: spaces would splice forged key=value tokens into the audit Command.
		"space in path":    {path: "/tmp/x bytes=0 sha256=00", content: []byte("x"), wantSubstr: "whitespace or control"},
		"tab in path":      {path: "/tmp/a\tb", content: []byte("x"), wantSubstr: "whitespace or control"},
		"oversized":        {path: "/tmp/f", content: bytes.Repeat([]byte("a"), 9), wantSubstr: "transfer limit is 8"},
		"bad mode":         {path: "/tmp/f", mode: "rwx", content: []byte("x"), wantSubstr: "invalid mode"},
		"mode with prefix": {path: "/tmp/f", mode: "u+x", content: []byte("x"), wantSubstr: "invalid mode"},
	} {
		_, err := e.PutFile(context.Background(), c, "web01", tc.path, tc.content, tc.mode, 0)
		if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
			t.Errorf("%s: err = %v, want substring %q", name, err, tc.wantSubstr)
		}
		if !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: err must wrap ErrBadRequest, got %v", name, err)
		}
	}
}

func TestGetFileValidation(t *testing.T) {
	t.Parallel()
	e := transferTestEngine(8)
	_, err := e.GetFile(context.Background(), Caller{ID: "test"}, "web01", "", 0, 0)
	if err == nil || !errors.Is(err, ErrBadRequest) {
		t.Errorf("empty path must be ErrBadRequest, got %v", err)
	}
}
