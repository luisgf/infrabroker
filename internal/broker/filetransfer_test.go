package broker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
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

func TestPutFileValidation(t *testing.T) {
	t.Parallel()
	e := transferTestEngine(8)
	c := Caller{ID: "test"}

	for name, tc := range map[string]struct {
		path, mode string
		content    []byte
		wantSubstr string
	}{
		"empty path":       {path: "", content: []byte("x"), wantSubstr: "path is required"},
		"null byte":        {path: "/tmp/\x00f", content: []byte("x"), wantSubstr: "null bytes"},
		"newline in path":  {path: "/tmp/a\nb", content: []byte("x"), wantSubstr: "newline"},
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
