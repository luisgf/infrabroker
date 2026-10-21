package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAtomicWriteFollowsSymlink locks in #750 for the signer's durable policy
// writer: a symlinked config is edited through the link, not replaced by a
// regular file.
func TestAtomicWriteFollowsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real", "signer.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "signer.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(link, []byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link must survive the edit, got %v %v", fi, err)
	}
	if got, _ := os.ReadFile(target); string(got) != `{"b":2}` {
		t.Errorf("the edit must land on the target, got %s", got)
	}
}
