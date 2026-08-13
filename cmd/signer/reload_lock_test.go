package main

import (
	"path/filepath"
	"testing"
	"time"
)

// TestReloadSerializesWithMutateAllow pins #378: reload holds writeMu for
// the whole read+build+swap, so a concurrent mutateAllow cannot persist a
// narrowing that this reload would then overwrite with a stale snapshot.
func TestReloadSerializesWithMutateAllow(t *testing.T) {
	// Not parallel: replaces the package-level afterReloadLock hook.
	srv := &server{cfgPath: filepath.Join(t.TempDir(), "missing.json")}

	entered := make(chan struct{})
	release := make(chan struct{})
	afterReloadLock = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { afterReloadLock = func() {} })

	reloaded := make(chan struct{})
	go func() {
		_, _ = srv.reload()
		close(reloaded)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("reload did not acquire writeMu")
	}

	mutated := make(chan struct{})
	go func() {
		_, _ = srv.mutateAllow("web01", "^x$", true)
		close(mutated)
	}()
	select {
	case <-mutated:
		t.Fatal("mutateAllow ran while reload held writeMu")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-reloaded
	select {
	case <-mutated:
	case <-time.After(2 * time.Second):
		t.Fatal("mutateAllow did not proceed after reload released writeMu")
	}
}
