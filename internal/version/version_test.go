package version

import (
	"runtime/debug"
	"testing"
)

func TestStringPrefersInjected(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "v9.9.9"
	if got := String(); got != "v9.9.9" {
		t.Fatalf("String() = %q, want the injected v9.9.9", got)
	}
}

func TestStringNeverEmpty(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = ""
	// With no ldflags injection the value comes from build info; whatever the
	// path, it must never be the empty string the stale const used to mask.
	if got := String(); got == "" {
		t.Fatal("String() must never return an empty version")
	}
}

func TestVcsInfo(t *testing.T) {
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef0123"},
		{Key: "vcs.modified", Value: "true"},
	}}
	rev, dirty := vcsInfo(info)
	if rev != "0123456789ab" {
		t.Errorf("rev = %q, want the 12-char short revision", rev)
	}
	if !dirty {
		t.Error("dirty should be true when vcs.modified is true")
	}
}
