// Package version exposes the build version of the ssh-broker binaries. The
// value is injected at build time from the git tag via -ldflags; when built
// without that flag it falls back to the module version or VCS revision that
// the Go toolchain records in the binary, so it never silently reports a
// hard-coded, stale string.
package version

import "runtime/debug"

// Version is overridden at build time with:
//
//	-ldflags "-X github.com/luisgf/ssh-broker/internal/version.Version=$(git describe --tags --always --dirty)"
//
// The Makefile's build targets set this automatically. Left empty here so that
// String() can tell "not injected" apart from a real value.
var Version = ""

// String returns the build version, preferring the ldflags-injected git tag and
// falling back to the Go build info: the module version (set when the binary is
// produced by `go install module@vX.Y.Z`), else the VCS revision recorded for a
// plain `go build` from the repository. Returns "dev" only when no information
// is available at all.
func String() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	rev, dirty := vcsInfo(info)
	if rev == "" {
		return "dev"
	}
	if dirty {
		return "dev-" + rev + "-dirty"
	}
	return "dev-" + rev
}

// vcsInfo extracts the short VCS revision and the dirty flag from the build
// settings the Go toolchain embeds (since Go 1.18) when building from a repo.
func vcsInfo(info *debug.BuildInfo) (rev string, dirty bool) {
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return rev, dirty
}
