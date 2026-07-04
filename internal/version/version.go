// Package version exposes the build version of the infrabroker binaries. The
// value is injected at build time from the git tag via -ldflags; when built
// without that flag it falls back to the module version or VCS revision that
// the Go toolchain records in the binary, so it never silently reports a
// hard-coded, stale string.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Version is overridden at build time with:
//
//	-ldflags "-X github.com/luisgf/infrabroker/internal/version.Version=$(git describe --tags --always --dirty)"
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

// Print writes the build version to stdout: the script-friendly short String()
// by default, or the multi-line Detailed() form when verbose is set. It is the
// single sink every binary's --version flag calls so the output stays uniform.
func Print(verbose bool) {
	if verbose {
		fmt.Println(Detailed())
	} else {
		fmt.Println(String())
	}
}

// Detailed returns a multi-field version string for `--version --verbose`: the
// build version (same source as String()), the Go toolchain, the target
// os/arch and, when built from a repository, the VCS revision and commit time.
// It is the long form behind the short String() default, so operators can
// capture the exact build provenance without changing the script-friendly
// default output.
func Detailed() string {
	s := fmt.Sprintf("version %s\n  go: %s\n  platform: %s/%s",
		String(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if info, ok := debug.ReadBuildInfo(); ok {
		rev, _ := vcsInfo(info)
		var when string
		for _, st := range info.Settings {
			if st.Key == "vcs.time" {
				when = st.Value
			}
		}
		if rev != "" {
			s += "\n  revision: " + rev
		}
		if when != "" {
			s += "\n  built: " + when
		}
	}
	return s
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
