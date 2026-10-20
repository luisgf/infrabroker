package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMap(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identities.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadIdentityMapRejectsMalformedEntries pins #667: an entry that would
// silently exempt a user from the four-eyes guard must fail the startup load.
func TestLoadIdentityMapRejectsMalformedEntries(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ body, want string }{
		"empty value":            {`{"U0123ABC": ""}`, "U0123ABC"},
		"blank value":            {`{"U0123ABC": "   "}`, "U0123ABC"},
		"empty key":              {`{"": "alice@corp.com"}`, "empty platform user id"},
		"blank key":              {`{"  ": "alice@corp.com"}`, "empty platform user id"},
		"duplicate key":          {`{"U0123ABC": "alice@corp.com", "U0123ABC": "bob@corp.com"}`, "duplicate key"},
		"case-variant duplicate": {`{"U0123ABC": "alice@corp.com", "u0123abc": "bob@corp.com"}`, "u0123abc"},
		"empty object":           {`{}`, "empty"},
		"not an object":          {`["U0123ABC"]`, "identity map"},
	}
	for name, c := range cases {
		_, err := loadIdentityMap(writeMap(t, c.body))
		if err == nil {
			t.Errorf("%s: %s must be rejected", name, c.body)
			continue
		}
		// Compared case-insensitively: a case-variant duplicate is reported by the
		// confcheck guard (original spelling) or by the post-normalisation check
		// (upper-cased), whichever sees it first.
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.want)) {
			t.Errorf("%s: error %q should mention %q", name, err, c.want)
		}
	}
}

// TestLoadIdentityMapNormalisesKeys pins #667: Slack user ids are upper-case, so
// keys are upper-cased (and values trimmed) at load; JSONC comments are accepted.
func TestLoadIdentityMapNormalisesKeys(t *testing.T) {
	t.Parallel()
	m, err := loadIdentityMap(writeMap(t, "{\n // alice\n \" u0123abc \": \" alice@corp.com \",\n \"U0456DEF\": \"bob@corp.com\"\n}"))
	if err != nil {
		t.Fatalf("loadIdentityMap: %v", err)
	}
	if len(m) != 2 || m["U0123ABC"] != "alice@corp.com" || m["U0456DEF"] != "bob@corp.com" {
		t.Errorf("want normalised {U0123ABC: alice@corp.com, U0456DEF: bob@corp.com}, got %v", m)
	}

	if m, err := loadIdentityMap(""); m != nil || err != nil {
		t.Errorf("an empty path leaves the guard off: got %v, %v", m, err)
	}
}
