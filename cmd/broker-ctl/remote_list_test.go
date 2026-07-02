package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// remoteHostsFixture mirrors what GET /v1/policy/hosts serves: the signer.json
// "hosts" schema, full policy fields included.
const remoteHostsFixture = `{
  "web01": {
    "addr": "10.0.0.1:22",
    "user": "deploy",
    "host_key": "ssh-ed25519 AAAA...",
    "principal": "host:web01",
    "source_address": "203.0.113.10",
    "max_ttl_seconds": 120,
    "allowed_callers": ["broker-1"],
    "allow_sudo": true,
    "allowed_sudo_users": ["root", "deploy"],
    "allow_pty": true,
    "groups": ["prod-web"],
    "command_policy": {"mode": "allowlist", "shell_parse": true, "allow": ["^uptime$"]}
  },
  "bastion": {
    "addr": "203.0.113.10:22",
    "user": "jump",
    "host_key": "ssh-ed25519 BBBB...",
    "principal": "host:bastion",
    "max_ttl_seconds": 60,
    "allow_as_bastion": true,
    "groups": ["prod-web"]
  }
}`

func TestFetchRemoteHosts(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy/hosts" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(remoteHostsFixture))
	}))
	defer ts.Close()

	hosts, err := fetchRemoteHosts(&http.Client{Timeout: 5 * time.Second}, ts.URL)
	if err != nil {
		t.Fatalf("fetchRemoteHosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}
	web := hosts["web01"]
	if web.Principal != "host:web01" || web.MaxTTLSeconds != 120 || !web.AllowSudo {
		t.Errorf("web01 policy fields lost in decode: %+v", web)
	}
	if len(web.AllowedCallers) != 1 || web.AllowedCallers[0] != "broker-1" {
		t.Errorf("allowed_callers lost: %+v", web.AllowedCallers)
	}
	if got := commandPolicyLabel(web.CommandPolicy); got != "allowlist(1)" {
		t.Errorf("command_policy label = %q, want allowlist(1)", got)
	}
	if !hosts["bastion"].AllowAsBastion {
		t.Errorf("bastion allow_as_bastion lost")
	}
}

// TestFetchRemoteHostsRejected: a non-200 must surface the status, the
// signer's message, and the reload_callers hint — and never fall back to a
// partial view.
func TestFetchRemoteHostsRejected(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not authorised to read policy", http.StatusForbidden)
	}))
	defer ts.Close()

	_, err := fetchRemoteHosts(&http.Client{Timeout: 5 * time.Second}, ts.URL)
	if err == nil {
		t.Fatal("expected an error on 403")
	}
	for _, want := range []string{"HTTP 403", "not authorised to read policy", "reload_callers"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestRenderHostTable(t *testing.T) {
	t.Parallel()
	hosts := map[string]hostEntry{
		"web01": {
			Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web01",
			MaxTTLSeconds: 120, SourceAddress: "203.0.113.10",
			AllowSudo: true, AllowedSudoUsers: []string{"root"},
			Groups: []string{"prod-web"}, AllowedCallers: []string{"broker-1"},
		},
	}
	var sb strings.Builder
	renderHostTable(&sb, hosts)
	out := sb.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want header + 1 row:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "PRINCIPAL") || !strings.Contains(lines[0], "POLICY") {
		t.Errorf("unexpected header: %q", lines[0])
	}
	for _, want := range []string{"web01", "10.0.0.1:22", "deploy", "host:web01", "120s", "203.0.113.10", "prod-web", "broker-1"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("row missing %q: %q", want, lines[1])
		}
	}

	sb.Reset()
	renderHostTable(&sb, nil)
	if got := strings.TrimSpace(sb.String()); got != "(no hosts configured)" {
		t.Errorf("empty table output = %q", got)
	}
}
