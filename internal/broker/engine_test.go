package broker

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

func TestClassifySignErr(t *testing.T) {
	t.Parallel()
	// A signing service that is unreachable / 5xx is an upstream failure.
	up := classifySignErr(fmt.Errorf("%w (502): boom", signer.ErrSignerUnavailable))
	if !errors.Is(up, ErrUpstream) {
		t.Errorf("signer-unavailable must classify as ErrUpstream, got %v", up)
	}
	// A policy/authorization denial is left unwrapped (frontend maps it to 403).
	den := classifySignErr(fmt.Errorf("caller %q not authorised", "x"))
	if errors.Is(den, ErrUpstream) {
		t.Errorf("a policy denial must not classify as ErrUpstream, got %v", den)
	}
}

func testEngine() *Engine {
	return &Engine{cfg: &Config{Hosts: map[string]HostConfig{
		"target":  {Addr: "t:22", Jump: "mid"},
		"mid":     {Addr: "m:22", Jump: "bastion"},
		"bastion": {Addr: "b:22"},
		"direct":  {Addr: "d:22"},
		"loopA":   {Addr: "a:22", Jump: "loopB"},
		"loopB":   {Addr: "b:22", Jump: "loopA"},
		"badjump": {Addr: "x:22", Jump: "nope"},
	}}}
}

func TestResolveChain(t *testing.T) {
	e := testEngine()
	cases := []struct {
		host string
		want []string
	}{
		{"direct", []string{"direct"}},
		{"target", []string{"bastion", "mid", "target"}}, // dial order
	}
	for _, c := range cases {
		got, err := e.resolveChain(c.host)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.host, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: chain = %v, want %v", c.host, got, c.want)
		}
	}
}

// dryRunEngine builds a local-mode Engine with a command policy and an audit
// log in a temporary file, suitable for testing the dry-run path without
// network or CA key (no signing happens in dry-run).
func dryRunEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := &Config{Hosts: map[string]HostConfig{
		"locked": {
			Addr: "h:22", User: "deploy", Principal: "host:locked",
			CommandPolicy: signer.CommandPolicy{
				Mode:            signer.CmdPolicyAllowlist,
				Allow:           []string{`^uptime$`, `^systemctl (status|restart) `},
				RequireApproval: []string{`^systemctl restart `},
			},
		},
	}}
	al, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	return &Engine{
		cfg:      cfg,
		sgn:      signer.NewLocal(nil, policyFromHosts(cfg), 2*time.Minute),
		auditLog: al,
		maxTTL:   2 * time.Minute,
	}
}

func TestExecuteDryRunAllowed(t *testing.T) {
	e := dryRunEngine(t)
	res, err := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "uptime", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run must not fail: %v", err)
	}
	if res.DryRun == nil {
		t.Fatal("Result.DryRun must be populated in dry-run")
	}
	if !res.DryRun.Allowed {
		t.Errorf("uptime must be allowed: %+v", res.DryRun)
	}
	if res.DryRun.ForceCommand != "uptime" {
		t.Errorf("force-command = %q, want uptime", res.DryRun.ForceCommand)
	}
	// Dry-run does not execute: no stdout or serial.
	if res.Stdout != "" || res.Serial != 0 {
		t.Errorf("dry-run must not produce output/serial: %+v", res)
	}
}

func TestExecuteDryRunDenied(t *testing.T) {
	e := dryRunEngine(t)
	res, err := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "rm -rf /", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("a policy denial in dry-run is a result, not an error: %v", err)
	}
	if res.DryRun == nil || res.DryRun.Allowed {
		t.Errorf("rm -rf / must be denied: %+v", res.DryRun)
	}
	if res.DryRun.Reason == "" {
		t.Error("a denial must include a reason")
	}
}

func TestExecuteDryRunRequireApproval(t *testing.T) {
	e := dryRunEngine(t)
	// systemctl restart is in the allowlist AND matches require_approval: allowed
	// but flagged as pending human approval.
	res, err := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "systemctl restart nginx", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run must not fail: %v", err)
	}
	if res.DryRun == nil || !res.DryRun.Allowed {
		t.Fatalf("systemctl restart must be allowed: %+v", res.DryRun)
	}
	if !res.DryRun.RequireApproval {
		t.Error("Result.DryRun.RequireApproval must be true")
	}
	// systemctl status: allowed and no approval needed.
	res2, _ := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "systemctl status nginx", 0, ExecOptions{DryRun: true})
	if res2.DryRun == nil || !res2.DryRun.Allowed || res2.DryRun.RequireApproval {
		t.Errorf("systemctl status: allowed without approval, got %+v", res2.DryRun)
	}
}

func TestExecuteDryRunUnknownHost(t *testing.T) {
	e := dryRunEngine(t)
	if _, err := e.Execute(context.Background(), Caller{ID: "tester"}, "nope", "uptime", 0, ExecOptions{DryRun: true}); err == nil {
		t.Error("unknown host must fail even in dry-run")
	}
}

func TestExecuteRefreshesHostsBeforeDryRun(t *testing.T) {
	e := engineForSessionTests(t)
	fetcher := &mutableHostFetcher{hosts: map[string]signer.HostInfo{
		"fresh": {Addr: "fresh.example:22", User: "deploy", HostKey: "fresh-key"},
	}}
	e.fetcher = fetcher
	e.hosts = map[string]signer.HostInfo{}
	e.sgn = &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}}
	e.maxTTL = time.Minute

	res, err := e.Execute(context.Background(), Caller{ID: "tester"}, "fresh", "uptime", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Execute dry-run must use refreshed hosts: %v", err)
	}
	if res.DryRun == nil || !res.DryRun.Allowed {
		t.Fatalf("dry-run decision not propagated: %+v", res.DryRun)
	}
	if fetcher.count != 1 {
		t.Fatalf("host list refreshes = %d, want 1", fetcher.count)
	}
}

func TestExecuteFailsClosedWhenHostRefreshFails(t *testing.T) {
	e := engineForSessionTests(t)
	e.fetcher = &mutableHostFetcher{err: errors.New("signer down")}
	e.sgn = &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}}

	_, err := e.Execute(context.Background(), Caller{ID: "tester"}, "stale", "uptime", 0, ExecOptions{DryRun: true})
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("refresh failure must be ErrUpstream, got %v", err)
	}
}

func TestOpenSessionRefreshesHostsBeforeSigning(t *testing.T) {
	e := engineForSessionTests(t)
	fetcher := &mutableHostFetcher{hosts: map[string]signer.HostInfo{
		"fresh": {Addr: "fresh.example:22", User: "deploy", HostKey: "fresh-key"},
	}}
	e.fetcher = fetcher
	e.hosts = map[string]signer.HostInfo{}
	stop := errors.New("stop before dial")
	e.sgn = &sessionPolicySigner{err: stop}

	_, err := e.OpenSession(context.Background(), Caller{ID: "tester"}, "fresh", "exec", 0, ExecOptions{})
	if !errors.Is(err, stop) {
		t.Fatalf("OpenSession must reach signing after refresh, got %v", err)
	}
	if fetcher.count != 1 {
		t.Fatalf("host list refreshes = %d, want 1", fetcher.count)
	}
}

func TestOpenSessionFailsClosedWhenHostRefreshFails(t *testing.T) {
	e := engineForSessionTests(t)
	e.fetcher = &mutableHostFetcher{err: errors.New("signer down")}

	_, err := e.OpenSession(context.Background(), Caller{ID: "tester"}, "stale", "exec", 0, ExecOptions{})
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("refresh failure must be ErrUpstream, got %v", err)
	}
}

func TestResolveChainErrors(t *testing.T) {
	e := testEngine()
	if _, err := e.resolveChain("loopA"); err == nil {
		t.Error("expected error for bastion cycle")
	}
	if _, err := e.resolveChain("badjump"); err == nil {
		t.Error("expected error for unknown bastion")
	}
	if _, err := e.resolveChain("inexistente"); err == nil {
		t.Error("expected error for unknown host")
	}
}

// fakeFetcher satisfies hostFetcher so a remote-mode Engine can be built in
// tests without a network signer.
type fakeFetcher struct{}

func (fakeFetcher) FetchHosts(context.Context, string) (map[string]signer.HostInfo, error) {
	return nil, nil
}

// TestServerInfosFilteredByCallerGroups verifies that ssh_list_servers only
// shows a group-restricted user the hosts it can actually sign for, in both
// local and remote mode. Callers without groups (stdio/mTLS) see every host.
func TestServerInfosFilteredByCallerGroups(t *testing.T) {
	local := &Engine{cfg: &Config{Hosts: map[string]HostConfig{
		"web01":  {Addr: "w:22", Groups: []string{"prod-web"}},
		"db01":   {Addr: "d:22", Groups: []string{"prod-db"}},
		"orphan": {Addr: "o:22"}, // no groups: invisible to restricted users
		"multi":  {Addr: "m:22", Groups: []string{"prod-db", "prod-web"}},
	}}}
	remote := &Engine{fetcher: fakeFetcher{}, hosts: map[string]signer.HostInfo{
		"web01":  {Addr: "w:22", Groups: []string{"prod-web"}},
		"db01":   {Addr: "d:22", Groups: []string{"prod-db"}},
		"orphan": {Addr: "o:22"},
		"multi":  {Addr: "m:22", Groups: []string{"prod-db", "prod-web"}},
	}}

	cases := []struct {
		name   string
		caller Caller
		want   []string
	}{
		{"nil groups sees all", Caller{ID: "mcp-stdio"}, []string{"db01", "multi", "orphan", "web01"}},
		{"restricted to prod-web", Caller{ID: "alice", Groups: []string{"prod-web"}}, []string{"multi", "web01"}},
		{"empty groups sees nothing", Caller{ID: "bob", Groups: []string{}}, []string{}},
		{"unknown group sees nothing", Caller{ID: "eve", Groups: []string{"staging"}}, []string{}},
	}
	for _, mode := range []struct {
		label string
		eng   *Engine
	}{{"local", local}, {"remote", remote}} {
		for _, tc := range cases {
			got := mode.eng.ServerInfos(tc.caller)
			names := make([]string, 0, len(got))
			for _, s := range got {
				names = append(names, s.Name)
			}
			if !reflect.DeepEqual(names, tc.want) && !(len(names) == 0 && len(tc.want) == 0) {
				t.Errorf("%s/%s: hosts = %v, want %v", mode.label, tc.name, names, tc.want)
			}
		}
	}
}

// TestParseHostKeyCached verifies the host key is parsed once and memoised
// (content-addressed by the authorized_keys line), and that parse errors are
// cached too.
func TestParseHostKeyCached(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub)) // "ssh-ed25519 AAAA...\n"

	e := &Engine{}
	k1, err := e.parseHostKeyCached(line)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if _, ok := e.hostKeyCache.Load(line); !ok {
		t.Fatal("key not memoised after first parse")
	}
	k2, err := e.parseHostKeyCached(line)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	// Both calls must yield the same key bytes as the original.
	for _, k := range []ssh.PublicKey{k1, k2} {
		if string(k.Marshal()) != string(sshPub.Marshal()) {
			t.Error("cached key does not match the original")
		}
	}

	// Parse errors are negatively cached.
	const bad = "not-a-key"
	if _, err := e.parseHostKeyCached(bad); err == nil {
		t.Fatal("expected an error for an invalid key line")
	}
	v, ok := e.hostKeyCache.Load(bad)
	if !ok {
		t.Fatal("error not memoised")
	}
	if _, isErr := v.(error); !isErr {
		t.Errorf("cached value for a bad key = %T, want error", v)
	}
}

// countingFetcher counts FetchHosts calls so a refresh-goroutine test can prove
// the goroutine both runs and then stops.
type countingFetcher struct{ n *int32 }

func (f countingFetcher) FetchHosts(context.Context, string) (map[string]signer.HostInfo, error) {
	atomic.AddInt32(f.n, 1)
	return map[string]signer.HostInfo{}, nil
}

// TestHostRefreshStopsOnClose verifies the host-refresh goroutine exits when its
// stop channel is closed (what Engine.Close does), so it does not leak past the
// engine's lifetime.
func TestHostRefreshStopsOnClose(t *testing.T) {
	var calls int32
	e := &Engine{fetcher: countingFetcher{n: &calls}}
	base := runtime.NumGoroutine()
	e.startHostRefresh(time.Millisecond)

	// Wait until it has ticked at least once (it is running).
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("refresh goroutine never ran")
		}
		time.Sleep(time.Millisecond)
	}

	// Closing the stop channel (as Close does) must terminate the goroutine.
	e.refreshStopOnce.Do(func() { close(e.refreshStop) })

	deadline = time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			t.Fatalf("refresh goroutine did not stop (goroutines: %d > base %d)", runtime.NumGoroutine(), base)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestIgnoredRemoteFieldsWarning covers the #178 startup diagnostic: a remote-
// mode config that also carries local-mode fields must name them; a pure remote
// or pure local config must stay silent.
func TestIgnoredRemoteFieldsWarning(t *testing.T) {
	t.Parallel()
	remote := func() *Config { return &Config{Signer: &SignerClientConfig{URL: "https://signer:8443"}} }
	cases := []struct {
		name      string
		cfg       *Config
		wantEmpty bool
		wantSub   []string // every substring must appear
	}{
		{
			name:      "pure local (no signer) — every field is honoured",
			cfg:       &Config{CAKey: "pki/ca", Hosts: map[string]HostConfig{"web01": {CommandPolicy: signer.CommandPolicy{Mode: "allowlist"}}}},
			wantEmpty: true,
		},
		{
			name:      "pure remote — nothing ignored",
			cfg:       remote(),
			wantEmpty: true,
		},
		{
			name:    "remote + ca_key",
			cfg:     func() *Config { c := remote(); c.CAKey = "pki/ca"; return c }(),
			wantSub: []string{"ca_key", "Host inventory and policy come from the signer"},
		},
		{
			name: "remote + host command_policy names host and field",
			cfg: func() *Config {
				c := remote()
				c.Hosts = map[string]HostConfig{"web01": {CommandPolicy: signer.CommandPolicy{Mode: "allowlist", Allow: []string{"^id$"}}}}
				return c
			}(),
			wantSub: []string{"web01", "command_policy"},
		},
		{
			name: "remote + aggregated top-level and per-host fields",
			cfg: func() *Config {
				c := remote()
				c.CAKey = "pki/ca"
				c.CommandPolicies = map[string]signer.CommandPolicy{"lib": {Mode: "denylist"}}
				c.Hosts = map[string]HostConfig{
					"web01": {AllowSudo: true, CommandPolicy: signer.CommandPolicy{Mode: "allowlist"}},
					"db01":  {Principal: "ops"},
				}
				return c
			}(),
			wantSub: []string{"ca_key", "command_policies", "2 host(s)", "web01: command_policy, allow_sudo", "db01: principal"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ignoredRemoteFieldsWarning(c.cfg)
			if c.wantEmpty {
				if got != "" {
					t.Fatalf("want no warning, got %q", got)
				}
				return
			}
			if got == "" {
				t.Fatalf("want a warning, got none")
			}
			for _, sub := range c.wantSub {
				if !strings.Contains(got, sub) {
					t.Errorf("warning missing %q\n  got: %s", sub, got)
				}
			}
		})
	}
}
