package mcpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/signer"
)

func TestReasonCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		d    signer.DecisionInfo
		want string
	}{
		{"allowed", signer.DecisionInfo{Allowed: true, MatchedRule: "allow:^uptime$"}, "allowed"},
		{"needs_approval", signer.DecisionInfo{Allowed: true, RequireApproval: true}, "needs_approval"},
		{"command_denied", signer.DecisionInfo{MatchedRule: "deny:^rm "}, "command_denied"},
		{"allowlist_no_match", signer.DecisionInfo{MatchedRule: "allowlist:no-match"}, "allowlist_no_match"},
		{"shell_parse_error", signer.DecisionInfo{MatchedRule: "shell-parse:syntax error"}, "shell_parse_error"},
		{"denied_fallback", signer.DecisionInfo{MatchedRule: "something-unexpected"}, "denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reasonCode(&tc.d); got != tc.want {
				t.Errorf("reasonCode = %q, want %q", got, tc.want)
			}
			out := decisionToOutput(&tc.d)
			if out.ReasonCode != tc.want {
				t.Errorf("decisionToOutput.ReasonCode = %q, want %q", out.ReasonCode, tc.want)
			}
			if out.Allowed != tc.d.Allowed {
				t.Errorf("decisionToOutput.Allowed = %v, want %v", out.Allowed, tc.d.Allowed)
			}
		})
	}
	if decisionToOutput(nil) != nil {
		t.Error("decisionToOutput(nil) must be nil")
	}
}

// sshDryRunSession registers the SSH tools on an in-memory server with two
// policy hosts: web01 (denylist ^rm ) and web02 (allowlist ^uptime$). Dry-run
// resolves the policy without connecting, so no live host is needed.
func sshDryRunSession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	dir := t.TempDir()
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(caPriv, "ca-test")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "audit.seed")
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	eng, err := broker.NewEngine(&broker.Config{
		CAKey:         caPath,
		AuditLog:      filepath.Join(dir, "audit.log"),
		AuditKey:      seedPath,
		SourceAddress: "127.0.0.1",
		MaxTTLSeconds: 120,
		Hosts: map[string]broker.HostConfig{
			"web01": {Addr: "10.0.0.21:22", User: "deploy", Principal: "host:web01", HostKey: "ssh-ed25519 AAAAC3Nz",
				CommandPolicy: signer.CommandPolicy{Mode: signer.CmdPolicyDenylist, Deny: []string{"^rm "}}},
			"web02": {Addr: "10.0.0.22:22", User: "deploy", Principal: "host:web02", HostKey: "ssh-ed25519 AAAAC3Nz",
				CommandPolicy: signer.CommandPolicy{Mode: signer.CmdPolicyAllowlist, Allow: []string{"^uptime$"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(srv, eng, func(context.Context) broker.Caller { return broker.Caller{ID: "test"} })
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

// TestSSHExecuteDryRunStructuredDecision pins the point of #119: a dry-run
// returns the decision as structuredContent (not just prose), with a stable
// reason_code the agent can branch on.
func TestSSHExecuteDryRunStructuredDecision(t *testing.T) {
	t.Parallel()
	sess := sshDryRunSession(t)
	ctx := context.Background()

	type dec struct {
		Allowed    bool   `json:"allowed"`
		ReasonCode string `json:"reason_code"`
	}
	call := func(server, command string) dec {
		t.Helper()
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "ssh_execute",
			Arguments: map[string]any{"server": server, "command": command, "dry_run": true},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected tool error: %s", k8sToolText(t, res))
		}
		var out struct {
			Decision *dec `json:"decision"`
		}
		raw, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode structuredContent: %v (%s)", err, raw)
		}
		if out.Decision == nil {
			t.Fatalf("dry-run must populate structuredContent.decision; got %s", raw)
		}
		return *out.Decision
	}

	if d := call("web01", "rm -rf /tmp/x"); d.Allowed || d.ReasonCode != "command_denied" {
		t.Errorf("denylist deny: allowed=%v reason_code=%q, want false/command_denied", d.Allowed, d.ReasonCode)
	}
	if d := call("web01", "id"); !d.Allowed || d.ReasonCode != "allowed" {
		t.Errorf("denylist allow: allowed=%v reason_code=%q, want true/allowed", d.Allowed, d.ReasonCode)
	}
	if d := call("web02", "reboot"); d.Allowed || d.ReasonCode != "allowlist_no_match" {
		t.Errorf("allowlist no-match: allowed=%v reason_code=%q, want false/allowlist_no_match", d.Allowed, d.ReasonCode)
	}
	if d := call("web02", "uptime"); !d.Allowed || d.ReasonCode != "allowed" {
		t.Errorf("allowlist match: allowed=%v reason_code=%q, want true/allowed", d.Allowed, d.ReasonCode)
	}
}
