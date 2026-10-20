package mcpserver

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/infrabroker/internal/broker"
)

// testEngineNoClusters builds a minimal engine (no Kubernetes clusters) good
// enough to register the k8s tools. The input-validation gate short-circuits
// before the engine is ever touched, so no live cluster is needed.
func testEngineNoClusters(t *testing.T) *broker.Engine {
	t.Helper()
	return newTestEngine(t, map[string]broker.HostConfig{
		"web01": {Addr: "10.0.0.21:22", User: "deploy", Principal: "host:web01", HostKey: "ssh-ed25519 AAAAC3Nz"},
	})
}

// k8sTestSession registers the k8s tools on an in-memory server and returns a
// connected client session.
func k8sTestSession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	eng := testEngineNoClusters(t)
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterK8s(srv, eng, func(context.Context) broker.Caller { return broker.Caller{ID: "test"} })

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

func k8sToolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// TestK8sApprovalWordingNeverOffersInChatApproval pins #599: the engine's
// shared ApprovalRequiredError offers in-chat approval "(if enabled)", but the
// k8s tools never elicit (only ssh_execute does), so the message the model
// sees for an approval-gated k8s action must point at the control plane /
// broker-ctl only. Other errors pass through untouched.
func TestK8sApprovalWordingNeverOffersInChatApproval(t *testing.T) {
	t.Parallel()
	appErr := &broker.ApprovalRequiredError{Host: "prod-k8s", Rule: "require_approval:^delete pods prod/"}
	got := k8sApprovalWording("prod-k8s", appErr).Error()
	if strings.Contains(got, "in-chat (if enabled)") || !strings.Contains(got, "not available") {
		t.Errorf("k8s approval wording must not offer in-chat approval: %q", got)
	}
	for _, want := range []string{`"prod-k8s"`, appErr.Rule, "control plane", "broker-ctl"} {
		if !strings.Contains(got, want) {
			t.Errorf("k8s approval wording missing %q: %q", want, got)
		}
	}
	// Wrapped approval errors are recognised too; anything else is unchanged.
	if got := k8sApprovalWording("prod-k8s", errors.Join(appErr)).Error(); strings.Contains(got, "in-chat (if enabled)") {
		t.Errorf("wrapped approval error must be rewritten: %q", got)
	}
	other := errors.New("not allowed by cluster policy")
	if got := k8sApprovalWording("prod-k8s", other); got != other {
		t.Errorf("non-approval errors must pass through unchanged, got %v", got)
	}
}

// TestK8sSelectorAndContainerValidated is the regression test for the gap where
// k8s_list selectors and the k8s_logs container bypassed validateInput. Before
// the fix a null byte in those fields passed the input gate and reached the
// engine (producing a cluster-not-found error, not a validation error); the fix
// rejects it up front with the same null-byte/length guarantees every other
// field gets.
func TestK8sSelectorAndContainerValidated(t *testing.T) {
	t.Parallel()
	sess := k8sTestSession(t)
	ctx := context.Background()
	big := strings.Repeat("a", 64*1024+1)

	cases := []struct {
		name string
		tool string
		args map[string]any
		want string
	}{
		{"list_label_selector_null", "k8s_list",
			map[string]any{"cluster": "c1", "resource": "pods", "label_selector": "app=x\x00y"}, "null bytes"},
		{"list_field_selector_null", "k8s_list",
			map[string]any{"cluster": "c1", "resource": "pods", "field_selector": "status.phase=\x00"}, "null bytes"},
		{"list_label_selector_too_long", "k8s_list",
			map[string]any{"cluster": "c1", "resource": "pods", "label_selector": big}, "exceeds the limit"},
		{"logs_container_null", "k8s_logs",
			map[string]any{"cluster": "c1", "namespace": "ns", "pod": "p", "container": "c\x00"}, "null bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
			if err != nil {
				t.Fatalf("CallTool transport error: %v", err)
			}
			if !res.IsError {
				t.Fatalf("expected a tool error, got success: %s", k8sToolText(t, res))
			}
			if got := k8sToolText(t, res); !strings.Contains(got, tc.want) {
				t.Fatalf("error %q does not contain %q — validation gate did not fire", got, tc.want)
			}
		})
	}
}
