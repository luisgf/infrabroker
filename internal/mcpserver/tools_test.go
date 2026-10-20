package mcpserver

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/infrabroker/internal/broker"
)

// TestToolErrorHidesUpstreamAddress pins #472: an infrastructure error from the
// engine (SSH dial/hop failure, signing service unreachable) must not reach the
// model verbatim, since it carries the internal ip:port of the target or the
// jump host. Mirrors brokermain's TestClassifyErrorUpstreamHidesInternalAddr:
// the HTTP frontend masks ErrUpstream, so the MCP frontends must as well.
func TestToolErrorHidesUpstreamAddress(t *testing.T) {
	t.Parallel()
	cases := []error{
		fmt.Errorf("%w: connection: connecting to 10.1.2.3:22: dial tcp 10.1.2.3:22: i/o timeout", broker.ErrUpstream),
		fmt.Errorf("%w: connection: hop to 10.1.2.3:22: dial tcp 10.1.2.3:22: connection refused", broker.ErrUpstream),
		fmt.Errorf("%w: refreshing host list: Get \"https://10.1.2.3:8443/v1/hosts\": connection refused", broker.ErrUpstream),
	}
	for _, err := range cases {
		res := toolError(err)
		if !res.IsError {
			t.Fatalf("toolError(%v): IsError must be true", err)
		}
		if len(res.Content) != 1 {
			t.Fatalf("toolError(%v): want 1 content item, got %d", err, len(res.Content))
		}
		text := res.Content[0].(*mcp.TextContent).Text
		if strings.Contains(text, "10.1.2.3") {
			t.Errorf("upstream tool error must not leak internal addresses, got %q", text)
		}
		if text != upstreamToolMessage {
			t.Errorf("upstream tool error = %q, want the generic %q", text, upstreamToolMessage)
		}
	}
}

// TestToolErrorKeepsPolicyText: denials and other non-infrastructure errors
// keep their text, which is what the model needs to self-correct.
func TestToolErrorKeepsPolicyText(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		errors.New("command denied by host policy: deny:^rm "),
		fmt.Errorf("%w: unknown field", broker.ErrBadRequest),
		fmt.Errorf("%w: nope", broker.ErrUnknownHost),
	} {
		text := toolError(err).Content[0].(*mcp.TextContent).Text
		if text != err.Error() {
			t.Errorf("toolError(%v) = %q, want the error text verbatim", err, text)
		}
	}
}

// TestEncodedBoundAndOversizedContentReject pins #396: ssh_put_file content
// bypasses maxInputLen, so the handler must bound the raw (base64-encoded)
// content at base64(4/3 of the transfer cap)+padding BEFORE decoding it.
func TestEncodedBoundAndOversizedContentReject(t *testing.T) {
	t.Parallel()
	max := 512 * 1024
	bound := encodedBound(max)
	// Exact base64 length for max bytes: 4*ceil(max/3). The bound is a
	// slightly looser (max/3 + 4) variant — it must never be UNDER it, and
	// within 32 bytes of it.
	want := ((max + 2) / 3) * 4
	if bound < want {
		t.Errorf("encodedBound(%d) = %d, must be at least the exact base64 length %d", max, bound, want)
	}
	if bound-want > 32 {
		t.Errorf("encodedBound(%d) = %d, unnecessarily loose vs exact %d", max, bound, want)
	}
}
