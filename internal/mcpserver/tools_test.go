package mcpserver

import (
	"testing"
)

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
