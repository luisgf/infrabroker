package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestApprovalListRendersStrippedEndUser pins #668: a request whose end_user was
// dropped (broker not in trusted_forwarders, #451) must not render like one that
// never carried an end user.
func TestApprovalListRendersStrippedEndUser(t *testing.T) {
	t.Parallel()
	var items []approvalListItem
	body := `[
	  {"id":"a1","status":"pending","caller":"broker-1","host":"web01","command":"reboot","end_user_stripped":true},
	  {"id":"a2","status":"pending","caller":"broker-1","host":"web01","command":"reboot"},
	  {"id":"a3","status":"pending","caller":"broker-1","host":"web01","command":"reboot","end_user":"alice@corp.com"}
	]`
	if err := json.Unmarshal([]byte(body), &items); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"user=(stripped) ", "user=- ", "user=alice@corp.com "} {
		if got := formatApprovalItem(items[i]); !strings.Contains(got, want) {
			t.Errorf("item %d: %q should contain %q", i, got, want)
		}
	}
}
