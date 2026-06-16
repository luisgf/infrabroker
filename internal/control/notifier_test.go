package control

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// TestLogNotifierShowsElevation verifies that the default notifier surfaces the
// sudo elevation, so a human approver sees that an innocuous-looking command
// would have its force-command issued under sudo. (Not parallel: it redirects
// the global logger.)
func TestLogNotifierShowsElevation(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	err := LogNotifier{}.Notify(Approval{
		ID: "x", Caller: "broker-1", Host: "web01",
		Command: "systemctl restart nginx", Sudo: true, SudoUser: "root",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "elevation=sudo:root") {
		t.Errorf("LogNotifier must surface the elevation; got %q", out)
	}

	// No sudo → elevation=none.
	buf.Reset()
	_ = LogNotifier{}.Notify(Approval{ID: "y", Caller: "broker-1", Host: "web01", Command: "uptime"})
	if out := buf.String(); !strings.Contains(out, "elevation=none") {
		t.Errorf("non-elevated request must show elevation=none; got %q", out)
	}
}
