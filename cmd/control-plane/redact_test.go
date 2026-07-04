package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/redact"
)

// captureNotifier records the last approval it was asked to notify.
type captureNotifier struct{ last control.Approval }

func (c *captureNotifier) Notify(a control.Approval) error {
	c.last = a
	return nil
}

// TestApprovalNotificationRedacted verifies the redaction split on the
// approval flow: the notifier payload (log/webhook/Teams — persists or leaves
// the host) is redacted, while the registry keeps the original command so the
// mTLS approval UI/API shows the approver exactly what will run, and the
// audit log free-text is redacted.
func TestApprovalNotificationRedacted(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	redactor, err := redact.New(&redact.Config{}) // defaults
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	s.redactor = redactor
	s.audit.SetRedactor(redactor)
	notifier := &captureNotifier{}
	s.notifier = notifier

	// "reboot ..." requires approval in the stub signer.
	const cmd = "reboot --password=hunter2"
	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, cmd)))
	if w.Code != 202 {
		t.Fatalf("expected 202 approval-required, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	// Outbound sink: redacted.
	if strings.Contains(notifier.last.Command, "hunter2") {
		t.Errorf("notifier payload must be redacted: %q", notifier.last.Command)
	}
	if !strings.Contains(notifier.last.Command, "[REDACTED:flag-password]") {
		t.Errorf("notifier payload missing the redaction marker: %q", notifier.last.Command)
	}

	// Approver-facing registry (mTLS UI/API): the original command, untouched.
	a, ok := s.registry.Get(resp["approval_id"])
	if !ok {
		t.Fatal("approval not found in registry")
	}
	if a.Command != cmd {
		t.Errorf("registry must keep the original command for the approver: %q", a.Command)
	}
}
