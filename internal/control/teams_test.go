package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// sampleApproval returns a test Approval with all relevant fields populated.
func sampleApproval() Approval {
	return Approval{
		ID:        "abc123def456abc1",
		Caller:    "broker-1",
		EndUser:   "alice@contoso.com",
		Host:      "db-prod-01",
		Command:   "systemctl restart postgresql",
		Sudo:      true,
		SudoUser:  "postgres",
		Rule:      "^systemctl restart ",
		Status:    StatusPending,
		CreatedAt: time.Date(2026, 6, 8, 14, 0, 0, 0, time.UTC),
	}
}

// captureWebhook starts an httptest.Server that captures the request body and
// responds 200. Returns the server and a pointer to the captured body.
func captureWebhook(t *testing.T) (*httptest.Server, *[]byte) {
	t.Helper()
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf []byte
		buf = make([]byte, 0, 4096)
		tmp := make([]byte, 512)
		for {
			n, err := r.Body.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
		captured = buf
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &captured
}

// ── Workflow format (Adaptive Card) ──────────────────────────────────────────

func TestTeamsNotifierAdaptiveCardFormato(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	// Message envelope must have type=message and attachments.
	var envelope map[string]any
	if err := json.Unmarshal(*body, &envelope); err != nil {
		t.Fatalf("body is not JSON: %v\nbody=%s", err, *body)
	}
	if envelope["type"] != "message" {
		t.Errorf("type=%v, want 'message'", envelope["type"])
	}
	attachments, ok := envelope["attachments"].([]any)
	if !ok || len(attachments) == 0 {
		t.Fatal("attachments absent or empty")
	}
	att := attachments[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("contentType=%v", att["contentType"])
	}
	content, ok := att["content"].(map[string]any)
	if !ok {
		t.Fatal("content is not an object")
	}
	if content["type"] != "AdaptiveCard" {
		t.Errorf("card type=%v, want 'AdaptiveCard'", content["type"])
	}
}

func TestTeamsNotifierAdaptiveCardAliasAdaptivecard(t *testing.T) {
	// "adaptivecard" must behave identically to "workflow".
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatAdaptiveCard, "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(*body, &envelope); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if envelope["type"] != "message" {
		t.Errorf("adaptivecard format must produce envelope type=message, got %v", envelope["type"])
	}
}

func TestTeamsNotifierDefaultFormatoEsWorkflow(t *testing.T) {
	// Empty format → workflow.
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, "", "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(*body, &envelope); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if envelope["type"] != "message" {
		t.Errorf("default format must be workflow (type=message), got %v", envelope["type"])
	}
}

// ── MessageCard format (legacy) ───────────────────────────────────────────────

func TestTeamsNotifierMessageCardFormato(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatMessageCard, "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var card map[string]any
	if err := json.Unmarshal(*body, &card); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if card["@type"] != "MessageCard" {
		t.Errorf("@type=%v, want 'MessageCard'", card["@type"])
	}
	sections, ok := card["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatal("sections absent or empty")
	}
}

// TestTeamsNotifierAdaptiveCardEscapesMarkdown: Teams renders Adaptive Card
// Fact.value as Markdown, so a crafted command must not inject a clickable link
// or formatting into the approver's notification (phishing / command obscuring).
// Sibling of #43, which fixed the MessageCard path with markdown:false.
func TestTeamsNotifierAdaptiveCardEscapesMarkdown(t *testing.T) {
	inject := "restart [APPROVED](https://evil.example/pwn) db"

	// Adaptive Card (default): the link syntax must be neutralized, but the
	// command text still shown (escaped).
	srv, body := captureWebhook(t)
	a := sampleApproval()
	a.Command = inject
	if err := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "").Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	adaptive := string(*body)
	if strings.Contains(adaptive, "](") {
		t.Errorf("Adaptive Card leaked a Markdown link from the command: %s", adaptive)
	}
	if !strings.Contains(adaptive, "APPROVED") {
		t.Error("the command text should still be shown (escaped), just not as a link")
	}

	// MessageCard (legacy): unchanged — markdown:false already renders literally,
	// so it must NOT be escaped (escaping would show stray backslashes).
	srv2, body2 := captureWebhook(t)
	if err := NewTeamsNotifier(srv2.URL, TeamsFormatMessageCard, "").Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	mc := string(*body2)
	if !strings.Contains(mc, `"markdown":false`) {
		t.Error("MessageCard must keep markdown:false")
	}
	if !strings.Contains(mc, "](") {
		t.Error("MessageCard path must render the command literally (raw), not escaped")
	}
}

// ── Facts content ─────────────────────────────────────────────────────────────

func TestTeamsNotifierFactsContienenCamposClave(t *testing.T) {
	for _, format := range []string{TeamsFormatWorkflow, TeamsFormatMessageCard} {
		t.Run(format, func(t *testing.T) {
			srv, body := captureWebhook(t)
			n := NewTeamsNotifier(srv.URL, format, "")

			a := sampleApproval()
			if err := n.Notify(a); err != nil {
				t.Fatalf("Notify: %v", err)
			}

			raw := string(*body)
			for _, want := range []string{a.ID, a.Host, a.Command, a.Caller, a.EndUser} {
				if !strings.Contains(raw, want) {
					t.Errorf("format=%s: field %q not found in payload", format, want)
				}
			}
		})
	}
}

func TestTeamsNotifierElevacionEnFacts(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	a := sampleApproval()
	a.Sudo = true
	a.SudoUser = "postgres"
	if err := n.Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if !strings.Contains(string(*body), "postgres") {
		t.Error("SudoUser 'postgres' must appear in the elevation payload")
	}
}

// TestTeamsNotifierFactsShowStrippedEndUser pins #668: an end_user the control
// plane dropped (broker not a trusted forwarder) is surfaced as an explicit fact,
// and a request with no end user at all gets no End user fact.
func TestTeamsNotifierFactsShowStrippedEndUser(t *testing.T) {
	n := NewTeamsNotifier("http://x", TeamsFormatMessageCard, "")
	endUserFact := func(a Approval) (string, bool) {
		for _, f := range n.approvalFacts(a) {
			if f["name"] == "End user" {
				return f["value"].(string), true
			}
		}
		return "", false
	}

	a := sampleApproval()
	a.EndUser = ""
	a.EndUserStripped = true
	if v, ok := endUserFact(a); !ok || v != "(asserted by an untrusted broker, dropped)" {
		t.Errorf("stripped end user fact = %q, %v", v, ok)
	}

	a.EndUserStripped = false
	if v, ok := endUserFact(a); ok {
		t.Errorf("no end user and not stripped must add no End user fact, got %q", v)
	}

	a.EndUser = "alice@contoso.com"
	if v, _ := endUserFact(a); v != "alice@contoso.com" {
		t.Errorf("a real end user must be shown, got %q", v)
	}
}

func TestTeamsNotifierElevacionSinUsuarioMuestraRoot(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	a := sampleApproval()
	a.Sudo = true
	a.SudoUser = "" // no user → root
	if err := n.Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if !strings.Contains(string(*body), "root") {
		t.Error("elevation without SudoUser must show 'root'")
	}
}

// ── approval_url_template ─────────────────────────────────────────────────────

func TestTeamsNotifierURLTemplateWorkflow(t *testing.T) {
	srv, body := captureWebhook(t)
	template := "https://approvals.example.com/requests/{id}"
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, template)

	a := sampleApproval()
	if err := n.Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	expectedURL := strings.ReplaceAll(template, "{id}", a.ID)
	if !strings.Contains(string(*body), expectedURL) {
		t.Errorf("approval URL %q not found in payload (workflow)", expectedURL)
	}
	// Must include Action.OpenUrl.
	if !strings.Contains(string(*body), "Action.OpenUrl") {
		t.Error("workflow payload must include 'Action.OpenUrl' when approval_url_template is set")
	}
}

func TestTeamsNotifierURLTemplateMessageCard(t *testing.T) {
	srv, body := captureWebhook(t)
	template := "https://approvals.example.com/requests/{id}"
	n := NewTeamsNotifier(srv.URL, TeamsFormatMessageCard, template)

	a := sampleApproval()
	if err := n.Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	expectedURL := strings.ReplaceAll(template, "{id}", a.ID)
	if !strings.Contains(string(*body), expectedURL) {
		t.Errorf("approval URL %q not found in payload (messagecard)", expectedURL)
	}
	if !strings.Contains(string(*body), "OpenUri") {
		t.Error("messagecard payload must include 'OpenUri' when approval_url_template is set")
	}
}

func TestTeamsNotifierSinTemplateSinAccion(t *testing.T) {
	// Without a template, the card must not include any action.
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if strings.Contains(string(*body), "Action.OpenUrl") {
		t.Error("without approval_url_template there must be no Action.OpenUrl in the payload")
	}
}

func TestTeamsNotifierRenderURLSustitucionID(t *testing.T) {
	n := &TeamsNotifier{approvalURLTemplate: "https://example.com/approval/{id}/review"}
	got := n.renderURL("abc123")
	want := "https://example.com/approval/abc123/review"
	if got != want {
		t.Errorf("renderURL: got %q, want %q", got, want)
	}
}

func TestTeamsNotifierRenderURLTemplateVacio(t *testing.T) {
	n := &TeamsNotifier{approvalURLTemplate: ""}
	if got := n.renderURL("anything"); got != "" {
		t.Errorf("renderURL with empty template must return \"\", got %q", got)
	}
}

// ── Security: private fields / pubkey not leaked ──────────────────────────────

func TestTeamsNotifierNoFiltraPubkey(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	a := sampleApproval()
	// The req field (WireRequest, which holds the ephemeral pubkey) is private;
	// it cannot be assigned here, but we verify the JSON does not contain
	// typical WireRequest keys that would indicate a leak.
	if err := n.Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	raw := string(*body)
	for _, leaked := range []string{"public_key", "PublicKey", "ttl_seconds", "on_behalf_of"} {
		if strings.Contains(raw, leaked) {
			t.Errorf("payload must not contain %q (internal WireRequest field)", leaked)
		}
	}
}

// ── HTTP error handling ───────────────────────────────────────────────────────

func TestTeamsNotifierErrorStatusHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")
	err := n.Notify(sampleApproval())
	if err == nil {
		t.Fatal("Notify must return error when server responds 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error must mention the HTTP status code, got: %v", err)
	}
}

func TestTeamsNotifierError4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")
	if err := n.Notify(sampleApproval()); err == nil {
		t.Fatal("Notify must return error when server responds 400")
	}
}

// ── Approval with no optional fields ─────────────────────────────────────────

func TestTeamsNotifierApprovalMinimo(t *testing.T) {
	// Approval without end_user, sudo, or rule — payload must still be valid.
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	a := Approval{
		ID:        "minid001",
		Caller:    "broker-1",
		Host:      "web01",
		Command:   "uptime",
		Status:    StatusPending,
		CreatedAt: time.Now().UTC(),
	}
	if err := n.Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(*body, &envelope); err != nil {
		t.Fatalf("body is not JSON for minimal approval: %v", err)
	}
	if envelope["type"] != "message" {
		t.Errorf("type=%v, want 'message'", envelope["type"])
	}
}

// TestTeamsNotifierBoundsLongCommand pins #666: a 64 KiB command must not make
// the card oversized (Teams rejects it and the approver sees nothing). The fact
// is truncated to TeamsCommandMax bytes plus the marker, in both card formats,
// the Adaptive Card value is still markdown-escaped, and a short command is
// untouched.
func TestTeamsNotifierBoundsLongCommand(t *testing.T) {
	a := sampleApproval()
	a.Command = strings.Repeat("*x", 32*1024) // 64 KiB; every '*' doubles when escaped

	// Adaptive Card: bounded, and the kept text is still escaped.
	srv, body := captureWebhook(t)
	if err := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "").Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if len(*body) > 4*TeamsCommandMax {
		t.Errorf("Adaptive Card payload is %d bytes for a 64 KiB command; want it bounded", len(*body))
	}
	if !strings.Contains(string(*body), `\\*x`) { // JSON-encoded `\*x`
		t.Errorf("the truncated command must still be markdown-escaped: %.200s", *body)
	}
	if !strings.Contains(string(*body), "truncated: 65536 bytes total") {
		t.Errorf("the truncation marker must name the total size: %.200s", *body)
	}

	// MessageCard: both the fact and the summary are bounded.
	srv2, body2 := captureWebhook(t)
	if err := NewTeamsNotifier(srv2.URL, TeamsFormatMessageCard, "").Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if len(*body2) > 3*TeamsCommandMax {
		t.Errorf("MessageCard payload is %d bytes for a 64 KiB command; want it bounded", len(*body2))
	}

	// A short command is unchanged.
	short := sampleApproval()
	facts := NewTeamsNotifier("http://x", TeamsFormatMessageCard, "").approvalFacts(short)
	for _, f := range facts {
		if f["name"] == "Command" && f["value"] != short.Command {
			t.Errorf("a short command must be presented unchanged, got %v", f["value"])
		}
	}
}

func TestPresentedCommand(t *testing.T) {
	if got := PresentedCommand("ls -l", 10); got != "ls -l" {
		t.Errorf("short command changed: %q", got)
	}
	if got := PresentedCommand("0123456789", 10); got != "0123456789" {
		t.Errorf("command at exactly max changed: %q", got)
	}
	got := PresentedCommand("0123456789A", 10)
	if !strings.HasPrefix(got, "0123456789 ... [truncated: 11 bytes total; full command in /ui/approvals/") {
		t.Errorf("unexpected truncation: %q", got)
	}
	// Cut on a rune boundary: "é" is 2 bytes, so max=3 in "aéé" must keep "aé".
	got = PresentedCommand("aéé", 3)
	if !strings.HasPrefix(got, "aé ... [truncated: 5 bytes total") {
		t.Errorf("must cut on a rune boundary, got %q", got)
	}
	if !utf8.ValidString(PresentedCommand(strings.Repeat("é", 100), 51)) {
		t.Error("truncated output must be valid UTF-8")
	}
}
