package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sampleApproval devuelve un Approval de prueba con todos los campos relevantes.
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

// captureWebhook levanta un httptest.Server que captura el body de la petición
// y responde 200. Devuelve el servidor y un puntero al body capturado.
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

// ── Formato workflow (Adaptive Card) ─────────────────────────────────────────

func TestTeamsNotifierAdaptiveCardFormato(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	// El sobre de mensaje debe tener type=message y attachments.
	var envelope map[string]any
	if err := json.Unmarshal(*body, &envelope); err != nil {
		t.Fatalf("body no es JSON: %v\nbody=%s", err, *body)
	}
	if envelope["type"] != "message" {
		t.Errorf("type=%v, quiero 'message'", envelope["type"])
	}
	attachments, ok := envelope["attachments"].([]any)
	if !ok || len(attachments) == 0 {
		t.Fatal("attachments ausente o vacío")
	}
	att := attachments[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("contentType=%v", att["contentType"])
	}
	content, ok := att["content"].(map[string]any)
	if !ok {
		t.Fatal("content no es un objeto")
	}
	if content["type"] != "AdaptiveCard" {
		t.Errorf("card type=%v, quiero 'AdaptiveCard'", content["type"])
	}
}

func TestTeamsNotifierAdaptiveCardAliasAdaptivecard(t *testing.T) {
	// "adaptivecard" debe comportarse igual que "workflow".
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatAdaptiveCard, "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(*body, &envelope); err != nil {
		t.Fatalf("body no es JSON: %v", err)
	}
	if envelope["type"] != "message" {
		t.Errorf("formato adaptivecard debe producir envelope type=message, got %v", envelope["type"])
	}
}

func TestTeamsNotifierDefaultFormatoEsWorkflow(t *testing.T) {
	// Formato vacío → workflow.
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, "", "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(*body, &envelope); err != nil {
		t.Fatalf("body no es JSON: %v", err)
	}
	if envelope["type"] != "message" {
		t.Errorf("formato por defecto debe ser workflow (type=message), got %v", envelope["type"])
	}
}

// ── Formato messagecard (legacy) ─────────────────────────────────────────────

func TestTeamsNotifierMessageCardFormato(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatMessageCard, "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var card map[string]any
	if err := json.Unmarshal(*body, &card); err != nil {
		t.Fatalf("body no es JSON: %v", err)
	}
	if card["@type"] != "MessageCard" {
		t.Errorf("@type=%v, quiero 'MessageCard'", card["@type"])
	}
	sections, ok := card["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatal("sections ausente o vacío")
	}
}

// ── Contenido de los facts ────────────────────────────────────────────────────

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
					t.Errorf("formato=%s: campo %q no aparece en el payload", format, want)
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
		t.Error("SudoUser 'postgres' debe aparecer en el payload de elevación")
	}
}

func TestTeamsNotifierElevacionSinUsuarioMuestraRoot(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	a := sampleApproval()
	a.Sudo = true
	a.SudoUser = "" // sin usuario → root
	if err := n.Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if !strings.Contains(string(*body), "root") {
		t.Error("elevación sin SudoUser debe mostrar 'root'")
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
		t.Errorf("URL de aprobación %q no aparece en el payload (workflow)", expectedURL)
	}
	// Debe incluir Action.OpenUrl
	if !strings.Contains(string(*body), "Action.OpenUrl") {
		t.Error("payload workflow debe incluir 'Action.OpenUrl' cuando hay approval_url_template")
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
		t.Errorf("URL de aprobación %q no aparece en el payload (messagecard)", expectedURL)
	}
	if !strings.Contains(string(*body), "OpenUri") {
		t.Error("payload messagecard debe incluir 'OpenUri' cuando hay approval_url_template")
	}
}

func TestTeamsNotifierSinTemplateSinAccion(t *testing.T) {
	// Sin template, la card no debe incluir ninguna acción.
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	if err := n.Notify(sampleApproval()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if strings.Contains(string(*body), "Action.OpenUrl") {
		t.Error("sin approval_url_template no debe haber Action.OpenUrl en el payload")
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
		t.Errorf("renderURL con template vacío debe devolver \"\", got %q", got)
	}
}

// ── Seguridad: no filtra campos privados / pubkey ─────────────────────────────

func TestTeamsNotifierNoFiltraPubkey(t *testing.T) {
	srv, body := captureWebhook(t)
	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")

	a := sampleApproval()
	// El campo req (WireRequest, que contiene la pubkey efímera) es privado;
	// no puede asignarse directamente aquí, pero verificamos que el JSON no
	// contiene claves típicas de WireRequest que indicarían una fuga.
	if err := n.Notify(a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	raw := string(*body)
	for _, leaked := range []string{"public_key", "PublicKey", "ttl_seconds", "on_behalf_of"} {
		if strings.Contains(raw, leaked) {
			t.Errorf("el payload no debe contener %q (campo interno de WireRequest)", leaked)
		}
	}
}

// ── Manejo de errores HTTP ────────────────────────────────────────────────────

func TestTeamsNotifierErrorStatusHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")
	err := n.Notify(sampleApproval())
	if err == nil {
		t.Fatal("Notify debe devolver error cuando el servidor responde 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error debe mencionar el código HTTP, got: %v", err)
	}
}

func TestTeamsNotifierError4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	n := NewTeamsNotifier(srv.URL, TeamsFormatWorkflow, "")
	if err := n.Notify(sampleApproval()); err == nil {
		t.Fatal("Notify debe devolver error cuando el servidor responde 400")
	}
}

// ── Approval sin campos opcionales ───────────────────────────────────────────

func TestTeamsNotifierApprovalMinimo(t *testing.T) {
	// Aprobación sin end_user, sudo ni rule — el payload debe seguir siendo válido.
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
		t.Fatalf("body no es JSON para aprobación mínima: %v", err)
	}
	if envelope["type"] != "message" {
		t.Errorf("type=%v, quiero 'message'", envelope["type"])
	}
}
