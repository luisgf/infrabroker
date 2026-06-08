// Package control — TeamsNotifier envía una notificación de aprobación pendiente
// a un canal de Microsoft Teams a través de un Incoming Webhook o un Workflow de
// Power Automate, formateando el payload como una Adaptive Card (formato "workflow"
// o "adaptivecard", recomendado y a prueba de futuro) o como una MessageCard legacy
// (formato "messagecard", para tenants que aún usen M365 Connectors clásicos).
//
// Seguridad: el payload solo contiene campos públicos del struct Approval. El campo
// privado req (que guarda la pubkey efímera) nunca se serializa.
package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Formatos soportados por TeamsNotifier.
const (
	// TeamsFormatWorkflow es el formato Adaptive Card envuelta en el sobre de mensaje
	// requerido por Power Automate Workflows / Incoming Webhooks modernos.
	// Es el formato recomendado por Microsoft y el default.
	TeamsFormatWorkflow = "workflow"

	// TeamsFormatAdaptiveCard es un alias de TeamsFormatWorkflow.
	TeamsFormatAdaptiveCard = "adaptivecard"

	// TeamsFormatMessageCard usa el formato MessageCard legacy de M365 Connectors.
	// Microsoft está retirando este mecanismo; úsalo solo si tu tenant no soporta
	// el formato Workflow todavía.
	TeamsFormatMessageCard = "messagecard"
)

// TeamsNotifier implementa Notifier enviando la notificación de aprobación a un
// canal de Microsoft Teams a través de un webhook.
type TeamsNotifier struct {
	url                 string
	format              string // TeamsFormatWorkflow | TeamsFormatMessageCard
	approvalURLTemplate string // opcional; "{id}" se sustituye por el ID de la solicitud
	client              *http.Client
}

// NewTeamsNotifier crea un notificador para Teams.
//
//   - url: URL del Incoming Webhook (Power Automate Workflow o M365 Connector).
//   - format: "workflow" / "adaptivecard" (recomendado) o "messagecard" (legacy).
//     Cadena vacía → "workflow".
//   - approvalURLTemplate: URL opcional que se incrusta en la card como enlace
//     "View request". Use "{id}" como marcador del approval ID (p. ej.
//     "https://approvals.example.com/requests/{id}"). Si está vacío, no se
//     añade ningún enlace.
func NewTeamsNotifier(url, format, approvalURLTemplate string) *TeamsNotifier {
	if format == "" || format == TeamsFormatAdaptiveCard {
		format = TeamsFormatWorkflow
	}
	return &TeamsNotifier{
		url:                 url,
		format:              format,
		approvalURLTemplate: approvalURLTemplate,
		client:              &http.Client{Timeout: 5 * time.Second},
	}
}

// Notify implementa Notifier. Construye el payload según el formato configurado
// y lo envía por HTTP POST al webhook de Teams.
func (t *TeamsNotifier) Notify(a Approval) error {
	var payload any
	switch t.format {
	case TeamsFormatMessageCard:
		payload = t.buildMessageCard(a)
	default: // workflow / adaptivecard
		payload = t.buildWorkflowEnvelope(a)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("teams notifier: serializar payload: %w", err)
	}
	resp, err := t.client.Post(t.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("teams notifier: POST: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams notifier: webhook devolvió HTTP %d", resp.StatusCode)
	}
	return nil
}

// renderURL sustituye "{id}" en el template por el ID de la solicitud.
// Devuelve cadena vacía si el template está vacío.
func (t *TeamsNotifier) renderURL(id string) string {
	if t.approvalURLTemplate == "" {
		return ""
	}
	return strings.ReplaceAll(t.approvalURLTemplate, "{id}", id)
}

// ── Adaptive Card (formato workflow) ─────────────────────────────────────────

// buildWorkflowEnvelope construye el sobre de mensaje que exige el trigger
// "When a Teams webhook request is received" de Power Automate, envolviendo
// una Adaptive Card v1.4.
func (t *TeamsNotifier) buildWorkflowEnvelope(a Approval) map[string]any {
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"contentUrl":  nil,
				"content":     t.buildAdaptiveCard(a),
			},
		},
	}
}

// buildAdaptiveCard construye el objeto de Adaptive Card v1.4.
func (t *TeamsNotifier) buildAdaptiveCard(a Approval) map[string]any {
	facts := t.approvalFacts(a)

	// Cuerpo de la card: título + descripción + FactSet.
	body := []map[string]any{
		{
			"type":   "TextBlock",
			"size":   "Medium",
			"weight": "Bolder",
			"text":   "SSH Broker — Approval Required",
			"color":  "Warning",
			"wrap":   true,
		},
		{
			"type": "TextBlock",
			"text": "An AI agent action is waiting for human approval before a certificate is issued.",
			"wrap": true,
		},
		{
			"type":  "FactSet",
			"facts": facts,
		},
	}

	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
	}

	// Añadir botón "View request" solo si hay template configurado.
	if approvalURL := t.renderURL(a.ID); approvalURL != "" {
		card["actions"] = []map[string]any{
			{
				"type":  "Action.OpenUrl",
				"title": "View request",
				"url":   approvalURL,
			},
		}
	}

	return card
}

// ── MessageCard (formato legacy) ─────────────────────────────────────────────

// buildMessageCard construye el payload MessageCard para M365 Connectors legacy.
func (t *TeamsNotifier) buildMessageCard(a Approval) map[string]any {
	facts := t.approvalFacts(a)

	// Convertir []{"name":…,"value":…} a []{"name":…,"value":…} (mismo formato;
	// los facts de MessageCard y FactSet de Adaptive Card comparten estructura).
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "FFA500",
		"summary":    fmt.Sprintf("Approval required: %s on %s", a.Command, a.Host),
		"sections": []map[string]any{
			{
				"activityTitle":    "SSH Broker — Approval Required",
				"activitySubtitle": "An AI agent action is waiting for human approval.",
				"facts":            facts,
				"markdown":         true,
			},
		},
	}

	// Añadir acción "View request" solo si hay template configurado.
	if approvalURL := t.renderURL(a.ID); approvalURL != "" {
		card["potentialAction"] = []map[string]any{
			{
				"@type": "OpenUri",
				"name":  "View request",
				"targets": []map[string]any{
					{"os": "default", "uri": approvalURL},
				},
			},
		}
	}

	return card
}

// ── Helpers compartidos ───────────────────────────────────────────────────────

// approvalFacts construye la lista de facts (pares nombre/valor) comunes a
// Adaptive Card y MessageCard, mostrando solo los campos con valor.
func (t *TeamsNotifier) approvalFacts(a Approval) []map[string]any {
	type kv struct{ k, v string }
	raw := []kv{
		{"Approval ID", a.ID},
		{"Status", string(a.Status)},
		{"Created", a.CreatedAt.UTC().Format(time.RFC3339)},
		{"Host", a.Host},
		{"Command", a.Command},
		{"Caller (broker)", a.Caller},
	}
	if a.EndUser != "" {
		raw = append(raw, kv{"End user", a.EndUser})
	}
	if a.Sudo {
		su := "root"
		if a.SudoUser != "" {
			su = a.SudoUser
		}
		raw = append(raw, kv{"Elevation", "sudo → " + su})
	}
	if a.Rule != "" {
		raw = append(raw, kv{"Policy rule", a.Rule})
	}

	facts := make([]map[string]any, 0, len(raw))
	for _, f := range raw {
		if f.v != "" {
			facts = append(facts, map[string]any{"name": f.k, "value": f.v})
		}
	}
	return facts
}
