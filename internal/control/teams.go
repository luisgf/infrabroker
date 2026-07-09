// Package control — TeamsNotifier sends a pending-approval notification to a
// Microsoft Teams channel via an Incoming Webhook or a Power Automate Workflow,
// formatting the payload as an Adaptive Card (format "workflow" / "adaptivecard",
// recommended and forward-compatible) or as a legacy MessageCard (format
// "messagecard", for tenants still using classic M365 Connectors).
//
// Security: the payload contains only public fields of the Approval struct. The
// private req field (which holds the ephemeral public key) is never serialised.
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

// Formats supported by TeamsNotifier.
const (
	// TeamsFormatWorkflow is the Adaptive Card wrapped in the message envelope
	// required by Power Automate Workflows / modern Incoming Webhooks.
	// This is the Microsoft-recommended format and the default.
	TeamsFormatWorkflow = "workflow"

	// TeamsFormatAdaptiveCard is an alias for TeamsFormatWorkflow.
	TeamsFormatAdaptiveCard = "adaptivecard"

	// TeamsFormatMessageCard uses the legacy MessageCard format for M365
	// Connectors. Microsoft is retiring this mechanism; use it only when your
	// tenant does not yet support the Workflow format.
	TeamsFormatMessageCard = "messagecard"
)

// TeamsNotifier implements Notifier by sending the approval notification to a
// Microsoft Teams channel via a webhook.
type TeamsNotifier struct {
	url                 string
	format              string // TeamsFormatWorkflow | TeamsFormatMessageCard
	approvalURLTemplate string // optional; "{id}" is replaced with the request ID
	client              *http.Client
}

// NewTeamsNotifier creates a Teams notifier.
//
//   - url: Incoming Webhook URL (Power Automate Workflow or M365 Connector).
//   - format: "workflow" / "adaptivecard" (recommended) or "messagecard" (legacy).
//     Empty string → "workflow".
//   - approvalURLTemplate: optional URL embedded in the card as a "View request"
//     link. Use "{id}" as a placeholder for the approval ID (e.g.
//     "https://approvals.example.com/requests/{id}"). Empty = no link.
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

// Notify implements Notifier. Builds the payload according to the configured
// format and sends it via HTTP POST to the Teams webhook.
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
		return fmt.Errorf("teams notifier: serialising payload: %w", err)
	}
	resp, err := t.client.Post(t.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("teams notifier: POST: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams notifier: webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// renderURL substitutes "{id}" in the template with the request ID.
// Returns an empty string when the template is empty.
func (t *TeamsNotifier) renderURL(id string) string {
	if t.approvalURLTemplate == "" {
		return ""
	}
	return strings.ReplaceAll(t.approvalURLTemplate, "{id}", id)
}

// ── Adaptive Card (workflow format) ──────────────────────────────────────────

// buildWorkflowEnvelope constructs the message envelope required by the Power
// Automate "When a Teams webhook request is received" trigger, wrapping an
// Adaptive Card v1.4.
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

// teamsMarkdownEscaper backslash-escapes the characters Teams honours as
// Markdown in Adaptive Card Fact values, so broker-supplied text (command, host,
// identities) renders literally instead of as a clickable link or formatting —
// the same protection the MessageCard path gets from markdown:false (#43). It
// runs in a single pass, so the backslashes it inserts are not re-escaped.
var teamsMarkdownEscaper = strings.NewReplacer(
	"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_",
	"[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)",
	"#", "\\#", "~", "\\~", ">", "\\>", "|", "\\|",
)

// buildAdaptiveCard constructs the Adaptive Card v1.4 object.
func (t *TeamsNotifier) buildAdaptiveCard(a Approval) map[string]any {
	facts := t.approvalFacts(a)
	// Teams renders Adaptive Card Fact.value as Markdown (unlike the MessageCard
	// path, which pins markdown:false). Escape the broker-supplied values so a
	// crafted command/host cannot inject a clickable link or hidden formatting
	// into the approver's notification (phishing / command obscuring, #43). The
	// facts slice is freshly built per call, so this does not affect MessageCard.
	for _, f := range facts {
		if v, ok := f["value"].(string); ok {
			f["value"] = teamsMarkdownEscaper.Replace(v)
		}
	}

	// Card body: title + description + FactSet.
	body := []map[string]any{
		{
			"type":   "TextBlock",
			"size":   "Medium",
			"weight": "Bolder",
			"text":   "infrabroker — Approval Required",
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

	// Add "View request" button only when a template is configured.
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

// ── MessageCard (legacy format) ───────────────────────────────────────────────

// buildMessageCard constructs the MessageCard payload for legacy M365 Connectors.
func (t *TeamsNotifier) buildMessageCard(a Approval) map[string]any {
	facts := t.approvalFacts(a)

	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "FFA500",
		"summary":    fmt.Sprintf("Approval required: %s on %s", a.Command, a.Host),
		"sections": []map[string]any{
			{
				"activityTitle":    "infrabroker — Approval Required",
				"activitySubtitle": "An AI agent action is waiting for human approval.",
				"facts":            facts,
				// markdown must stay false: the fact values include the broker-
				// supplied command and host, and a markdown-enabled MessageCard
				// would let a crafted command inject a clickable link/formatting
				// into the approver's notification (phishing / command obscuring).
				"markdown": false,
			},
		},
	}

	// Add "View request" action only when a template is configured.
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

// ── Shared helpers ────────────────────────────────────────────────────────────

// approvalFacts builds the list of facts (name/value pairs) shared by Adaptive
// Card and MessageCard, including only non-empty fields.
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
