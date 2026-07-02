// Minimal server-rendered approval UI on the control plane's mTLS listener.
// GET /ui/approvals lists the requests (pending first, auto-refresh) and
// GET /ui/approvals/{id} shows one with Approve / Deny actions. Decisions are
// same-origin fetch POSTs to the existing /v1/approvals/{id} API, so the
// audit trail, broker/approver role separation, and the four-eyes
// self-approval guard are inherited unchanged. Auth is the browser's mTLS
// client certificate: the CN must be in approval.callers, exactly like the
// API. approval_url_template can point notification links here, e.g.
// https://cp.example:7443/ui/approvals/{id}.

package main

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
	"sort"

	"github.com/luisgf/ssh-broker/internal/control"
)

// uiPage is the shared shell: deliberately dependency-free (inline CSS, no
// external assets), so the mTLS listener serves everything.
const uiPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ssh-broker — approvals</title>
{{if .Refresh}}<meta http-equiv="refresh" content="10">{{end}}
<style>
 body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; color: #1a1a1a; }
 h1 { font-size: 1.3rem; }
 table { border-collapse: collapse; width: 100%; }
 th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #ddd; font-size: .9rem; }
 code { background: #f4f4f4; padding: .1rem .3rem; border-radius: 3px; }
 .status-pending  { color: #b45309; font-weight: 600; }
 .status-approved { color: #15803d; }
 .status-denied   { color: #b91c1c; }
 .status-expired  { color: #6b7280; }
 .actions { margin-top: 1.5rem; display: flex; gap: .8rem; align-items: center; flex-wrap: wrap; }
 button { padding: .5rem 1.2rem; border: 0; border-radius: 4px; font-size: 1rem; cursor: pointer; }
 .approve { background: #15803d; color: #fff; }
 .deny    { background: #b91c1c; color: #fff; }
 .learn   { font-size: .9rem; color: #444; }
 #result  { margin-top: 1rem; font-weight: 600; }
 dl { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; }
 dt { color: #6b7280; }
 a { color: #1d4ed8; }
</style>
</head>
<body>
{{.Body}}
</body>
</html>`

const uiListBody = `<h1>Approval requests</h1>
{{if not .Approvals}}<p>No approval requests in memory.</p>{{end}}
{{if .Approvals}}<table>
<tr><th>Status</th><th>Created</th><th>Caller</th><th>End user</th><th>Host</th><th>Command</th><th></th></tr>
{{range .Approvals}}<tr>
 <td class="status-{{.Status}}">{{.Status}}</td>
 <td>{{.CreatedAt.Format "2006-01-02 15:04:05"}}</td>
 <td>{{.Caller}}</td>
 <td>{{.EndUser}}</td>
 <td>{{.Host}}</td>
 <td><code>{{.Command}}</code>{{if .Sudo}} <em>(sudo{{if .SudoUser}}:{{.SudoUser}}{{end}})</em>{{end}}</td>
 <td><a href="/ui/approvals/{{.ID}}">view</a></td>
</tr>{{end}}
</table>{{end}}
<p><small>This page refreshes every 10 seconds.</small></p>`

const uiDetailBody = `<h1>Approval {{.A.ID}}</h1>
<dl>
 <dt>Status</dt><dd class="status-{{.A.Status}}">{{.A.Status}}{{if .A.DecidedBy}} by {{.A.DecidedBy}} at {{.A.DecidedAt.Format "2006-01-02 15:04:05"}}{{end}}</dd>
 <dt>Created</dt><dd>{{.A.CreatedAt.Format "2006-01-02 15:04:05"}}</dd>
 <dt>Caller</dt><dd>{{.A.Caller}}</dd>
 {{if .A.EndUser}}<dt>End user</dt><dd>{{.A.EndUser}}</dd>{{end}}
 <dt>Host</dt><dd>{{.A.Host}}</dd>
 <dt>Command</dt><dd><code>{{.A.Command}}</code></dd>
 {{if .A.Sudo}}<dt>Elevation</dt><dd>sudo{{if .A.SudoUser}} → {{.A.SudoUser}}{{else}} → root{{end}}</dd>{{end}}
 {{if .A.Rule}}<dt>Matched rule</dt><dd><code>{{.A.Rule}}</code></dd>{{end}}
</dl>
{{if .Pending}}
<div class="actions">
 <button class="approve" onclick="decide(true)">Approve</button>
 <button class="deny" onclick="decide(false)">Deny</button>
 <label class="learn"><input type="checkbox" id="learn"> approve-and-learn, waive re-approval for
  <input type="number" id="ttl" value="3600" min="1" style="width:6rem"> seconds</label>
</div>
<p id="result"></p>
<script>
async function decide(approve) {
  const body = { approve: approve };
  if (approve && document.getElementById("learn").checked) {
    body.learn = true;
    body.ttl_seconds = parseInt(document.getElementById("ttl").value, 10) || 0;
  }
  const res = await fetch("/v1/approvals/{{.A.ID}}", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const el = document.getElementById("result");
  if (res.ok) {
    el.textContent = approve ? "Approved." : "Denied.";
    setTimeout(() => location.reload(), 800);
  } else {
    el.textContent = "Error " + res.status + ": " + await res.text();
  }
}
</script>
{{end}}
<p><a href="/ui/approvals">← all requests</a></p>`

var (
	uiListTmpl   = template.Must(template.Must(template.New("page").Parse(uiPage)).New("body").Parse(uiListBody))
	uiDetailTmpl = template.Must(template.Must(template.New("page").Parse(uiPage)).New("body").Parse(uiDetailBody))
)

// renderUI executes the body template and wraps it in the page shell. The body
// is rendered by html/template with contextual auto-escaping and only then
// marked template.HTML for the shell, so user-controlled fields (command,
// caller, end_user) are escaped exactly once.
func renderUI(w http.ResponseWriter, tmpl *template.Template, refresh bool, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "body", data); err != nil {
		log.Printf("ui: rendering body: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "page", struct {
		Refresh bool
		Body    template.HTML
	}{refresh, template.HTML(buf.String())}); err != nil {
		log.Printf("ui: rendering page: %v", err)
	}
}

// handleUIList renders the approval list, pending first, then newest first.
func (s *server) handleUIList(w http.ResponseWriter, r *http.Request) {
	if !s.isApprover(w, r) {
		return
	}
	approvals := s.registry.List()
	sort.Slice(approvals, func(i, j int) bool {
		pi, pj := approvals[i].Status == control.StatusPending, approvals[j].Status == control.StatusPending
		if pi != pj {
			return pi
		}
		return approvals[i].CreatedAt.After(approvals[j].CreatedAt)
	})
	renderUI(w, uiListTmpl, true, struct{ Approvals []control.Approval }{approvals})
}

// handleUIDetail renders one approval with the decision actions when pending.
func (s *server) handleUIDetail(w http.ResponseWriter, r *http.Request) {
	if !s.isApprover(w, r) {
		return
	}
	a, ok := s.registry.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "approval not found", http.StatusNotFound)
		return
	}
	// No auto-refresh on the detail page: it would wipe the learn checkbox
	// state while the human is deciding. The decision script reloads on success.
	renderUI(w, uiDetailTmpl, false, struct {
		A       control.Approval
		Pending bool
	}{a, a.Status == control.StatusPending})
}
