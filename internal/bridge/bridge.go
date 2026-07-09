// Package bridge turns a chat platform into an approval surface for the control
// plane (#120). It polls the control plane's GET /v1/approvals for pending
// requests, presents each to humans through a PlatformAdapter, and relays their
// Allow/Deny back to POST /v1/approvals/{id} with the bridge's own mTLS approver
// identity. Everything is outbound (poll the control plane, connect out to the
// platform), so nothing with approval authority becomes internet-facing.
//
// The bridge is a convenience, not a new trust root: the control plane still
// enforces consumed-once and the four-eyes guard (a request's originator CN
// cannot decide it). Approver attribution through the bridge is bridge-asserted
// — see docs/THREAT_MODEL.md.
package bridge

import (
	"context"
	"log"
	"time"

	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/redact"
)

// Decision is a human's Allow/Deny for a pending approval, from a platform.
type Decision struct {
	ID      string // approval request id
	Approve bool
	By      string // platform user id, recorded as attribution metadata only
}

// PlatformAdapter presents approval requests on a chat platform and streams the
// humans' decisions. Implementations are outbound-only (e.g. Slack Socket Mode).
type PlatformAdapter interface {
	// Post presents a pending approval to the approvers.
	Post(ctx context.Context, a control.Approval) error
	// Decisions streams decisions as humans act; closed when the adapter stops.
	Decisions() <-chan Decision
	// Name identifies the platform (for logs).
	Name() string
}

// ControlPlane is the slice of the control-plane approval API the bridge needs.
type ControlPlane interface {
	// List returns the currently pending approval requests.
	List(ctx context.Context) ([]control.Approval, error)
	// Decide resolves a request as approved or denied.
	Decide(ctx context.Context, id string, approve bool) error
}

// Bridge relays between a control plane and a platform adapter.
type Bridge struct {
	cp       ControlPlane
	adapter  PlatformAdapter
	interval time.Duration
	posted   map[string]bool  // approval ids already presented (dedupe)
	redactor control.Redactor // masks secrets before the off-host chat sink
}

// New builds a bridge polling every interval (default 5s if <= 0).
func New(cp ControlPlane, adapter PlatformAdapter, interval time.Duration) *Bridge {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Bridge{cp: cp, adapter: adapter, interval: interval, posted: map[string]bool{}, redactor: mustDefaultRedactor()}
}

// mustDefaultRedactor builds the command redactor applied before an approval is
// presented on a chat platform. The bridge is a persistent/outbound sink of the
// same class as the control plane's webhook/Teams notifier (docs/THREAT_MODEL.md
// section 8): GET /v1/approvals serves the ORIGINAL command because the human
// mTLS approval UI is entitled to it, so the masking must happen here at the
// off-host relay, not at that shared endpoint. Built-in defaults only (the
// bridge has no config file) — best-effort, matching the notifier's default
// patterns. redact.New(nil) compiles the vetted Defaults and so never errors.
func mustDefaultRedactor() control.Redactor {
	r, err := redact.New(nil)
	if err != nil {
		panic("bridge: compiling default command redactor: " + err.Error())
	}
	return r
}

// Run polls for pending approvals and relays decisions until ctx is cancelled.
// It is single-goroutine: poll ticks and adapter decisions are handled in the
// same select, so the dedupe map needs no lock.
func (b *Bridge) Run(ctx context.Context) error {
	t := time.NewTicker(b.interval)
	defer t.Stop()
	b.poll(ctx) // present immediately rather than waiting a full interval
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			b.poll(ctx)
		case d, ok := <-b.adapter.Decisions():
			if !ok {
				return nil // adapter stopped
			}
			if err := b.cp.Decide(ctx, d.ID, d.Approve); err != nil {
				log.Printf("approval-bridge: deciding %s: %v", d.ID, err)
				continue
			}
			delete(b.posted, d.ID)
			log.Printf("approval-bridge: %s decided approve=%v (by %s via %s)", d.ID, d.Approve, d.By, b.adapter.Name())
		}
	}
}

// poll presents pending approvals not yet seen and forgets ids that are no
// longer pending (decided or expired elsewhere), keeping the dedupe map bounded.
func (b *Bridge) poll(ctx context.Context) {
	pending, err := b.cp.List(ctx)
	if err != nil {
		log.Printf("approval-bridge: listing approvals: %v", err)
		return
	}
	live := make(map[string]bool, len(pending))
	for _, a := range pending {
		live[a.ID] = true
		if b.posted[a.ID] {
			continue
		}
		// Mask secrets in the command before it leaves the host for the chat
		// platform, matching the control plane's webhook/Teams notifier sink
		// (section 8). The dedupe/relay below key on a.ID, which is untouched.
		if err := b.adapter.Post(ctx, a.WithRedactedCommand(b.redactor)); err != nil {
			log.Printf("approval-bridge: presenting %s: %v", a.ID, err)
			continue // retry on the next tick
		}
		b.posted[a.ID] = true
	}
	for id := range b.posted {
		if !live[id] {
			delete(b.posted, id)
		}
	}
}
