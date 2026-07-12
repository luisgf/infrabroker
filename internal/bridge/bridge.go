// Package bridge turns a chat platform into an approval surface for the control
// plane (#120). It polls the control plane's GET /v1/approvals for pending
// requests, presents each to humans through a PlatformAdapter, and relays their
// Allow/Deny back to POST /v1/approvals/{id} with the bridge's own mTLS approver
// identity. Everything is outbound (poll the control plane, connect out to the
// platform), so nothing with approval authority becomes internet-facing.
//
// The bridge is a convenience, not a new trust root: the control plane still
// enforces consumed-once. Its four-eyes guard compares the request's originator
// against the *bridge's* approver CN, which never collides — so the platform
// clicker who both originated and approves would slip through. When an identity
// map is configured (--identity-map), the bridge closes that gap by enforcing
// four-eyes itself: it refuses an approval whose clicker maps to the request's
// originating end user (#214). Approver attribution through the bridge is
// bridge-asserted — see docs/THREAT_MODEL.md.
package bridge

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/redact"
)

// Decision is a human's Allow/Deny for a pending approval, from a platform.
type Decision struct {
	ID      string // approval request id
	Approve bool
	By      string // platform user id: attribution, and the self-approval guard input (#214)
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
	posted   map[string]bool   // approval ids already presented (dedupe)
	origins  map[string]string // approval id → originating end-user, for the four-eyes check on decide
	identity map[string]string // platform user id → end-user identity (self-approval guard); nil/empty disables it
	redactor control.Redactor  // masks secrets before the off-host chat sink
}

// New builds a bridge polling every interval (default 5s if <= 0). identityMap
// maps a platform user id (e.g. a Slack user id) to the end-user identity it
// belongs to; when set, the bridge enforces four-eyes for the platform path by
// refusing an approval whose clicker maps to the request's originating end user
// (#214). A nil/empty map leaves that guard off (the documented residual).
func New(cp ControlPlane, adapter PlatformAdapter, interval time.Duration, identityMap map[string]string) *Bridge {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Bridge{
		cp: cp, adapter: adapter, interval: interval,
		posted:   map[string]bool{},
		origins:  map[string]string{},
		identity: identityMap,
		redactor: mustDefaultRedactor(),
	}
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
			// Four-eyes for the platform path: the control plane sees only the
			// bridge's approver CN, so its self-approval guard cannot catch a human
			// who both originated the request and clicks Approve here. Enforce it at
			// the bridge, where the clicker's platform id is known (#214). Scoped to
			// approvals — a self-deny grants nothing.
			if d.Approve && b.isSelfApproval(d) {
				log.Printf("approval-bridge: refusing self-approval of %s by %s (maps to the request's originator); another approver must decide it", d.ID, d.By)
				continue
			}
			if err := b.cp.Decide(ctx, d.ID, d.Approve); err != nil {
				log.Printf("approval-bridge: deciding %s: %v", d.ID, err)
				continue
			}
			delete(b.posted, d.ID)
			delete(b.origins, d.ID)
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
		// Remember the originating end user so a later decision can be four-eyes
		// checked against it (#214), even for an already-posted request.
		b.origins[a.ID] = a.EndUser
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
	for id := range b.origins {
		if !live[id] {
			delete(b.origins, id)
		}
	}
}

// isSelfApproval reports whether decision d is the request's originator approving
// their own request through the platform. It maps the clicker's platform id to an
// end-user identity and compares it (case-insensitively) to the request's
// originating end user. It fails OPEN — returns false — whenever the guard cannot
// attribute the clicker: no identity map configured, the clicker is unmapped, or
// the request carries no end-user identity. Enabling the guard is the operator's
// choice (cmd/approval-bridge --identity-map); without it the bridge behaves as
// before (docs/THREAT_MODEL.md).
func (b *Bridge) isSelfApproval(d Decision) bool {
	if len(b.identity) == 0 {
		return false
	}
	clicker := b.identity[d.By]
	origin := b.origins[d.ID]
	if clicker == "" || origin == "" {
		return false
	}
	return strings.EqualFold(clicker, origin)
}
