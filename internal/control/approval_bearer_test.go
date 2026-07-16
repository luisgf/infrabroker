package control

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/signer"
)

// TestRegistryStripsBearerTokenFromPersistedRequest pins #143: the end-user
// bearer forwarded for signer-side re-validation is a secret and must never be
// written to request_json in state_db. It is retained in memory (so a
// same-process post-approval forward can re-validate it) but stripped before
// persistence, so a restart rehydrates it empty and a gated caller's
// post-approval issuance then fails closed rather than being re-forwarded with
// an un-re-validatable token.
func TestRegistryStripsBearerTokenFromPersistedRequest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	db := openRegistryDB(t, path)
	r1, err := NewRegistryDB(time.Minute, db)
	if err != nil {
		t.Fatalf("NewRegistryDB: %v", err)
	}

	const secret = "eyJ.header.payload.SECRET-BEARER-SIGNATURE"
	req := testWireReq("reboot")
	req.BearerToken = secret
	a, err := r1.Create(req, "broker-1", &signer.DecisionInfo{RequireApproval: true, MatchedRule: "^reboot"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// In memory the token is retained for a same-process post-approval forward.
	if got, ok := r1.Request(a.ID); !ok || got.BearerToken != secret {
		t.Fatalf("in-memory WireRequest must retain the bearer token, got %q", got.BearerToken)
	}

	// On disk the token must be absent: request_json is public-material-only.
	var reqJSON string
	if err := db.QueryRow("SELECT request_json FROM approvals WHERE id = ?", a.ID).Scan(&reqJSON); err != nil {
		t.Fatalf("select request_json: %v", err)
	}
	if strings.Contains(reqJSON, "bearer_token") || strings.Contains(reqJSON, secret) {
		t.Fatalf("bearer token was persisted to state_db (must be stripped): %s", reqJSON)
	}

	// After a restart the token is gone (fail-closed): a gated caller's
	// post-approval issuance is denied re-validation rather than trusting a
	// tokenless re-forward.
	r2, err := NewRegistryDB(time.Minute, openRegistryDB(t, path))
	if err != nil {
		t.Fatalf("NewRegistryDB after restart: %v", err)
	}
	restored, ok := r2.Request(a.ID)
	if !ok {
		t.Fatal("approval must survive the restart")
	}
	if restored.BearerToken != "" {
		t.Errorf("a restart must not rehydrate the bearer token, got %q", restored.BearerToken)
	}
}
