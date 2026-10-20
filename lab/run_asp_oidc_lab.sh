#!/usr/bin/env bash
# Lab: infrabroker's HTTP frontend with an ASP sandbox workload token (docs/SANDBOX.md).
#
# An Agent Sandbox Platform (ASP) control plane mints, for each microVM, a short
# OIDC token whose `sub` is the sandbox (sandbox/<id>) and whose `user_sub` is
# the human who owns it, plus `groups` (the owner's IdP groups as they were when
# the sandbox was created; absent on an ownerless sandbox), `sandbox_id` and
# `tenant_id`; the guest chooses only `aud`. This lab runs that shape of token
# against the REAL serve-mcp-http frontend (newMux) with a toy issuer (discovery
# + JWKS in-process), and shows:
#
#   1. user_claim=user_sub → the audit `caller` is the human owner, not the sandbox.
#   2. groups_claim=groups → the owner's groups drive the signer's per-user RBAC:
#      a host is reached only if its `groups` intersect the owner's; a token
#      without `groups` (an ownerless sandbox) is rejected, fail-closed.
#   3. context_claim=sandbox_id → the sandbox lands in the audit as end_user_context
#      (and as ctx= in the certificate KeyID when a cert is issued).
#   4. A token without sandbox_id is still accepted (attribution, not authorisation);
#      a token without user_sub is rejected (no usable identity).
#
# Needs only Go: no ASP, no KVM, no Docker. The check itself is the Go test
# TestASPWorkloadToken (internal/brokermain), so it also runs in CI; this script
# is the readable entry point and prints the config block to copy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== 1. ASP-shaped token against serve-mcp-http (toy issuer, real frontend) =="
go test ./internal/brokermain -run 'TestASPWorkloadToken' -v -count=1 2>&1 | grep -E '^(=== RUN|--- (PASS|FAIL)|PASS|FAIL|ok|\s+mcphttp_test)' || {
  echo "FAIL: TestASPWorkloadToken did not pass"; exit 1
}

echo "== 2. the context claim end to end in the signer (gated caller) =="
go test ./cmd/signer -run 'TestRederiveEndUser/gated_re-derives_the_context_from_the_token' -v -count=1 2>&1 | grep -E '^(=== RUN|--- (PASS|FAIL)|PASS|FAIL|ok)' || {
  echo "FAIL: the signer did not re-derive the context from the verified token"; exit 1
}

cat <<'EOF'

== 3. config to copy (frontend "oauth" block; mirror it as "end_user_oidc" in signer.json) ==

  "oauth": {
    "issuer":                "https://asp.example.internal",   // ASP_OIDC_ISSUER of the ASP control plane
    "audience":              "infrabroker",                    // the aud the guest requests
    "user_claim":            "user_sub",                       // the human owner of the sandbox
    "groups_claim":          "groups",                         // the owner's IdP groups → per-user RBAC
    "context_claim":         "sandbox_id",                     // → KeyID ctx=, audit end_user_context
    "max_token_age_seconds": 300                               // ASP tokens live <= 5 min
  }

  signer.json: "callers": { "<broker CN>": { "allowed_groups": [...], "require_verified_end_user": true } }
               and on each host the IdP groups whose sandboxes may reach it: "groups": ["sre"]

Remember (docs/SANDBOX.md § Honest limits): the groups are a snapshot taken when
the sandbox was created — revoking is destroying the sandbox; an ownerless sandbox
carries no groups and is rejected (401); a control plane older than ASP's ADR-0020
mints no groups, so with groups_claim set every token from it is rejected (unset
it there, and per-user RBAC is off: the token is attribution, not scope). And the
broker must run on a host other than the ASP node.
EOF
