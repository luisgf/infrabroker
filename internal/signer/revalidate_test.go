package signer

import "testing"

// TestMayRequireVerifiedEndUser pins #143: require_verified_end_user is honoured
// only on an explicit CN, never inherited from the _default entry — otherwise a
// single _default entry would silently gate (and, absent an issuer, deny) every
// unlisted caller at once. Mirrors TestMaySelfApproveIgnoresDefault (#207).
func TestMayRequireVerifiedEndUser(t *testing.T) {
	t.Parallel()

	// Flag set only on _default: no unlisted CN, and not the literal "_default"
	// CN, is gated.
	onlyDefault := CallerTable{DefaultCallerKey: {RequireVerifiedEndUser: true}}
	if onlyDefault.MayRequireVerifiedEndUser("some-broker") {
		t.Error("an unlisted CN must not inherit require_verified_end_user from _default")
	}
	if onlyDefault.MayRequireVerifiedEndUser(DefaultCallerKey) {
		t.Error("the literal _default CN must not be gated")
	}

	// An explicit CN with the flag is gated; _default does not widen it.
	mixed := CallerTable{
		"http-broker":    {RequireVerifiedEndUser: true},
		DefaultCallerKey: {RequireVerifiedEndUser: true},
	}
	if !mixed.MayRequireVerifiedEndUser("http-broker") {
		t.Error("an explicit CN with require_verified_end_user must be gated")
	}
	if mixed.MayRequireVerifiedEndUser("other-broker") {
		t.Error("an unlisted CN must not be gated even when _default sets the flag")
	}

	// A listed CN without the flag is not gated.
	listed := CallerTable{"broker": {AllowedGroups: []string{"g"}}}
	if listed.MayRequireVerifiedEndUser("broker") {
		t.Error("a listed CN without require_verified_end_user must not be gated")
	}
}
