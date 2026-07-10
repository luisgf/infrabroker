package signer

import "testing"

// TestMaySelfApproveIgnoresDefault pins #207: self_approve is honoured only on an
// explicit CN, never inherited from the _default entry — otherwise a single
// _default entry would waive four-eyes for every unlisted caller.
func TestMaySelfApproveIgnoresDefault(t *testing.T) {
	t.Parallel()

	// self_approve set only on _default: no unlisted CN, and not the literal
	// "_default" CN, may self-approve.
	onlyDefault := CallerTable{DefaultCallerKey: {SelfApprove: true}}
	if onlyDefault.MaySelfApprove("some-broker") {
		t.Error("an unlisted CN must not inherit self_approve from _default")
	}
	if onlyDefault.MaySelfApprove(DefaultCallerKey) {
		t.Error("the literal _default CN must not self-approve")
	}

	// An explicit CN with self_approve still works; _default does not widen it to
	// other callers.
	mixed := CallerTable{
		"stdio-broker":   {SelfApprove: true},
		DefaultCallerKey: {SelfApprove: true},
	}
	if !mixed.MaySelfApprove("stdio-broker") {
		t.Error("an explicit CN with self_approve must self-approve")
	}
	if mixed.MaySelfApprove("other-broker") {
		t.Error("an unlisted CN must not self-approve even when _default sets self_approve")
	}

	// A listed CN without self_approve does not self-approve.
	listed := CallerTable{"broker": {AllowedGroups: []string{"g"}}}
	if listed.MaySelfApprove("broker") {
		t.Error("a listed CN without self_approve must not self-approve")
	}
}
