package main

import "testing"

// TestCanonicalSerial: `broker-ctl freeze --serial` sends the canonical decimal
// spelling, so a zero-padded serial freezes the certificate it names (#647).
// The reject path exits via fatalf and is covered by the signer's 400 test.
func TestCanonicalSerial(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"7": "7", "007": "7", "0012345": "12345", "0": "0", "18446744073709551615": "18446744073709551615"} {
		if got := canonicalSerial(in); got != want {
			t.Errorf("canonicalSerial(%q) = %q, want %q", in, got, want)
		}
	}
}
