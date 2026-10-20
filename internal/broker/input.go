package broker

import (
	"fmt"
	"strings"
)

// MaxInputLen is the maximum size of any frontend text input field.
// L4: prevents malformed inputs from reaching the engine without a prior filter.
const MaxInputLen = 64 * 1024 // 64 KiB

// IdentifierLimits caps the fields that name things (a host, an account, a
// cluster, a Kubernetes object) far below MaxInputLen: none of them is ever
// that long, and several land in metadata fields of the signed audit record on
// denial paths (#572) — a 64 KiB "server" name is only ever an attack. Paths
// get the usual filesystem bound; free text (command, manifest) keeps
// MaxInputLen.
var IdentifierLimits = map[string]int{
	"server": 1024, "sudo_user": 1024, "session_id": 1024, "mode": 64,
	"cluster": 1024, "resource": 1024, "group": 1024, "namespace": 1024,
	"name": 1024, "container": 1024,
	"path": 4096,
}

// ValidateInput checks that all fields do not exceed the length limit and do
// not contain null bytes (which could cause unexpected behaviour in the shell
// or in logs). Every frontend (MCP stdio/HTTP and the mTLS HTTP /v1/ssh_run)
// runs it before handing input to the engine, so input hygiene is the same
// whichever frontend a request arrives on (#648).
func ValidateInput(fields map[string]string) error {
	for name, val := range fields {
		limit := MaxInputLen
		if l, ok := IdentifierLimits[name]; ok {
			limit = l
		}
		if len(val) > limit {
			return fmt.Errorf("field %q exceeds the limit of %d bytes", name, limit)
		}
		if strings.ContainsRune(val, 0) {
			return fmt.Errorf("field %q contains null bytes", name)
		}
	}
	return nil
}
