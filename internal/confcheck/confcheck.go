// Package confcheck supports a doc/code anti-drift test: it verifies that the
// committed *.example.json files only use keys that exist on their Go config
// structs. The examples use "_*"-prefixed keys for inline comments; those are
// stripped before the structs are decoded with DisallowUnknownFields, so a renamed
// or removed struct field makes the example's now-unknown key fail the test.
package confcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// StripUnderscoreKeys removes every object key beginning with "_" (recursively) —
// the inline "_*_comment" documentation keys — EXCEPT the reserved "_default" key
// (used in ca_keys / group_command_policies), which is real configuration.
func StripUnderscoreKeys(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return json.Marshal(strip(v))
}

func strip(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			// Drop "_*" documentation keys, but keep the reserved "_default" map
			// key (ca_keys / group_command_policies) — it is real configuration,
			// not a comment.
			if k != "_default" && strings.HasPrefix(k, "_") {
				continue
			}
			out[k] = strip(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = strip(t[i])
		}
		return t
	default:
		return v
	}
}

// DecodeStrict decodes b into v rejecting any key that has no matching struct
// field (recursively), so an example key that no longer exists on the struct is
// an error — the signal that the docs/example drifted from the code.
func DecodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Strict loads config bytes into v with comment keys removed and unknown keys
// rejected, so a typo in a security control (sign_callers, allowed_callers,
// callers, …) fails closed at load instead of being silently ignored — which
// would otherwise leave a setting more open than intended. Used by the runtime
// config loaders (startup, reload, and the validated policy-mutation path).
func Strict(raw []byte, v any) error {
	// Pass 1 — load the real configuration leniently. This preserves every map
	// key, including any that legitimately begins with "_" (e.g. a broker CN named
	// "_ci" in callers, or a "_default" group), and ignores the "_*" comment keys
	// at struct positions. This is the value actually used.
	if err := json.Unmarshal(raw, v); err != nil {
		return err
	}
	// Pass 2 — typo detection only. Strip comment keys and reject any UNKNOWN
	// STRUCT FIELD (a misspelled control like "sign_caller") by decoding into a
	// throwaway of the same type. The stripping here never touches the value
	// loaded above, so real "_"-prefixed map data is not lost.
	clean, err := StripUnderscoreKeys(raw)
	if err != nil {
		return err
	}
	rt := reflect.TypeOf(v)
	if rt == nil || rt.Kind() != reflect.Pointer {
		return fmt.Errorf("confcheck.Strict: v must be a non-nil pointer")
	}
	return DecodeStrict(clean, reflect.New(rt.Elem()).Interface())
}
