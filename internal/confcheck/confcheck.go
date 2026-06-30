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

// StripUnderscoreKeys removes the inline documentation keys recursively (see
// isCommentKey for what counts as a comment). It deliberately keeps "_"-prefixed
// keys that carry real configuration — the reserved "_default" group, or an
// object/array entry whose identifier happens to start with "_" (e.g. a host or
// broker CN) — so they are loaded AND reach the strict validation pass; removing
// them would lose data and hide a typo nested inside such an entry.
func StripUnderscoreKeys(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return json.Marshal(strip(v))
}

// isCommentKey reports whether (k, val) is an inline documentation entry rather
// than real configuration. A comment is:
//   - a key following the "_*_comment" / "_*_example" convention (any value), or
//   - any other "_"-prefixed key with a SCALAR value — an ad-hoc note such as
//     {"_note": "keep me verbatim"} placed inside an object.
//
// A "_"-prefixed key whose value is an object or array is treated as real data
// (e.g. a host or caller whose identifier starts with "_"): it is kept so the
// strict pass validates its nested fields. The reserved "_default" key is always
// data.
func isCommentKey(k string, val any) bool {
	if !strings.HasPrefix(k, "_") || k == "_default" {
		return false
	}
	if strings.HasSuffix(k, "_comment") || strings.HasSuffix(k, "_example") {
		return true
	}
	switch val.(type) {
	case map[string]any, []any:
		return false // real data: a "_"-prefixed object/array entry
	default:
		return true // scalar value: an inline note/comment
	}
}

func strip(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isCommentKey(k, val) {
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
