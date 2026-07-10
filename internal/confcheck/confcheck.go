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

	"github.com/tailscale/hujson"
)

// Standardize converts JSONC/JWCC (// and /* */ comments, plus trailing commas)
// into plain JSON by replacing comments with whitespace and dropping trailing
// commas; plain JSON passes through unchanged (idempotent). Every config loader
// applies it, so config files may carry real // comments. It does NOT touch
// object keys, so the legacy "_*" comment-key convention — and the reserved
// "_default" data key — keep working exactly as before.
//
// It also rejects duplicate object keys fail-closed: encoding/json (the loaders)
// keeps the LAST value for a repeated key while hujson (the comment-preserving
// Patch) resolves a JSON pointer to the FIRST, so a duplicated key would make the
// value the runtime enforces diverge from the one a policy rewrite edits. A
// security config must not depend on which parser wins, so a duplicate key is an
// error here — before any load or rewrite — rather than a silent last-wins.
func Standardize(raw []byte) ([]byte, error) {
	// hujson.Standardize edits its input in place (comment bytes → whitespace), so
	// copy first — callers must be able to keep the original bytes (e.g. to then
	// apply a format-preserving Patch to them).
	b, err := hujson.Standardize(append([]byte(nil), raw...))
	if err != nil {
		return nil, fmt.Errorf("parsing JSONC: %w", err)
	}
	if err := rejectDuplicateKeys(b); err != nil {
		return nil, err
	}
	return b, nil
}

// rejectDuplicateKeys errors if any JSON object in b (already standard JSON, so
// comments are gone) has two members with the same name, walking the whole
// document.
func rejectDuplicateKeys(b []byte) error {
	return checkDupKeys(json.NewDecoder(bytes.NewReader(b)))
}

// checkDupKeys consumes exactly one JSON value from dec, recursing into objects
// and arrays, and returns an error on the first object carrying a repeated key.
func checkDupKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar value: nothing to check
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key := keyTok.(string) // an object member name is always a string
			if seen[key] {
				return fmt.Errorf("duplicate key %q in config object", key)
			}
			seen[key] = true
			if err := checkDupKeys(dec); err != nil { // the member's value
				return err
			}
		}
		_, err = dec.Token() // consume the closing '}'
		return err
	case '[':
		for dec.More() {
			if err := checkDupKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // consume the closing ']'
		return err
	}
	return nil
}

// Patch applies an RFC 6902 JSON Patch to raw JSONC bytes, PRESERVING the file's
// comments, formatting, and key order (via hujson), and returns the new bytes.
// It is the format-preserving counterpart to a parse→marshal round trip: the
// config-rewrite paths (signer policy mutation, broker-ctl edits) use it so an
// operator's // comments survive an edit. A patch that does not apply (e.g. a
// path whose parent is absent) is an error and nothing is written.
func Patch(raw, patch []byte) ([]byte, error) {
	// Refuse to edit a config with a duplicate key: hujson resolves a JSON pointer
	// to the FIRST matching member, so a patch would target a different occurrence
	// than the encoding/json loaders enforce (last-wins). Standardize runs the
	// duplicate-key check; the bytes it returns are discarded (Patch edits raw so
	// comments survive).
	if _, err := Standardize(raw); err != nil {
		return nil, err
	}
	v, err := hujson.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing JSONC: %w", err)
	}
	if err := v.Patch(patch); err != nil {
		return nil, fmt.Errorf("applying config patch: %w", err)
	}
	v.Format() // re-indent only the patched-in values; existing lines are untouched
	return v.Pack(), nil
}

// HasComments reports whether raw carries JSONC features (// or /* */ comments,
// or trailing commas) that a parse→marshal round trip would lose. Rewrite paths
// use it to decide between a format-preserving edit and the plain path.
func HasComments(raw []byte) bool {
	v, err := hujson.Parse(raw)
	if err != nil {
		return false
	}
	return !v.IsStandard()
}

// Unmarshal standardizes JSONC then json.Unmarshals raw into v WITHOUT the
// strict unknown-key check. It is for the raw config readers — partial structs
// and map[string]json.RawMessage decoders that must tolerate the rest of a real
// config — so a config carrying // comments or trailing commas loads for them
// too. Use Strict for the authoritative typed load with typo detection.
func Unmarshal(raw []byte, v any) error {
	std, err := Standardize(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(std, v)
}

// StripUnderscoreKeys removes the inline documentation keys recursively (see
// isCommentKey for what counts as a comment). It deliberately keeps "_"-prefixed
// keys that carry real configuration — the reserved "_default" group, or an
// object/array entry whose identifier happens to start with "_" (e.g. a host or
// broker CN) — so they are loaded AND reach the strict validation pass; removing
// them would lose data and hide a typo nested inside such an entry.
func StripUnderscoreKeys(raw []byte) ([]byte, error) {
	raw, err := Standardize(raw)
	if err != nil {
		return nil, err
	}
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
	// JSONC → plain JSON first, so both passes accept // comments and trailing
	// commas. Malformed JSONC fails closed here (same posture as a malformed
	// config today).
	raw, err := Standardize(raw)
	if err != nil {
		return err
	}
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
