package audit

import (
	"reflect"
	"testing"
	"time"
	"unicode/utf8"
)

// TestSanitizeEntryCoversEveryStringField fails when a field is added to Entry
// that sanitizeEntry does not handle: every string field is filled with invalid
// UTF-8 and must come out valid; any other non-trivial kind must be consciously
// handled in sanitizeEntry and listed here.
func TestSanitizeEntryCoversEveryStringField(t *testing.T) {
	t.Parallel()
	var e Entry
	v := reflect.ValueOf(&e).Elem()
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		switch f.Type.Kind() {
		case reflect.String:
			v.Field(i).SetString("a\xffb\xc3")
		case reflect.Bool, reflect.Uint64, reflect.Int:
		case reflect.Struct:
			if f.Type != reflect.TypeOf(time.Time{}) {
				t.Fatalf("field %s: struct type %s may hide strings; handle it in sanitizeEntry and here", f.Name, f.Type)
			}
		default:
			t.Fatalf("field %s has kind %s: handle it in sanitizeEntry and here", f.Name, f.Type.Kind())
		}
	}
	sanitizeEntry(&e)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() != reflect.String {
			continue
		}
		s := v.Field(i).String()
		if !utf8.ValidString(s) || s != "a�b�" {
			t.Errorf("field %s not normalised: %q", typ.Field(i).Name, s)
		}
	}
}
