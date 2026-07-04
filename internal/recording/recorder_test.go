package recording

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTmp(t *testing.T) (*Recorder, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.cast")
	r, err := Open(path, Meta{
		SessionID: "abc123",
		Caller:    "alice",
		Host:      "web01",
		Serial:    42,
		Width:     220,
		Height:    40,
		StartedAt: time.Date(2026, 6, 9, 14, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r, path
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			lines = append(lines, s)
		}
	}
	return lines
}

func TestHeader(t *testing.T) {
	t.Parallel()
	_, path := openTmp(t)
	lines := readLines(t, path)
	if len(lines) == 0 {
		t.Fatal("no lines in file")
	}

	var h map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatalf("header not valid JSON: %v", err)
	}
	if h["version"].(float64) != 2 {
		t.Errorf("version = %v, want 2", h["version"])
	}
	if h["title"] == "" {
		t.Error("title must not be empty")
	}
	broker, ok := h["infrabroker"].(map[string]any)
	if !ok {
		t.Fatal("infrabroker field missing or wrong type")
	}
	if broker["session_id"] != "abc123" {
		t.Errorf("session_id = %v, want abc123", broker["session_id"])
	}
	if broker["caller"] != "alice" {
		t.Errorf("caller = %v, want alice", broker["caller"])
	}
	if broker["host"] != "web01" {
		t.Errorf("host = %v, want web01", broker["host"])
	}
}

func TestEventTypes(t *testing.T) {
	t.Parallel()
	r, path := openTmp(t)

	_ = r.WriteInput("uptime\n")
	_ = r.WriteOutput(" 14:00:01 up 3 days\r\n")
	_ = r.WriteStderr("warning: something\n")
	r.Close()

	lines := readLines(t, path)
	// lines[0] = header; lines[1..3] = events
	if len(lines) < 4 {
		t.Fatalf("expected 4 lines (header + 3 events), got %d", len(lines))
	}

	wantTypes := []string{"i", "o", "e"}
	for i, wantType := range wantTypes {
		var event []any
		if err := json.Unmarshal([]byte(lines[i+1]), &event); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i+1, err)
		}
		if len(event) != 3 {
			t.Fatalf("line %d: want 3 elements, got %d", i+1, len(event))
		}
		if event[1].(string) != wantType {
			t.Errorf("line %d: type = %q, want %q", i+1, event[1], wantType)
		}
	}
}

func TestDeltasIncreasing(t *testing.T) {
	t.Parallel()
	r, path := openTmp(t)

	for i := 0; i < 5; i++ {
		_ = r.WriteOutput("x\n")
		time.Sleep(2 * time.Millisecond)
	}
	r.Close()

	lines := readLines(t, path)
	var prevDelta float64
	for _, line := range lines[1:] {
		var event []any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		delta := event[0].(float64)
		if delta < prevDelta {
			t.Errorf("delta went backwards: %v < %v", delta, prevDelta)
		}
		prevDelta = delta
	}
}

func TestConcurrentWrites(t *testing.T) {
	t.Parallel()
	r, _ := openTmp(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.WriteOutput("line\n")
		}()
	}
	wg.Wait()
	// Must not panic or deadlock; file is closed by cleanup.
}

func TestEmptyDataSkipped(t *testing.T) {
	t.Parallel()
	r, path := openTmp(t)
	_ = r.WriteOutput("")
	_ = r.WriteInput("")
	r.Close()

	lines := readLines(t, path)
	// Only header; empty writes must not produce event lines.
	if len(lines) != 1 {
		t.Errorf("expected 1 line (header only), got %d", len(lines))
	}
}

func TestCloseIdempotent(t *testing.T) {
	t.Parallel()
	r, _ := openTmp(t)
	if err := r.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close should be a no-op: %v", err)
	}
}

func TestWriteAfterClose(t *testing.T) {
	t.Parallel()
	r, _ := openTmp(t)
	r.Close()
	// Must not error or panic after close.
	if err := r.WriteOutput("after close\n"); err != nil {
		t.Errorf("WriteOutput after Close must be a no-op, got: %v", err)
	}
}

func TestSizeCap(t *testing.T) {
	t.Parallel()
	r, path := openTmp(t)

	// Shrink the cap so a couple of writes exceed it.
	r.mu.Lock()
	capBytes := r.written + 50
	r.maxBytes = capBytes
	r.mu.Unlock()

	for i := 0; i < 100; i++ {
		_ = r.WriteOutput("0123456789\n")
	}
	r.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file must stay bounded near the cap, not grow to 100 events.
	if info.Size() > capBytes+200 {
		t.Errorf("recording grew to %d bytes, cap was %d", info.Size(), capBytes)
	}

	lines := readLines(t, path)
	last := lines[len(lines)-1]
	if !strings.Contains(last, "recording truncated") {
		t.Errorf("expected a truncation note as the final line, got %q", last)
	}
}

func TestDefaultDimensions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "defaults.cast")
	r, err := Open(path, Meta{SessionID: "x", Caller: "bot", Host: "h"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	r.Close()

	lines := readLines(t, path)
	var h map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatalf("header JSON: %v", err)
	}
	if h["width"].(float64) != 220 {
		t.Errorf("default width = %v, want 220", h["width"])
	}
	if h["height"].(float64) != 40 {
		t.Errorf("default height = %v, want 40", h["height"])
	}
}
