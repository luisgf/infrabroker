package audit

// This file is the verification counterpart to Append: the same package that
// produces chained, signed entries also verifies them, so canonicalization
// order, the prev_hash chain, cross-segment linkage after rotation, and
// trailing-corruption detection are defined exactly once. A change to Append
// that would break verification must fail a test in this package, not surface
// later in broker-ctl on an operator's machine. cmd/broker-ctl is a thin
// consumer of the functions below.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Verify checks sequence monotonicity, the prev_hash chain and, when pub is
// non-nil, the Ed25519 signature of every entry read from r. The first line's
// prev_hash is treated as the chain seed: after log rotation the first entry of
// a file carries the hash of the last entry of the previous file, so any seed
// value is accepted and continuity is verified from there. Each problem is
// reported through reportf; returns (entries read, errors).
func Verify(r io.Reader, pub ed25519.PublicKey, reportf func(format string, args ...any)) (total, errs int) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, readerBufferSize), readerBufferSize)

	var prevHash string
	var prevSeq uint64
	first := true

	for sc.Scan() {
		rawLine := sc.Bytes()
		if len(rawLine) == 0 {
			continue
		}
		// Copy before next Scan() invalidates the buffer.
		line := make([]byte, len(rawLine))
		copy(line, rawLine)

		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			reportf("malformed JSON: %v", err)
			errs++
			continue
		}
		total++

		// 1. Sequence monotonicity.
		if !first && e.Seq != prevSeq+1 {
			reportf("seq %d — expected %d (gap or reorder)", e.Seq, prevSeq+1)
			errs++
		}

		// 2. Hash chain: prev_hash of entry N must equal SHA-256 of raw line N-1.
		if !first && e.PrevHash != prevHash {
			reportf("seq %d — prev_hash mismatch\n  expected: %s\n  got:      %s",
				e.Seq, prevHash, e.PrevHash)
			errs++
		}

		// 3. Ed25519 signature (optional).
		if pub != nil {
			if err := VerifyEntry(e, pub); err != nil {
				reportf("seq %d — %v", e.Seq, err)
				errs++
			}
		}

		sum := sha256.Sum256(line)
		prevHash = hex.EncodeToString(sum[:])
		prevSeq = e.Seq
		first = false
	}
	if err := sc.Err(); err != nil {
		reportf("read error: %v", err)
		errs++
	}
	return total, errs
}

// VerifyEntry checks the Ed25519 signature of a single entry against pub. The
// canonical payload is the entry re-marshaled with Sig="" — byte-for-byte what
// Append signs — so producer and verifier share one canonicalization and cannot
// drift: a signed field added to Entry is covered here automatically. Returns
// nil when the signature is valid.
func VerifyEntry(e Entry, pub ed25519.PublicKey) error {
	sigBytes, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf("invalid sig encoding: %v", err)
	}
	e.Sig = ""
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal for sig check: %v", err)
	}
	if !ed25519.Verify(pub, payload, sigBytes) {
		return errors.New("signature invalid")
	}
	return nil
}

// VerifySegments verifies the complete audit chain across rotated segments.
// Each segment is checked internally with Verify, and consecutive segments are
// cross-linked: segment[N]'s first prev_hash must equal SHA-256 of
// segment[N-1]'s last line, and the earliest segment must begin at genesis
// (prev_hash=""). This makes dropping/truncating/reordering a whole rotated
// segment detectable — the guarantee THREAT_MODEL.md states for rotation, which
// single-file verification cannot deliver (it accepts the first prev_hash as an
// unchecked seed).
func VerifySegments(logPath string, pub ed25519.PublicKey, reportf func(string, ...any)) (total, errs int) {
	segments, err := discoverSegments(logPath)
	if err != nil {
		reportf("discovering audit segments: %v", err)
		return 0, 1
	}
	if len(segments) == 0 {
		reportf("no audit segments found for %q", logPath)
		return 0, 1
	}
	prevLast := ""
	for i, seg := range segments {
		f, err := os.Open(seg)
		if err != nil {
			reportf("%s: open: %v", seg, err)
			errs++
			continue
		}
		t, e := Verify(f, pub, func(format string, args ...any) {
			reportf(seg+": "+format, args...)
		})
		f.Close()
		total += t
		errs += e

		firstPrev, lastHash, berr := FileBounds(seg)
		if berr != nil {
			reportf("%s: %v", seg, berr)
			errs++
			continue
		}
		switch {
		case i == 0 && firstPrev != "":
			reportf("%s: earliest segment does not start at genesis (prev_hash=%s); an earlier segment is missing or was pruned", seg, firstPrev)
			errs++
		case i > 0 && firstPrev != prevLast:
			reportf("%s: first prev_hash does not link to the previous segment\n  expected: %s\n  got:      %s\n  (a rotated segment was dropped, truncated, replaced, or reordered)", seg, prevLast, firstPrev)
			errs++
		}
		prevLast = lastHash
	}
	return total, errs
}

// discoverSegments returns the rotated segments of logPath followed by the
// active file, sorted oldest→newest (the timestamp suffix — and its ".<n>"
// same-second disambiguator — sorts chronologically). Only true rotation
// segments are included, recognised by isRotatedSegment (single-sourced with what
// maybeRotate/rotatedSegmentPath write). This deliberately excludes sibling files
// that share the "<logPath>." glob prefix but are NOT segments, notably the
// `audit repair` quarantine file (<logPath>.corrupt-<ts>), whose quarantined bytes
// are malformed by definition and would otherwise make `verify --all` falsely
// report a repaired chain broken.
func discoverSegments(logPath string) ([]string, error) {
	matches, err := filepath.Glob(logPath + ".*")
	if err != nil {
		return nil, err
	}
	prefix := logPath + "."
	var files []string
	for _, m := range matches {
		if isRotatedSegment(strings.TrimPrefix(m, prefix)) {
			files = append(files, m)
		}
	}
	sort.Strings(files)
	if _, err := os.Stat(logPath); err == nil {
		files = append(files, logPath)
	}
	return files, nil
}

// FileBounds returns the prev_hash of the first entry and the SHA-256 of the
// last raw line of an audit segment, used to verify cross-segment linkage.
func FileBounds(path string) (firstPrevHash, lastHash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, readerBufferSize), readerBufferSize)
	first := true
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		if first {
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				return "", "", fmt.Errorf("parsing first entry: %w", err)
			}
			firstPrevHash = e.PrevHash
			first = false
		}
		sum := sha256.Sum256(line)
		lastHash = hex.EncodeToString(sum[:])
	}
	if err := sc.Err(); err != nil {
		return "", "", fmt.Errorf("scanning: %w", err)
	}
	if first {
		return "", "", fmt.Errorf("empty segment")
	}
	return firstPrevHash, lastHash, nil
}

// TrailingCorruption scans an audit log for a corrupt/truncated trailing record.
// It returns the byte offset up to which the log is clean (records parse and are
// newline-terminated), the last good seq, the count of well-formed records in
// that prefix, the corrupt trailing bytes, and whether a well-formed record
// appears AFTER a malformed one (middle corruption — unsafe to truncate, and not
// the startup-brick case since restoreChain reads the last line). Blank lines
// are benign and skipped. A complete final record with no trailing newline (the
// #14 case, which restoreChain already repairs) is treated as clean.
func TrailingCorruption(data []byte) (cleanEnd int, lastGoodSeq uint64, goodCount int, corruptTail []byte, middleCorruption bool) {
	offset := 0
	sawBad := false
	for offset < len(data) {
		rest := data[offset:]
		nl := bytes.IndexByte(rest, '\n')
		var line []byte
		var lineLen int
		if nl < 0 {
			line, lineLen = rest, len(rest)
		} else {
			line, lineLen = rest[:nl], nl+1
		}
		trimmed := bytes.TrimRight(line, "\r")
		if len(bytes.TrimSpace(trimmed)) == 0 {
			offset += lineLen // blank line: harmless
			continue
		}
		var e Entry
		if json.Unmarshal(trimmed, &e) == nil {
			if sawBad {
				middleCorruption = true
			} else {
				cleanEnd = offset + lineLen
				lastGoodSeq = e.Seq
				goodCount++
			}
		} else {
			sawBad = true
		}
		offset += lineLen
	}
	if sawBad && !middleCorruption {
		corruptTail = data[cleanEnd:]
	}
	return
}
