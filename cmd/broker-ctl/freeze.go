package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/luisgf/infrabroker/internal/signer"
)

// resolveFreezeSubject maps the mutually-exclusive subject flags to a (kind,
// value) pair, requiring exactly one to be set.
func resolveFreezeSubject(caller, endUser, sessionID, serial string) (kind, value string) {
	n := 0
	if caller != "" {
		n, kind, value = n+1, signer.FreezeCaller, caller
	}
	if endUser != "" {
		n, kind, value = n+1, signer.FreezeEndUser, endUser
	}
	if sessionID != "" {
		n, kind, value = n+1, signer.FreezeSessionID, sessionID
	}
	if serial != "" {
		n, kind, value = n+1, signer.FreezeSerial, serial
	}
	if n != 1 {
		fatalf("exactly one of --caller / --end-user / --session-id / --serial is required")
	}
	return kind, value
}

// subjectFlags registers the four mutually-exclusive freeze subject flags.
func subjectFlags(fs *flag.FlagSet) (caller, endUser, sessionID, serial *string) {
	caller = fs.String("caller", "", "freeze/unfreeze a broker mTLS CN")
	endUser = fs.String("end-user", "", "freeze/unfreeze an end-user identity")
	sessionID = fs.String("session-id", "", "freeze/unfreeze a specific live session")
	serial = fs.String("serial", "", "freeze/unfreeze a specific certificate serial")
	return
}

// cmdFreeze calls the signer's POST /v1/freeze (mTLS, reload_callers) to freeze a
// subject: it gets no new certificate and no connectivity, and brokers kill its
// live sessions. Freezing a caller/end_user also revokes its runtime grants.
func cmdFreeze(args []string) {
	fs := flag.NewFlagSet("freeze", flag.ExitOnError)
	caller, endUser, sessionID, serial := subjectFlags(fs)
	reason := fs.String("reason", "", "optional reason recorded in the audit log")
	urlFlag, cert, key, ca := signerFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] freeze (--caller cn | --end-user u | --session-id id | --serial n) [--reason r]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	kind, value := resolveFreezeSubject(*caller, *endUser, *sessionID, *serial)
	resolveSignerTarget(fs)

	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
	body, _ := json.Marshal(map[string]any{"kind": kind, "value": value, "reason": *reason})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/freeze", bytes.NewReader(body))
	if err != nil {
		fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatalf("POST %s/v1/freeze: %v", base, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rejected the freeze (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var result struct {
		NewlyFrozen   bool `json:"newly_frozen"`
		GrantsRevoked int  `json:"grants_revoked"`
	}
	_ = json.Unmarshal(rb, &result)
	state := "frozen"
	if !result.NewlyFrozen {
		state = "already frozen (refreshed)"
	}
	fmt.Printf("%s %s=%s (grants revoked: %d)\n", state, kind, value, result.GrantsRevoked)
}

// cmdUnfreeze calls the signer's POST /v1/unfreeze (mTLS, reload_callers) to
// release a previously frozen subject.
func cmdUnfreeze(args []string) {
	fs := flag.NewFlagSet("unfreeze", flag.ExitOnError)
	caller, endUser, sessionID, serial := subjectFlags(fs)
	urlFlag, cert, key, ca := signerFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] unfreeze (--caller cn | --end-user u | --session-id id | --serial n)")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	kind, value := resolveFreezeSubject(*caller, *endUser, *sessionID, *serial)
	resolveSignerTarget(fs)

	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
	body, _ := json.Marshal(map[string]any{"kind": kind, "value": value})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/unfreeze", bytes.NewReader(body))
	if err != nil {
		fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatalf("POST %s/v1/unfreeze: %v", base, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rejected the unfreeze (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var result struct {
		WasFrozen bool `json:"was_frozen"`
	}
	_ = json.Unmarshal(rb, &result)
	if result.WasFrozen {
		fmt.Printf("unfrozen %s=%s\n", kind, value)
	} else {
		fmt.Printf("%s=%s was not frozen\n", kind, value)
	}
}

// cmdRevocations calls the signer's GET /v1/revocations (mTLS) and renders the
// current freeze set — the same list brokers poll to kill matching sessions.
func cmdRevocations(args []string) {
	fs := flag.NewFlagSet("revocations", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output as JSON")
	urlFlag, cert, key, ca := signerFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] revocations [--json]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	resolveSignerTarget(fs)

	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
	resp, err := client.Get(base + "/v1/revocations")
	if err != nil {
		fatalf("GET %s/v1/revocations: %v", base, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rejected the request (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if *asJSON {
		os.Stdout.Write(rb)
		if len(rb) > 0 && rb[len(rb)-1] != '\n' {
			fmt.Println()
		}
		return
	}
	var frozen []signer.FrozenEntry
	if err := json.Unmarshal(rb, &frozen); err != nil {
		fatalf("decode revocations: %v", err)
	}
	if len(frozen) == 0 {
		fmt.Println("(no frozen subjects)")
		return
	}
	fmt.Printf("%-12s %-24s %-20s %-16s %s\n", "KIND", "VALUE", "FROZEN AT (UTC)", "BY", "REASON")
	for _, e := range frozen {
		fmt.Printf("%-12s %-24s %-20s %-16s %s\n",
			e.Kind, e.Value, e.FrozenAt.UTC().Format(time.RFC3339), e.FrozenBy, e.Reason)
	}
}
