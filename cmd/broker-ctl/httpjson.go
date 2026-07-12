package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// maxRespBytes bounds every broker-ctl HTTP response read, matching the
// io.LimitReader discipline of the internal clients (internal/bridge/cpclient,
// internal/signer/remote) instead of the previously-unbounded io.ReadAll: a
// hostile or malfunctioning peer cannot make the CLI allocate without limit.
const maxRespBytes = 4 << 20 // 4 MiB

// doJSON performs an mTLS JSON request against the signer / control plane and
// returns the response body, read bounded to maxRespBytes. It marshals reqBody as
// the request body when non-nil (with Content-Type: application/json), exits via
// fatalf on a transport error or a non-2xx status, and decodes the body into out
// when out is non-nil. Callers that need the raw bytes (e.g. a --json passthrough
// or a conditional decode) pass a nil out and use the return value.
//
// It collapses the ~marshal → NewRequest → Do → ReadAll → status-check → Unmarshal
// block that every broker-ctl command otherwise repeats, and is the single place
// the response size is bounded.
func doJSON(client *http.Client, method, url string, reqBody, out any) []byte {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			fatalf("encoding request for %s: %v", url, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		fatalf("building request %s %s: %v", method, url, err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if resp.StatusCode/100 != 2 {
		fatalf("%s %s failed (HTTP %d): %s", method, url, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if out != nil {
		if err := json.Unmarshal(rb, out); err != nil {
			fatalf("decoding response from %s: %v", url, err)
		}
	}
	return rb
}
