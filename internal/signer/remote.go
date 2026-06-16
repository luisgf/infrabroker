package signer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrSignerUnavailable indicates the signing service could not be reached or
// returned a server error (transport failure or HTTP 5xx) — an infrastructure
// problem, not an authorization decision. Callers (e.g. the HTTP frontend) can
// map it to 502 instead of 403. A 4xx rejection is a policy/authorization
// denial and is returned as a plain error (not wrapped in this sentinel).
var ErrSignerUnavailable = errors.New("signing service unavailable")

// WireRequest is the body of POST /v1/sign. It does not include Caller: the
// service derives it from the mTLS client certificate (not assertable by the
// broker).
type WireRequest struct {
	Host       string `json:"host"`
	Role       string `json:"role"`
	Purpose    string `json:"purpose"`
	Command    string `json:"command,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	PublicKey  string `json:"public_key"` // authorized_keys line of the ephemeral pubkey

	// Elevation (sudo NOPASSWD).
	Sudo     bool   `json:"sudo,omitempty"`
	SudoUser string `json:"sudo_user,omitempty"` // empty = root

	// PTY: requests permit-pty in the certificate.
	PTY bool `json:"pty,omitempty"`

	// DryRun: resolves the policy and returns the decision without issuing a
	// usable cert.
	DryRun bool `json:"dry_run,omitempty"`

	// OnBehalfOf: CN of the broker on whose behalf a trusted forwarder (control
	// plane) is acting. The signer honours this only if the mTLS CN is in
	// trusted_forwarders.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`

	// Approved: the operation (which requires approval) has already been approved.
	// Honoured only from a trusted forwarder.
	Approved bool `json:"approved,omitempty"`

	// End-user identity, asserted by the broker (authenticated via mTLS).
	// EndUser feeds traceability; EndUserGroups, if non-nil, activates per-user
	// RBAC in the signer.
	//
	// EndUserGroups deliberately has NO omitempty: the nil-vs-empty distinction
	// is load-bearing. nil = no end-user identity asserted (stdio/mTLS) → per-user
	// RBAC not applied; non-nil empty []string{} = an authenticated user with zero
	// groups → deny every host. With omitempty, encoding/json drops a length-0
	// slice entirely (nil and empty both vanish), so a deny-all decision computed
	// by the OIDC verifier would arrive at the signer as nil = unrestricted — the
	// exact inverse of the intended decision. Keep it serialised: nil→null→nil,
	// []→[]→non-nil-empty.
	EndUser       string   `json:"end_user,omitempty"`
	EndUserGroups []string `json:"end_user_groups"`
}

// WireResponse is the service response to /v1/sign.
type WireResponse struct {
	Certificate string `json:"certificate,omitempty"` // authorized_keys line of the cert (empty in dry-run)
	Serial      uint64 `json:"serial,omitempty"`
	// ElevationPrefix is the prefix to prepend in persistent sessions.
	// Empty in one-shot (the prefix is already in the cert's force-command).
	ElevationPrefix string `json:"elevation_prefix,omitempty"`
	// Decision is populated in dry-run (empty Certificate) and optionally in
	// normal issuance for traceability.
	Decision *DecisionInfo `json:"decision,omitempty"`
}

// WireHostInfo contains the connectivity and capability data for a host as
// returned by GET /v1/hosts. It does not include internal policy data
// (principal, source_address, etc.) — those remain exclusive to the signer.
type WireHostInfo struct {
	Addr    string `json:"addr"`
	User    string `json:"user"`
	HostKey string `json:"host_key"`
	Jump    string `json:"jump,omitempty"`
	// Capabilities: tells the broker (and the model) which operations are allowed.
	AllowSudo bool `json:"allow_sudo,omitempty"`
	AllowPTY  bool `json:"allow_pty,omitempty"`
	// Groups are the RBAC groups the host belongs to, so the broker can filter
	// the host list it shows to an end user by the user's OIDC groups —
	// consistent with the per-user check the signer applies at signing time.
	// Group names are labels, not secrets; the broker already asserts
	// end_user_groups, so it sits at the same trust level.
	Groups []string `json:"groups,omitempty"`
}

// HostInfo is the broker's internal representation of connectivity and
// capability data received from the signer.
type HostInfo struct {
	Addr      string
	User      string
	HostKey   string
	Jump      string
	AllowSudo bool
	AllowPTY  bool
	Groups    []string
}

// Remote delegates signing to the external service via HTTP+mTLS. It can talk
// to the signer directly or to the control plane (same protocol); in the latter
// case a 202 response indicates that the operation is pending human approval and
// the client polls until it is resolved.
type Remote struct {
	client       *http.Client
	url          string
	approvalWait time.Duration // maximum wait time on a 202 (0 = do not wait)
}

// NewRemote creates a client for the signing service.
func NewRemote(url string, tlsCfg *tls.Config, timeout time.Duration) *Remote {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Remote{
		url:    url,
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}
}

// SetApprovalWait sets how long the client waits for a human approval to be
// resolved (202 response from the control plane). 0 = do not wait (a 202
// translates to an immediate error).
func (r *Remote) SetApprovalWait(d time.Duration) { r.approvalWait = d }

// SignIntent implements Signer against the remote service.
func (r *Remote) SignIntent(ctx context.Context, in Intent) (*Issued, error) {
	body, err := json.Marshal(WireRequest{
		Host:          in.Host,
		Role:          in.Role,
		Purpose:       in.Purpose,
		Command:       in.Command,
		TTLSeconds:    int(in.RequestedTTL / time.Second),
		PublicKey:     string(ssh.MarshalAuthorizedKey(in.PublicKey)),
		Sudo:          in.Sudo,
		SudoUser:      in.SudoUser,
		PTY:           in.PTY,
		DryRun:        in.DryRun,
		OnBehalfOf:    in.OnBehalfOf,
		Approved:      in.Approved,
		EndUser:       in.EndUser,
		EndUserGroups: in.EndUserGroups,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url+"/v1/sign", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building /v1/sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: contacting signing service: %v", ErrSignerUnavailable, err)
	}
	defer resp.Body.Close()
	// A2: limit the read from /v1/sign to prevent OOM from oversized responses.
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading /v1/sign response: %w", err)
	}
	// 202: operation requires human approval (control plane). Poll for result.
	if resp.StatusCode == http.StatusAccepted {
		var acc struct {
			ApprovalID string `json:"approval_id"`
		}
		if err := json.Unmarshal(rb, &acc); err != nil || acc.ApprovalID == "" {
			return nil, fmt.Errorf("invalid 202 response from control plane")
		}
		return r.pollApproval(ctx, acc.ApprovalID)
	}
	if resp.StatusCode != http.StatusOK {
		// 5xx is an infrastructure failure; 4xx is a policy/authorization denial.
		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("%w (%d): %s", ErrSignerUnavailable, resp.StatusCode, bytes.TrimSpace(rb))
		}
		return nil, fmt.Errorf("signing rejected (%d): %s", resp.StatusCode, bytes.TrimSpace(rb))
	}

	var wr WireResponse
	if err := json.Unmarshal(rb, &wr); err != nil {
		return nil, fmt.Errorf("invalid response: %w", err)
	}
	// Dry-run, or response without certificate (requires approval): decision only.
	if in.DryRun || wr.Certificate == "" {
		return &Issued{Decision: wr.Decision}, nil
	}
	cert, err := ParseCertificate(wr.Certificate)
	if err != nil {
		return nil, err
	}
	return &Issued{Certificate: cert, Serial: wr.Serial, ElevationPrefix: wr.ElevationPrefix, Decision: wr.Decision}, nil
}

// HeaderOnBehalfOf carries the broker CN in GET requests (no body) that a
// trusted forwarder (control plane) makes on its behalf.
const HeaderOnBehalfOf = "X-On-Behalf-Of"

// pollApproval queries GET /v1/sign/result/{id} until the request is resolved
// (cert issued after approval), denied/expired, or approvalWait is exhausted.
// Each poll is a short request; the interval between polls is fixed.
func (r *Remote) pollApproval(ctx context.Context, approvalID string) (*Issued, error) {
	if r.approvalWait <= 0 {
		return nil, fmt.Errorf("operation requires human approval (id %s); client is not configured to wait", approvalID)
	}
	const interval = 2 * time.Second
	deadline := time.Now().Add(r.approvalWait)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("approval not granted within deadline (id %s)", approvalID)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url+"/v1/sign/result/"+approvalID, nil)
		if err != nil {
			return nil, fmt.Errorf("building poll request: %w", err)
		}
		resp, err := r.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("querying approval result: %w", err)
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusAccepted:
			continue // still pending
		case http.StatusOK:
			var wr WireResponse
			if err := json.Unmarshal(rb, &wr); err != nil {
				return nil, fmt.Errorf("invalid approval response: %w", err)
			}
			cert, err := ParseCertificate(wr.Certificate)
			if err != nil {
				return nil, err
			}
			return &Issued{Certificate: cert, Serial: wr.Serial, ElevationPrefix: wr.ElevationPrefix, Decision: wr.Decision}, nil
		default:
			return nil, fmt.Errorf("approval not granted (%d): %s", resp.StatusCode, bytes.TrimSpace(rb))
		}
	}
}

// FetchHosts calls GET /v1/hosts on the signer and returns the connectivity
// data for all configured hosts. The broker uses this to build SSH hops; the
// signing policy remains in the signer.
//
// onBehalfOf, if non-empty, is sent in the X-On-Behalf-Of header so that the
// signer filters hosts by the original broker's groups (control plane use case).
// The broker passes "" (acting on its own behalf).
func (r *Remote) FetchHosts(ctx context.Context, onBehalfOf string) (map[string]HostInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url+"/v1/hosts", nil)
	if err != nil {
		return nil, fmt.Errorf("building /v1/hosts request: %w", err)
	}
	if onBehalfOf != "" {
		req.Header.Set(HeaderOnBehalfOf, onBehalfOf)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching host list: %w", err)
	}
	defer resp.Body.Close()
	// A2: limit the read from /v1/hosts to prevent OOM from oversized responses.
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading /v1/hosts response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer returned %d: %s", resp.StatusCode, bytes.TrimSpace(rb))
	}

	var wire map[string]WireHostInfo
	if err := json.Unmarshal(rb, &wire); err != nil {
		return nil, fmt.Errorf("invalid /v1/hosts response: %w", err)
	}

	hosts := make(map[string]HostInfo, len(wire))
	for name, h := range wire {
		hosts[name] = HostInfo{
			Addr:      h.Addr,
			User:      h.User,
			HostKey:   h.HostKey,
			Jump:      h.Jump,
			AllowSudo: h.AllowSudo,
			AllowPTY:  h.AllowPTY,
			Groups:    h.Groups,
		}
	}
	return hosts, nil
}

// ParseCertificate converts an authorized_keys line into an *ssh.Certificate.
func ParseCertificate(authorizedLine string) (*ssh.Certificate, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedLine))
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("returned key is not a certificate")
	}
	return cert, nil
}

// ParsePublicKey converts an authorized_keys line into an ssh.PublicKey.
func ParsePublicKey(authorizedLine string) (ssh.PublicKey, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedLine))
	if err != nil {
		return nil, fmt.Errorf("parsing pubkey: %w", err)
	}
	return pk, nil
}
