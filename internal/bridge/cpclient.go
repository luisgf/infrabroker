package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/luisgf/infrabroker/internal/control"
)

// HTTPControlPlane is the ControlPlane backed by the control plane's mTLS
// approval API. The client certificate CN must be an approver (in the control
// plane's approval.callers).
type HTTPControlPlane struct {
	base   string
	client *http.Client
}

// NewHTTPControlPlane dials host ("host:port") over mTLS with tlsCfg.
func NewHTTPControlPlane(host string, tlsCfg *tls.Config) *HTTPControlPlane {
	return newControlPlane("https://"+host, &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}})
}

// newControlPlane is the transport-agnostic constructor (used by tests).
func newControlPlane(base string, client *http.Client) *HTTPControlPlane {
	return &HTTPControlPlane{base: base, client: client}
}

// List calls GET /v1/approvals and returns the pending requests.
func (c *HTTPControlPlane) List(ctx context.Context) ([]control.Approval, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/approvals", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /v1/approvals: %w", err)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned %d listing approvals: %s", resp.StatusCode, bytes.TrimSpace(rb))
	}
	var out []control.Approval
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("decoding approvals: %w", err)
	}
	return out, nil
}

// Decide calls POST /v1/approvals/{id} to approve or deny. The control plane
// derives the approver from the mTLS CN and enforces the four-eyes guard, so a
// decision on the bridge's own originated request (there are none) would be
// rejected there, not here.
func (c *HTTPControlPlane) Decide(ctx context.Context, id string, approve bool) error {
	payload, _ := json.Marshal(map[string]any{"approve": approve})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/approvals/"+url.PathEscape(id), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /v1/approvals/%s: %w", id, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane returned %d deciding %s: %s", resp.StatusCode, id, bytes.TrimSpace(rb))
	}
	return nil
}
