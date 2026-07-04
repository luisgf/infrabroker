package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Response read caps: a get/list response is JSON the model will consume; logs
// are additionally bounded by tail_lines at the request level.
const (
	apiMaxBytes  = 4 * 1024 * 1024
	logsMaxBytes = 512 * 1024
)

// FieldManager identifies this broker in server-side-apply ownership.
const FieldManager = "infrabroker"

// Target is the connection identity of one cluster: where the API server is
// and which CA signs it. Both are public material (they travel from the
// signer to the broker over /v1/clusters).
type Target struct {
	APIServer string // e.g. https://10.0.0.5:6443
	CAPEM     []byte // PEM bundle of the cluster CA
}

// httpClientFor builds an http.Client pinned to the target's CA. No system
// roots: the cluster CA is the only trust anchor (fail-closed).
func httpClientFor(t Target, timeout time.Duration) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(t.CAPEM) {
		return nil, fmt.Errorf("k8s: no CA certificate parsed for %s", t.APIServer)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// Client performs the five curated verbs against one cluster with one
// short-lived bearer token. It is built per operation and discarded with the
// token — the broker holds no standing cluster credential.
type Client struct {
	target Target
	token  string
	http   *http.Client
}

// NewClient builds a client for one operation. token is the ephemeral bound
// ServiceAccount token minted by the signer.
func NewClient(t Target, token string, timeout time.Duration) (*Client, error) {
	hc, err := httpClientFor(t, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{target: t, token: token, http: hc}, nil
}

// resourcePath builds the REST path for a resource, with every component
// path-escaped (they are charset-validated upstream; the escape is defense in
// depth, not a sanitizer).
func resourcePath(def ResourceDef, namespace, name string) string {
	var b strings.Builder
	if def.Group == "" {
		b.WriteString("/api/" + url.PathEscape(def.Version))
	} else {
		b.WriteString("/apis/" + url.PathEscape(def.Group) + "/" + url.PathEscape(def.Version))
	}
	if def.Namespaced && namespace != "" {
		b.WriteString("/namespaces/" + url.PathEscape(namespace))
	}
	b.WriteString("/" + url.PathEscape(def.Resource))
	if name != "" {
		b.WriteString("/" + url.PathEscape(name))
	}
	return b.String()
}

// do runs one request and returns the (bounded) response body. A non-2xx
// answer surfaces the API server's Status message, so the agent sees "pods
// \"x\" not found" instead of a bare status code.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, contentType string, body []byte, maxBytes int64) (string, int, error) {
	u := strings.TrimRight(c.target.APIServer, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return "", 0, fmt.Errorf("k8s: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("k8s: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("k8s: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", resp.StatusCode, fmt.Errorf("k8s: %s %s: %s", method, path, statusMessage(rb, resp.StatusCode))
	}
	return string(rb), resp.StatusCode, nil
}

// statusMessage extracts the message from a Kubernetes Status error body.
func statusMessage(body []byte, code int) string {
	var st struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(body, &st); err == nil && st.Message != "" {
		return fmt.Sprintf("%d %s", code, st.Message)
	}
	return fmt.Sprintf("%d %s", code, strings.TrimSpace(string(body)))
}

// Get retrieves one object as JSON.
func (c *Client) Get(ctx context.Context, def ResourceDef, namespace, name string) (string, error) {
	out, _, err := c.do(ctx, http.MethodGet, resourcePath(def, namespace, name), nil, "", nil, apiMaxBytes)
	return out, err
}

// ListOptions bound a List call.
type ListOptions struct {
	LabelSelector string
	FieldSelector string
	Limit         int // 0 = server default
}

// List retrieves a collection as JSON. An empty namespace on a namespaced
// resource lists across all namespaces (subject to the SA's RBAC).
func (c *Client) List(ctx context.Context, def ResourceDef, namespace string, opt ListOptions) (string, error) {
	q := url.Values{}
	if opt.LabelSelector != "" {
		q.Set("labelSelector", opt.LabelSelector)
	}
	if opt.FieldSelector != "" {
		q.Set("fieldSelector", opt.FieldSelector)
	}
	if opt.Limit > 0 {
		q.Set("limit", strconv.Itoa(opt.Limit))
	}
	out, _, err := c.do(ctx, http.MethodGet, resourcePath(def, namespace, ""), q, "", nil, apiMaxBytes)
	return out, err
}

// LogOptions bound a Logs call.
type LogOptions struct {
	Container    string
	TailLines    int // <=0 selects the 200-line default
	SinceSeconds int
}

// Logs retrieves (plain-text) container logs from a pod.
func (c *Client) Logs(ctx context.Context, namespace, pod string, opt LogOptions) (string, error) {
	q := url.Values{}
	if opt.Container != "" {
		q.Set("container", opt.Container)
	}
	tail := opt.TailLines
	if tail <= 0 {
		tail = 200
	}
	q.Set("tailLines", strconv.Itoa(tail))
	if opt.SinceSeconds > 0 {
		q.Set("sinceSeconds", strconv.Itoa(opt.SinceSeconds))
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod) + "/log"
	out, _, err := c.do(ctx, http.MethodGet, path, q, "", nil, logsMaxBytes)
	return out, err
}

// Delete removes one object.
func (c *Client) Delete(ctx context.Context, def ResourceDef, namespace, name string) (string, error) {
	out, _, err := c.do(ctx, http.MethodDelete, resourcePath(def, namespace, name), nil, "", nil, apiMaxBytes)
	return out, err
}

// Apply performs a server-side apply (create-or-update) of a JSON manifest as
// fieldManager=infrabroker. The API server enforces that the manifest's
// metadata matches the path; a field-manager conflict fails the apply (there
// is no force override — the broker never overwrites another manager's fields).
func (c *Client) Apply(ctx context.Context, def ResourceDef, namespace, name string, manifest []byte) (string, error) {
	q := url.Values{}
	q.Set("fieldManager", FieldManager)
	out, _, err := c.do(ctx, http.MethodPatch, resourcePath(def, namespace, name), q,
		"application/apply-patch+yaml", manifest, apiMaxBytes)
	return out, err
}

// MinterTarget is one cluster's token-minting identity: the API server, its
// CA, and the path to the minter credential — a ServiceAccount token whose
// entire RBAC is `create` on `serviceaccounts/token` for the bound SAs. It is
// the signer's only standing cluster credential, read per call so an
// externally rotated file is picked up without a reload.
type MinterTarget struct {
	Target
	TokenFile string
}

// Minter mints short-lived bound ServiceAccount tokens via the TokenRequest
// API. It satisfies the signer's TokenMinter interface.
type Minter struct {
	targets map[string]MinterTarget
	timeout time.Duration
}

// NewMinter builds a minter over the configured clusters.
func NewMinter(targets map[string]MinterTarget) *Minter {
	return &Minter{targets: targets, timeout: 15 * time.Second}
}

// MintToken requests a bound token for namespace/sa on cluster with the given
// TTL, returning the token and its expiry.
func (m *Minter) MintToken(ctx context.Context, cluster, namespace, sa string, ttl time.Duration) (string, time.Time, error) {
	t, ok := m.targets[cluster]
	if !ok {
		return "", time.Time{}, fmt.Errorf("k8s: unknown cluster %q", cluster)
	}
	minterTok, err := os.ReadFile(t.TokenFile)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("k8s: reading minter token: %w", err)
	}
	c, err := NewClient(t.Target, strings.TrimSpace(string(minterTok)), m.timeout)
	if err != nil {
		return "", time.Time{}, err
	}

	body, err := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec":       map[string]any{"expirationSeconds": int(ttl / time.Second)},
	})
	if err != nil {
		return "", time.Time{}, err
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/serviceaccounts/" + url.PathEscape(sa) + "/token"
	out, _, err := c.do(ctx, http.MethodPost, path, nil, "application/json", body, apiMaxBytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("minting token for %s/%s on %q: %w", namespace, sa, cluster, err)
	}
	var tr struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &tr); err != nil || tr.Status.Token == "" {
		return "", time.Time{}, fmt.Errorf("k8s: invalid TokenRequest response for %q", cluster)
	}
	return tr.Status.Token, tr.Status.ExpirationTimestamp, nil
}
