// Package sealed implements the per-command authorization envelope behind
// "sealed exec" — host-enforced session commands (#144, THREAT_MODEL gap #1).
//
// Session exec filtering is otherwise broker-enforced: a compromised broker
// could simply skip the per-command preflight. On a host with sealed_exec the
// session certificate instead carries force-command=infrabroker-shim. The signer
// signs {nonce, host, command, expiry} at the per-command preflight it already
// performs (no new hot path); the broker sends that envelope as the SSH channel
// command; sshd hands it to the shim in $SSH_ORIGINAL_COMMAND, and the shim runs
// the inner command only if the envelope verifies against a pinned public key,
// has not expired, and its nonce has not been seen before. A broker that skips
// the preflight therefore holds nothing the host will run — per-command
// authorization that survives broker compromise.
//
// The envelope key is a dedicated Ed25519 keypair, deliberately NOT the SSH CA:
// the AKV CA backend cannot do Ed25519, signing a raw blob is a different
// surface from signing an ssh.Certificate, and the shim should trust only this
// key rather than the whole CA.
package sealed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ShimCommand is the shim's name, as it appears in a sealed host's certificate
// force-command. sshd runs that command for every channel on the connection and
// passes the broker's requested command (the envelope) in $SSH_ORIGINAL_COMMAND.
// Use ForceCommand to build the full value: the host name must ride along.
const ShimCommand = "infrabroker-shim"

// validHostName restricts a sealed host's name to a single shell-safe token. The
// name is passed to the shim as argv through the certificate's force-command,
// which sshd runs via the user's shell, so anything else could break the command
// line or splice into it.
var validHostName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidHostName reports whether name may be used as a sealed host's name.
func ValidHostName(name string) bool { return validHostName.MatchString(name) }

// ForceCommand renders the force-command a sealed host's certificate carries:
// the shim, plus the host name that shim must enforce. Passing the name through
// the certificate is what makes it trustworthy — sshd hands argv over verbatim
// from the signer-signed cert, so a compromised broker cannot forge it. Without
// it every sealed host would accept an envelope minted for any other sealed host
// (they all pin the same envelope key).
func ForceCommand(host string) (string, error) {
	if !ValidHostName(host) {
		return "", fmt.Errorf("sealed: host name %q is not a shell-safe token; sealed_exec requires [A-Za-z0-9][A-Za-z0-9._-]*", host)
	}
	return ShimCommand + " " + host, nil
}

// DefaultTTL is how long an envelope stays valid. It bounds the replay window
// alongside the shim's nonce cache, and is deliberately short: the envelope is
// minted at the preflight immediately before the broker executes the command.
const DefaultTTL = 30 * time.Second

// MaxTTL caps the validity an envelope may be issued with. A longer window would
// widen the replay surface on a host whose nonce cache is best-effort.
const MaxTTL = 5 * time.Minute

// domainPrefix separates this signature domain from every other Ed25519
// signature in the system (notably the audit chain), so a blob signed elsewhere
// can never verify as an envelope.
const domainPrefix = "infrabroker-sealed-exec-v1\x00"

// Envelope is a signer-issued authorization for exactly one command on one
// sealed host, valid until Expiry and intended to be used once (Nonce). Field
// names are short because it travels as the SSH channel command.
type Envelope struct {
	Nonce   string `json:"n"`
	Host    string `json:"h"`
	Command string `json:"c"`
	Expiry  int64  `json:"e"` // unix seconds
	Sig     []byte `json:"s"` // Ed25519 over signedBytes
}

// signedBytes is the canonical byte string the signature covers. Every field is
// length-prefixed, which makes the encoding injective: no combination of host
// and command values can collide with a different envelope's bytes.
func (e Envelope) signedBytes() []byte {
	var b bytes.Buffer
	b.WriteString(domainPrefix)
	writeField(&b, e.Nonce)
	writeField(&b, e.Host)
	writeField(&b, e.Command)
	writeField(&b, strconv.FormatInt(e.Expiry, 10))
	return b.Bytes()
}

func writeField(b *bytes.Buffer, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	b.Write(n[:])
	b.WriteString(s)
}

// Sign issues an envelope authorising command on host for ttl from now, and
// returns its wire form (base64url of the JSON — no spaces or newlines, so it
// survives as an SSH channel command). command must already carry any elevation
// prefix: the shim, not the broker, is what applies it.
func Sign(key ed25519.PrivateKey, host, command string, ttl time.Duration, now time.Time) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("sealed: invalid envelope private key")
	}
	if host == "" {
		return "", errors.New("sealed: empty host")
	}
	if command == "" {
		return "", errors.New("sealed: empty command")
	}
	if ttl <= 0 || ttl > MaxTTL {
		return "", fmt.Errorf("sealed: ttl must be in (0, %v]", MaxTTL)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("sealed: nonce: %w", err)
	}
	e := Envelope{
		Nonce:   hex.EncodeToString(nonce),
		Host:    host,
		Command: command,
		Expiry:  now.Add(ttl).Unix(),
	}
	e.Sig = ed25519.Sign(key, e.signedBytes())
	js, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(js), nil
}

// Verify decodes wire, authenticates it against pub, and binds it to
// expectedHost and to now. It is stateless and therefore cannot detect a replay:
// the caller (the shim) must additionally claim the returned Nonce exactly once.
//
// expectedHost is REQUIRED — an empty value is an error rather than a wildcard.
// Every sealed host pins the same envelope key, so an envelope checked without a
// host binding is a fleet-wide bearer token: one minted for a permissive host
// would execute verbatim on a restrictive one. Making the parameter mandatory is
// what stops a future caller from quietly dropping the check.
func Verify(pub ed25519.PublicKey, wire, expectedHost string, now time.Time) (*Envelope, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("sealed: invalid envelope public key")
	}
	if expectedHost == "" {
		return nil, errors.New("sealed: no expected host given; refusing to verify an envelope that is not bound to this host")
	}
	js, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(wire))
	if err != nil {
		return nil, fmt.Errorf("sealed: malformed envelope: %w", err)
	}
	var e Envelope
	if err := json.Unmarshal(js, &e); err != nil {
		return nil, fmt.Errorf("sealed: malformed envelope: %w", err)
	}
	// Signature first: nothing else in the envelope is trustworthy until the
	// bytes are authenticated.
	if !ed25519.Verify(pub, e.signedBytes(), e.Sig) {
		return nil, errors.New("sealed: envelope signature does not verify")
	}
	// Host binding. The signer authorises a command on ONE host, but every sealed
	// host pins the same envelope key, so this comparison is the only thing that
	// stops an envelope minted for a permissive host from executing verbatim on a
	// restrictive one — the signature alone would happily verify there.
	if e.Host != expectedHost {
		return nil, fmt.Errorf("sealed: envelope is bound to host %q, not %q", e.Host, expectedHost)
	}
	if e.Nonce == "" {
		return nil, errors.New("sealed: envelope carries no nonce")
	}
	if e.Command == "" {
		return nil, errors.New("sealed: envelope carries no command")
	}
	if now.Unix() > e.Expiry {
		return nil, fmt.Errorf("sealed: envelope expired at %s",
			time.Unix(e.Expiry, 0).UTC().Format(time.RFC3339))
	}
	// Bound the window against clock skew: Sign refuses a ttl beyond MaxTTL, so an
	// envelope claiming validity further ahead than that means this host's clock is
	// behind the signer's (or the expiry is nonsense). Accepting it would stretch
	// the replay window far past the 30s the design assumes — and past what the
	// shim's nonce sweep is sized for.
	if e.Expiry-now.Unix() > int64(MaxTTL/time.Second) {
		return nil, fmt.Errorf("sealed: envelope expiry is more than %v in the future; check clock sync between signer and host", MaxTTL)
	}
	return &e, nil
}

// PublicKeyString renders an envelope public key in the one-line base64 form the
// shim reads from its pinned key file. The signer logs it at startup so an
// operator can pin it on sealed hosts.
func PublicKeyString(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey reads the one-line base64 form written by PublicKeyString.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("sealed: envelope public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("sealed: envelope public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// KeyFromSeed builds the envelope private key from a raw seed file's bytes,
// mirroring how the audit chain key is loaded (a 32-byte seed on disk).
func KeyFromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) < ed25519.SeedSize {
		return nil, fmt.Errorf("sealed: envelope key seed must be at least %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]), nil
}
