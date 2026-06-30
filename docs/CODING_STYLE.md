# Coding Style — ssh-broker

Rules enforced in this project. Every rule has a rationale and a mechanical
check so "does this pass?" has an unambiguous answer.

---

## 1. Formatting — `gofmt` is non-negotiable

```bash
gofmt -l .          # must print nothing
gofmt -w .          # apply in-place before committing
```

`gofmt` is the Go community standard. Struct tag alignment, comment spacing,
and indentation are handled by the tool; do not fight it manually. If a diff
touches only whitespace, run `gofmt -w` before opening a PR.

**What gofmt does NOT cover** (see rules below for those):
- Import grouping
- Comment style
- Function length
- Error wrapping

---

## 2. Import grouping — three blocks, always

Imports are separated into three groups with a blank line between each:

```go
import (
    // 1. Standard library
    "context"
    "fmt"
    "net/http"

    // 2. Third-party modules
    "golang.org/x/crypto/ssh"
    "github.com/modelcontextprotocol/go-sdk/mcp"

    // 3. Internal packages (same module)
    "github.com/luisgf/ssh-broker/internal/audit"
    "github.com/luisgf/ssh-broker/internal/signer"
)
```

`goimports` enforces this automatically. Run it as a pre-commit check if
available; otherwise enforce it in code review.

---

## 3. Error handling

### 3a. Wrap with `%w` when there is an underlying error

```go
// Correct — caller can use errors.Is / errors.As
return nil, fmt.Errorf("parsear certificado: %w", err)

// Wrong — loses the underlying error type
return nil, fmt.Errorf("parsear certificado: %v", err)
```

Use `%w` whenever you have an `err` value from a previous call. Use
`errors.New` or `fmt.Errorf` (without `%w`) only when creating a new error
with no underlying cause.

### 3b. Never silence errors with `_ =` in HTTP handlers

The pattern `_ = json.NewEncoder(w).Encode(v)` hides write failures.
Use the `writeJSON` helper that logs on error:

```go
func writeJSON(w http.ResponseWriter, status int, v any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    if err := json.NewEncoder(w).Encode(v); err != nil {
        log.Printf("writeJSON: %v", err)
    }
}
```

### 3c. No panics in production code

`panic` is reserved for programmer errors caught at init time (e.g. invalid
regex in a `var` block). Never panic in request-handling code.

---

## 4. `context.Context` — first parameter, always

Any function that performs network I/O, calls an external service, or may
block must accept `ctx context.Context` as its **first parameter**:

```go
// Correct
func (r *Remote) SignIntent(ctx context.Context, in Intent) (*Issued, error)
func (e *Engine) Execute(ctx context.Context, ...) (*Result, error)

// Wrong — no way to cancel from the caller
func (r *Remote) SignIntent(in Intent) (*Issued, error)
```

Pass `context.Background()` only in:
- Long-lived background goroutines (e.g. host-refresh ticker)
- `main()` startup paths

Never store a context in a struct field.

### Nil-interface pitfall

When a function returns a concrete pointer type (`*T`) that may be nil, and
the caller stores it in an interface field, assign the **interface type**
directly to avoid the non-nil interface with nil value trap:

```go
// Wrong — e.fetcher != nil is always true even when r == nil
func buildSigner(...) (signer.Signer, *signer.Remote, error) { ... }
e.fetcher = fetcher  // *signer.Remote(nil) stored as hostFetcher interface ≠ nil

// Correct — nil stays nil
func buildSigner(...) (signer.Signer, hostFetcher, error) { ... }
```

---

## 5. Interfaces — small and defined by the consumer

- Prefer single-method interfaces (`Signer`, `Notifier`, `hostFetcher`).
- Define interfaces in the package that **consumes** them, not the one that
  implements them.
- Avoid interface pollution: only define an interface when you have (or
  anticipate) more than one implementation, or when you need to break a
  dependency cycle.

---

## 6. Function length — 80 lines max

No function body should exceed **80 lines** (blank lines and comments
included). When a function grows past this limit:

1. Identify a cohesive sub-task within the function.
2. Extract it into a named helper with a descriptive name.
3. The helper must be independently testable or at least independently
   readable.

Check with:
```bash
awk '/^func /{if(fname!="" && lines>80) printf "%s: %s (%d lines)\n",FILENAME,fname,lines
             fname=$0; fstart=NR; lines=0} {lines++}
     END     {if(fname!="" && lines>80) printf "%s: %s (%d lines)\n",FILENAME,fname,lines
}' $(find . -name "*.go" -not -name "*_test.go" -not -path "*/vendor/*")
```

**Allowed exceptions:** `main()` startup functions and generated code.

---

## 7. Tests

### 7a. `t.Parallel()` in pure unit tests

Every `func TestXxx(t *testing.T)` that does not share global state, open
real network connections, or write to disk must call `t.Parallel()` as its
first statement:

```go
func TestRegistryCreateAndApprove(t *testing.T) {
    t.Parallel()
    // ...
}
```

This catches data races earlier and speeds up the test suite.

**Exclude from parallelisation:**
- Tests that spin up real HTTP servers (`httptest.NewServer`) with shared
  state
- Tests that write to the same temp directory
- Integration tests in `cmd/` that coordinate multiple components

### 7b. Race detector in CI

All test runs must pass with `-race`:

```bash
go test -race ./...
```

This is the gate that confirms concurrency correctness. A test that only
passes without `-race` is a broken test.

### 7c. Table-driven tests for exhaustive cases

When testing more than three variants of the same behaviour, use a
table-driven pattern:

```go
tests := []struct {
    name    string
    input   string
    want    bool
}{
    {"empty", "", false},
    {"valid", "deploy", true},
    {"with-flag", "--rm", false},
}
for _, tc := range tests {
    tc := tc // capture range variable
    t.Run(tc.name, func(t *testing.T) {
        t.Parallel()
        got := sudoUserAllowed(nil, tc.input)
        if got != tc.want {
            t.Errorf("got %v, want %v", got, tc.want)
        }
    })
}
```

---

## 8. Naming

| Thing | Convention | Example |
|---|---|---|
| Exported type | PascalCase noun | `PolicyTable`, `WireRequest` |
| Unexported type | camelCase noun | `liveSession`, `hostFetcher` |
| Interface | Noun or agent noun | `Signer`, `Notifier`, `hostFetcher` |
| Constructor | `New` prefix | `NewRegistry`, `NewEngine` |
| Boolean field/var | Positive assertion | `AllowSudo`, `IsError` |
| Error variable | `Err` prefix (sentinel) | `ErrUnknownHost` |
| Context parameter | Always `ctx` | `func f(ctx context.Context, ...)` |
| HTTP handler | verb + noun suffix | `handleSign`, `handleHosts` |

Avoid stutter: `signer.SignerConfig` → `signer.Config`. Avoid generic names
(`data`, `info`, `result`) unless the scope is tiny (< 5 lines).

---

## 9. Concurrency

### 9a. Keep mutexes unexported and close to the data they protect

```go
type Registry struct {
    mu    sync.Mutex        // protects items
    items map[string]*Approval
    ttl   time.Duration
}
```

Never export a mutex. Never embed a mutex in a type that is copied by value.

### 9b. Prefer `sync.RWMutex` for read-heavy caches

`Engine.mu` and `server.mu` protect caches that are read on every request
but written only during periodic reload. `RWMutex` avoids contention on the
read path.

### 9c. Goroutines must have a clear lifetime

Every `go func()` must have an obvious termination condition (context
cancellation, channel close, or ticker stop). Document it with a comment if
it is not obvious:

```go
// Runs until the ticker is stopped in Close().
go func() {
    t := time.NewTicker(interval)
    defer t.Stop()
    for range t.C { ... }
}()
```

---

## 10. Language

All source code must be in English. No exceptions for legacy code.

| Artifact | Language |
|---|---|
| Commit messages | English |
| Go comments (all files, new and existing) | English |
| `*.md` docs (README, API, USAGE, CHANGELOG, ARCHITECTURE, OPERATIONS, THREAT_MODEL, SECURITY, CONTRIBUTING) | English |
| `HANDOFF.md` | Spanish (internal session-handoff document) |

The rule is: **do not mix languages within a single function or doc block**.
When editing a legacy function that still has Spanish comments, translate them
in the same commit.

---

## Quick reference checklist

Before opening a PR or pushing to `main`:

```
[ ] gofmt -l . → no output
[ ] go vet ./... → no output
[ ] go test -race ./... → all pass
[ ] No function body > 80 lines (run awk check above)
[ ] All new I/O functions accept ctx context.Context as first param
[ ] No _ = json.NewEncoder(w).Encode(...) in handlers
[ ] New Test functions call t.Parallel() (if applicable)
[ ] Imports in three groups: stdlib / third-party / internal
[ ] fmt.Errorf uses %w when wrapping an existing error
[ ] CHANGELOG.md updated (see workflow in CONTRIBUTING.md)
```
