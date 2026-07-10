# Security Policy

## Supported versions

infrabroker follows `X.Y.Z` versioning (see [CONTRIBUTING.md](CONTRIBUTING.md)).
Only the latest `1.x` release on `main` receives security fixes.

| Version | Supported |
|---|---|
| latest `1.x` (`main`) | ✅ |
| older `1.x` tags | ❌ (upgrade to latest) |

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Report privately via one of:

- **GitHub Security Advisories** — "Report a vulnerability" on the repository's
  Security tab (preferred; keeps the report and fix coordinated).
- **Email** — `luisgf@luisgf.es` with subject `[infrabroker security]`.

Please include:

- affected component (`signer`, `control-plane`, a broker frontend, `broker-ctl`)
  and version/commit;
- a description of the issue and its impact (which trust boundary it crosses);
- reproduction steps or a proof of concept, if available;
- any suggested remediation.

You can expect an acknowledgement within a few days and a coordinated timeline
for a fix and disclosure. Please allow a reasonable window before any public
disclosure.

## Scope

infrabroker's security goals and **explicit non-goals** are documented in
[THREAT_MODEL.md](THREAT_MODEL.md). Reports about the following are known/by
design rather than vulnerabilities (but context is still welcome):

- absence of host-enforced `force-command` containment for **sessions**; `mode=exec`
  is broker-preflighted, but one-shot remains the strongest guarantee — gap #1;
- behavior guardrails being detection rather than containment — gap #2;
- absence of certificate revocation (KRL) — gap #3;
- leaving `callers` unset (unrestricted) rather than a non-empty default-deny
  table — gap #6;
- use of a PEM CA key in production (use AKV/HSM/KMS instead) — gap #7.

In-scope and high-value: anything that lets a **compromised broker** or
**compromised agent** exceed the operator's policy, mint or widen a certificate,
bypass the approval gate, forge an identity assertion the signer trusts, or
tamper with the audit chain undetected.

## Handling of secrets

- The `pki/` directory holds private keys and **must never be committed** (it is
  git-ignored). Treat any accidental commit as a key-rotation event.
- Audit seeds (`pki/*.seed`) must not be rotated casually — doing so breaks the
  hash/signature chain of existing logs.

## Redaction is best-effort

The optional `redact` config block (broker, signer, control plane) masks
secrets embedded in commands before they reach a **persistent or outbound
sink**: the audit log's free-text fields (`command`, `err`, `warning`,
`anomaly`), session recordings (`.cast`), and the approval notification payload
(log/webhook/Teams). A matched secret is replaced by `[REDACTED:<rule>]`;
masking happens **before** the audit entry is signed, so `broker-ctl audit
verify` is unaffected — and the original text is irrecoverable by design.

Know its limits before relying on it:

- **Regex matching is not DLP.** The built-in rules cover common shapes
  (password/token flags, `mysql -p<pass>`, `VAR=secret` assignments, URI
  `user:pass@`, `Authorization` headers, JWTs, AWS/GitHub/GitLab/Slack tokens,
  private-key blocks). A secret in an unanticipated format survives. Extend
  coverage with operator `patterns` (RE2; a `(?P<secret>...)` group masks only
  the secret and keeps the rest of the match as forensic context).
- **Recording output is chunked.** Session **input** is recorded one full
  command line per event, where patterns match reliably; **output** arrives in
  arbitrary chunks, so a secret split across two events can escape a pattern.
- **The decision path is never redacted, by design.** The signer authorizes,
  and the certificate `force-command` enforces, the original command; the mTLS
  approval UI (`/ui/approvals`) and `GET /v1/approvals` show the approver the
  original command so the human decides on real information. sshd's own logs on
  the target host are outside the broker's control.
- **False positives cost forensics.** The `[REDACTED:<rule>]` marker names the
  rule that fired; if a default rule masks something you need, disable the
  defaults (`disable_defaults`) and supply your own `patterns`.

The first line of defence remains unchanged: prefer credential-free
invocations (env files on the host, `~/.pgpass`, secret managers) over inline
secrets.
