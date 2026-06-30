# Security Policy

## Supported versions

ssh-broker follows `X.Y.Z` versioning (see [CONTRIBUTING.md](CONTRIBUTING.md)).
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
- **Email** — `luisgf@luisgf.es` with subject `[ssh-broker security]`.

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

ssh-broker's security goals and **explicit non-goals** are documented in
[THREAT_MODEL.md](THREAT_MODEL.md). Reports about the following are known/by
design rather than vulnerabilities (but context is still welcome):

- absence of a command firewall in **sessions** (one-shot only) — gap #1;
- behavior guardrails being detection rather than containment — gap #2;
- absence of certificate revocation (KRL) — gap #3;
- `callers` being default-open for unlisted CNs — gap #6;
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
