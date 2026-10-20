# infrabroker demo (docker/podman compose)

Self-contained demo: a signer holding an ephemeral SSH CA, a control plane
in front of it, a toy sshd target and a broker that executes commands with
per-operation certificates — no real servers touched, everything discarded
with `compose down -v`.

| Service | Role |
|---|---|
| `pki-init` | One-shot: generates the SSH CA, mTLS PKI and the service configs into the `infrabroker-demo-state` volume |
| `signer` | Holds the CA key and the issuance policy (`127.0.0.1:9160` monitor) |
| `control-plane` | Approval gate + behaviour guardrails in front of the signer; **the broker's signer endpoint** — `broker.json` points at `https://control-plane:7443`, not at the signer (`127.0.0.1:7443` mTLS approvals API + UI, `127.0.0.1:9170` monitor) |
| `sshd` | Toy target host trusting the demo CA, user `demo` |
| `broker` | HTTP+mTLS frontend, `POST /v1/ssh_run` (`127.0.0.1:8443` API, `127.0.0.1:9180` monitor) |

The control plane holds no CA key: it forwards signing to the signer as
`control-plane-1` and holds `require_approval` commands (`systemctl restart …`
in the demo policy) for a human decision, with a self-approval (four-eyes)
guard. `prompt-injection-demo.sh` exercises exactly that path in its last
scenario, approving through `https://control-plane:7443/v1/approvals/<id>`.

```bash
docker compose up --build -d      # or: podman compose up --build -d
```

The full walkthrough (verification curl, audit-chain inspection, connecting
Claude Code over stdio, cleanup) lives in the documentation:
[Containers](../../docs/CONTAINERS.md) · https://luisgf.github.io/infrabroker/CONTAINERS/

**This is a demo, not a production layout** — production deployment is
`deploy/install.sh` (systemd, one system user per service, optional Azure Key
Vault or ssh-agent/HSM CA custody). See [deploy/README.md](../../deploy/README.md).
