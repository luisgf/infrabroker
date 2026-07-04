# infrabroker demo (docker/podman compose)

Self-contained demo: a signer holding an ephemeral SSH CA, a toy sshd target
and a broker that executes commands with per-operation certificates — no real
servers touched, everything discarded with `compose down -v`.

```bash
docker compose up --build -d      # or: podman compose up --build -d
```

The full walkthrough (verification curl, audit-chain inspection, connecting
Claude Code over stdio, cleanup) lives in the documentation:
[Containers](../../docs/CONTAINERS.md) · https://luisgf.github.io/infrabroker/CONTAINERS/

**This is a demo, not a production layout** — production deployment is
`deploy/install.sh` (systemd, one system user per service, optional Azure Key
Vault CA custody). See [deploy/README.md](../../deploy/README.md).
