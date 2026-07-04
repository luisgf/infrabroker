# Containers

infrabroker ships an official OCI image and a self-contained compose demo.
Containers are the fastest way to **evaluate** the broker and the vehicle for
MCP-client installs from the registry; they are **not** the recommended
production layout (see the warning at the end).

## The official image

```
ghcr.io/luisgf/infrabroker:<X.Y.Z>     # matches each release tag
ghcr.io/luisgf/infrabroker:latest
```

- **Contents:** the six release binaries (`signer`, `broker`, `broker-ctl`,
  `mcp-broker`, `mcp-broker-http`, `control-plane`) under `/usr/local/bin/`,
  bit-identical to the release archives (the image copies the prebuilt
  binaries; nothing is compiled in the Dockerfile).
- **Base:** `distroless/static` — CA roots for outbound TLS (signer, OIDC,
  Azure Key Vault), a `nonroot` user (uid 65532), and **no shell or package
  manager**. The SSH client is pure Go; no `openssh` inside.
- **Entrypoint:** `mcp-broker` (the stdio MCP frontend — what an MCP client
  launches). Arguments after the image name go to `mcp-broker`.
- **Architectures:** `linux/amd64`, `linux/arm64`.

```bash
docker run --rm ghcr.io/luisgf/infrabroker -version
```

## stdio MCP frontend in a container

Mount a directory with your `config.json` (and the PKI material it points to)
and pass `-i` so the MCP client owns stdin/stdout:

```bash
docker run -i --rm -v /secure/path:/config \
  ghcr.io/luisgf/infrabroker -config /config/config.json
# podman is a drop-in replacement (rootless works):
podman run -i --rm -v /secure/path:/config:Z \
  ghcr.io/luisgf/infrabroker -config /config/config.json
```

Register it in Claude Code:

```bash
claude mcp add infrabroker -- docker run -i --rm \
  -v /secure/path:/config ghcr.io/luisgf/infrabroker -config /config/config.json
```

Note that the container needs network reachability to your signer and to the
managed hosts. For personal use the native binary is simpler (no mounts, no
network namespace to think about) — see the [Quickstart](index.md).

## Running the other binaries

Everything else in the image is selected with `--entrypoint`:

```bash
docker run --rm --entrypoint /usr/local/bin/signer \
  -v /secure/path:/config -p 9443:9443 \
  ghcr.io/luisgf/infrabroker -config /config/signer.json
```

## Try it in 5 minutes (compose demo)

`examples/compose/` in the repository spins up the full remote-signing
topology against a **toy target** — nothing touches real servers:

| Service | What it is |
|---|---|
| `pki-init` | One-shot provisioner: SSH CA, mTLS PKI, service configs into a volume |
| `signer` | Holds the CA key and the policy (only `broker-1` may reach host `demo`) |
| `sshd` | Toy target host trusting the demo CA (`TrustedUserCAKeys`), user `demo` |
| `broker` | HTTP+mTLS frontend — runs **without** the CA key (remote signing) |

```bash
git clone https://github.com/luisgf/infrabroker && cd infrabroker/examples/compose
docker compose up --build -d        # or: podman compose up --build -d
curl -s http://127.0.0.1:9160/healthz && curl -s http://127.0.0.1:9180/healthz
```

Run a command through the broker (the `sshd` container carries `curl` and the
demo agent's client certificate, so it doubles as the "agent" for testing):

```bash
docker compose exec sshd curl -s \
  --cacert /demo/pki/agents_ca.crt \
  --cert /demo/pki/agent.crt --key /demo/pki/agent.key \
  https://broker:8443/v1/ssh_run -d '{"host":"demo","command":"id"}'
# {"stdout":"uid=1000(demo) ...","stderr":"","exit_code":0,"serial":...}
```

What just happened: the broker generated an ephemeral Ed25519 key in RAM,
asked the signer for a certificate scoped to `host:demo` with a TTL of
minutes, opened the SSH connection itself and returned only the output. See
the same `serial` on both sides of the trust boundary:

```bash
docker compose exec sshd sh -c 'tail -1 /demo/state/signer_audit.log'   # outcome: issued
docker compose exec sshd sh -c 'tail -1 /demo/state/broker_audit.log'   # outcome: executed
```

Policy is default-deny — an undeclared host is refused:

```bash
docker compose exec sshd curl -s --cacert /demo/pki/agents_ca.crt \
  --cert /demo/pki/agent.crt --key /demo/pki/agent.key \
  https://broker:8443/v1/ssh_run -d '{"host":"prod-db","command":"id"}'
# unknown host: "prod-db"  (404)
```

Connect Claude Code to the demo over stdio (the provisioner also wrote an
`mcp.json` for this):

```bash
claude mcp add infrabroker-demo -- docker run -i --rm \
  --network infrabroker-demo -v infrabroker-demo-state:/demo \
  ghcr.io/luisgf/infrabroker -config /demo/mcp.json
```

Then ask the model to run something on `demo` (`ssh_execute`) — and watch the
audit log grow. Tear everything down (PKI and state included):

```bash
docker compose down -v
```

Re-running `up` re-provisions from scratch; `up` over a live volume is a no-op
(the provisioner is idempotent).

## Podman notes

The demo avoids Docker-only features on purpose: explicit project, network and
volume names (`infrabroker-demo`, `infrabroker-demo-state`) so the stdio
one-liner works identically, and healthcheck/`depends_on` conditions from the
compose spec. It requires either `podman compose` delegating to the
docker-compose provider or `podman-compose` recent enough to support
`depends_on: condition:`. Rootless podman works — nothing in the demo needs
privileged ports on the host.

!!! warning "Demo ≠ production"
    The demo trades away everything the hardened deployment is about: all
    material lives in one volume, services share it, TTLs and cert lifetimes
    are short but the PKI is self-signed and disposable. Production runs each
    service as its own system user via `deploy/install.sh` (systemd), with
    per-service PKI directories and optionally the CA key in Azure Key Vault —
    see [Operations](OPERATIONS.md) and the
    [deploy README](https://github.com/luisgf/infrabroker/tree/main/deploy).

!!! note "Kubernetes: target vs runtime"
    infrabroker already **brokers access to** Kubernetes clusters (the `k8s_*`
    tools: per-operation bound ServiceAccount tokens, default-deny policy —
    see [Tool usage §10](USAGE.md#10-kubernetes-tools-k8s_)). Running the
    broker itself **inside** a cluster (manifests/Helm) is deliberately not
    shipped yet; it is on the roadmap and needs its own answer for CA-key
    custody in-cluster. The image works fine as a building block if you roll
    your own.
