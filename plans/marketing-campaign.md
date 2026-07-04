# Campaña de visibilidad — infrabroker

> Estado vivo de la campaña. Creado 2026-07-04 junto al renombrado
> ssh-broker → infrabroker (v1.36.0). Marcar cada acción al completarla.

## Posicionamiento

**Tagline (EN):** *Infrastructure access broker for AI agents — SSH &
Kubernetes. The model never touches a credential.*

**Elevator pitch (EN):** Every MCP server that gives an agent SSH or cluster
access hands it a real credential — a key in the config, a kubeconfig on disk —
and one prompt injection away from exfiltration. infrabroker inverts that: the
agent requests an *action*; a separate signer checks policy and mints a
credential that exists only for that operation (an ephemeral scope-limited SSH
certificate, or a short-lived bound ServiceAccount token); the broker executes
and returns only the output. Per-command policy with dry-run, human-in-the-loop
approvals, behavioral guardrails, session recording, and an Ed25519-chained
audit log. A handful of self-hosted Go binaries, GPLv3.

**Diferenciadores frente a lo listado en awesome-mcp-servers** (verificado
2026-07-04): todos los MCP de SSH existentes (tufantunc/ssh-mcp,
blakerouse/ssh-mcp, bvisible/mcp-ssh-manager, faizbawa/mcp-remote-ssh…) usan
credenciales estáticas o delegan en el agente local; ninguno tiene CA efímera,
signer separado, firewall por comando con AST, ni aprobación humana. El más
cercano en mensaje (mcp-remote-ssh, "secret-safe") solo oculta secretos en
tránsito. En k8s, los MCP existentes montan el kubeconfig entero.

## Fase 0 — Base (este PR)

- [x] Renombrado completo a `infrabroker` (module path, dist, CI, docs, deploy).
- [x] README reposicionado: SSH **y Kubernetes** en cabecera, badges, k8s en
      feature table.
- [x] `server.json` (manifest MCP Registry, requiere Fase 2 para publicar).
- [ ] Topics y About del repo (gh repo edit — se hace al renombrar el repo).
- [ ] Social preview image del repo (Settings → Social preview; diagrama del
      README sobre fondo oscuro, 1280×640).

## Fase 1 — Descubribilidad (semana 1)

- [ ] **PR a [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers)**
      — sección *Command Line / SSH*. Entrada lista (formato de la lista:
      lenguaje 🏎️=Go, ámbito 🏠=local, ☁️=cloud, SO):

      ```markdown
      - [luisgf/infrabroker](https://github.com/luisgf/infrabroker) 🏎️ 🏠 ☁️ 🐧 🍎 - SSH & Kubernetes access broker where the model never touches a credential: a separate signer mints per-operation ephemeral SSH certificates and bound ServiceAccount tokens, with per-command allow/deny/approval policy (POSIX-sh AST), dry-run, human-in-the-loop approvals, session recording and an Ed25519-chained audit log. Self-hosted Go binaries.
      ```

- [ ] **MCP Registry oficial** (`registry.modelcontextprotocol.io`): requiere
      el paquete OCI de Fase 2. Pasos: `brew install mcp-publisher` →
      `mcp-publisher login github` → `mcp-publisher publish` (usa
      `server.json`). Los agregadores (Glama, PulseMCP) lo indexan desde aquí.
- [ ] **Submissions directas**: [glama.ai](https://glama.ai/mcp/servers)
      (indexa desde GitHub; comprobar ficha y reclamarla),
      [mcp.so](https://mcp.so) (issue/PR en su repo),
      [pulsemcp.com](https://www.pulsemcp.com) (formulario submit).
- [ ] **Docker MCP Catalog** (`docker/mcp-registry`, PR): opcional, tras Fase 2.

## Fase 2 — Fricción de instalación (semanas 1–2)

- [ ] **goreleaser**: binarios linux/darwin × amd64/arm64 adjuntos a cada
      release (`.goreleaser.yml` + job en release.yml). Mantener el tarball
      actual para `deploy/install.sh`.
- [ ] **Imagen OCI** `ghcr.io/luisgf/infrabroker` (mcp-broker como entrypoint,
      tag = versión) — prerequisito del MCP Registry.
- [ ] Documentar `go install github.com/luisgf/infrabroker/cmd/mcp-broker@latest`
      en README/Quickstart.
- [ ] **One-click installs** en README: bloque `claude mcp add infrabroker …`,
      deeplink de Cursor, badge "Install in VS Code".

## Fase 3 — Lanzamiento y contenido (cuando Fase 1–2 estén)

- [ ] **Demo GIF/asciinema** para el README: Claude pidiendo `ssh_execute`
      (se ve policy check + cert efímero en el log del signer + solo stdout al
      modelo) y un `k8s_get` con dry-run. Grabar con `asciinema rec` +
      `agg` para el GIF. Sin demo visual, el resto de la fase rinde menos.
- [ ] **Show HN** (martes–jueves, 14:00–17:00 CET). Borrador:

      > **Title:** Show HN: Infrabroker – SSH and Kubernetes for AI agents,
      > without giving them credentials
      >
      > **Body:** I run AI agents (Claude Code, mostly) against my own servers
      > and clusters. Every MCP server I found hands the agent a real
      > credential — an SSH key in the config, a kubeconfig on disk. One prompt
      > injection and that key is in the model's context, and anywhere else.
      >
      > Infrabroker is a self-hosted broker where the model never touches a
      > credential. The agent requests an action; a separate signer checks
      > policy and mints a credential for that single operation — an ephemeral,
      > scope-limited SSH certificate (TTL of minutes, source-address pinned,
      > force-command for one-shots) or a short-lived bound ServiceAccount
      > token via the TokenRequest API. The broker executes and returns only
      > stdout/stderr. Keys live in RAM and are discarded.
      >
      > On top of that: a per-command firewall (POSIX-sh AST, allow/deny/
      > require_approval, dry-run), human-in-the-loop approvals, behavioral
      > guardrails, ASCIIcast session recording, and an append-only
      > Ed25519-chained audit log correlated across signer, broker and sshd.
      >
      > It's a handful of Go binaries, GPLv3. The threat model — including
      > what it deliberately does NOT defend — is documented:
      > https://luisgf.github.io/infrabroker/THREAT_MODEL/
      >
      > https://github.com/luisgf/infrabroker
- [ ] **Reddit**: r/mcp y r/ClaudeAI (ángulo: "your SSH MCP is one prompt
      injection away from leaking your keys — this one can't"), r/selfhosted
      (ángulo self-hosted PAM ligero). Adaptar, no cross-postear idéntico.
- [ ] **Discord de MCP** (canal showcase) y foro de Anthropic devs.
- [ ] **X/LinkedIn** (perfil personal): hilo corto con el diagrama y el GIF.
- [ ] **Post técnico** en el blog/docs: "Giving AI agents SSH access without
      giving them credentials" — el problema, el diseño signer/broker, por qué
      certificados y no llaves, el firewall AST, qué NO defiende. Sirve de
      landing para HN/Reddit y de contenido enlazable.

## Métricas (revisar mensualmente)

Stars/forks/traffic (Insights → Traffic), instalaciones vía registry (si
publican stats), issues/PRs externos. Baseline 2026-07-04: 1 star, 0 forks.

## Registrado / pendiente de registrar

- Dominios: `infrabroker.io` / `infrabroker.dev` libres a 2026-07-04 (~12–30
  €/año). Si se compra, configurar como custom domain de GitHub Pages y
  actualizar `site_url`, About y server.json.
- Docker Hub: namespace `infrabroker` libre; no urge (usamos ghcr.io).
