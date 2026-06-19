# Handoff: SSH Broker con CA Efímera para Agentes de IA

> Documento de traspaso para retomar la sesión de desarrollo. Última
> actualización: 2026-06-19 (v1.16.0 — **pasada de rendimiento y mantenibilidad**:
> estado del BehaviorTracker ahora **acotado** (eviction LRU+TTL de sujetos y cap
> de cardinalidad host/comando — corrige fuga de memoria / DoS lento); **un único
> evaluador** de command_policy (`PolicySet`), borrado `CommandPolicy.Decide` y
> `cmdpolicy.go` normalizado a inglés; cache de host keys parseadas; `shellQuote`
> O(n²)→O(n); pool del parser POSIX-sh + KeyID con `strings.Builder`; ciclo de vida
> de la goroutine de host-refresh (para en `Close`). Backlog de los ítems diferidos
> en §«Backlog de rendimiento y mantenibilidad».
> v1.15.0 — **CLI: `--version` en los seis binarios** y
> **`--config` como flag global de `broker-ctl`**, antes del subcomando. Versión
> corta por defecto y detallada con `--verbose` (`internal/version` ya existía,
> inyectado desde el tag git por el Makefile; ahora se cablea a la CLI). **Cambio
> incompatible**: `broker-ctl --config f host list` sustituye a
> `broker-ctl host list --config f`; el `--config` por subcomando se eliminó.
> v1.14.0 — **políticas de comando componibles por
> grupo**: librería con nombre (`command_policies`) + `group_command_policies`; la
> política efectiva de un host es la composición aditiva (unión de allows, deny
> gana, `require_approval` unión, `shell_parse` OR) de su `command_policy` inline y
> las de todos sus grupos; grupo reservado `_default` aplica a todos los hosts;
> `broker-ctl policy explain` para inspeccionar la composición offline.
> v1.13.0 — **revisión adversarial (red-team) de
> seguridad** en rama `fix/security-redteam-audit`: cierra el bypass del firewall
> de comandos vía `role=bastion` en hosts `allow_as_bastion`+`command_policy`
> (HIGH); el bypass de RBAC per-usuario donde un deny-all (`[]grupos`) colapsaba a
> nil/sin-filtro por `omitempty` en el wire (HIGH); `GET /v1/hosts` que ignoraba
> `allowed_callers`; la aprobación humana que ocultaba `sudo`; inyección de
> caracteres de control en el KeyID del cert; verificación de auditoría entre
> ficheros rotados (`broker-ctl audit verify --all`); `host add --force` que
> borraba el `command_policy` entero; y el modo local que marcaba `allow_as_bastion`
> en todos los hosts. +10 tests de regresión.
> v1.12.7 — última tanda de la revisión de fallos de lógica (nbf/clock-skew OIDC,
> última línea sin `\n` en shells, mapeo de errores HTTP del broker, reload que
> verifica el PID, grabaciones con tope, versión de build desde el tag git).
> v1.12.6 cerró la segunda tanda; v1.12.5 los dos bypasses del firewall del signer.
> Estado y pendientes; el resto de la documentación está enlazada abajo.

## Índice de documentación

| Documento | Contenido |
|---|---|
| [README.md](README.md) | Visión general, comparativa, configuración pública |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Diagrama, flujo de petición, **decisiones de diseño**, elevación sudo |
| [OPERATIONS.md](OPERATIONS.md) | Runbook: arranque, alta de hosts, hot-reload, broker-ctl, PKI, configs |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Actores, fronteras de confianza, **gaps explícitos** |
| [SECURITY.md](SECURITY.md) | Política de divulgación de vulnerabilidades |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Ramas, versionado X.Y.Z, checklist pre-commit, idioma |
| [CODING_STYLE.md](CODING_STYLE.md) | Reglas Go con verificación mecánica |
| [API.md](API.md) | Referencia de endpoints HTTP de todos los servicios |
| [USAGE.md](USAGE.md) | Guía de las 5 tools MCP para el modelo |

---

## Qué es (resumen)

Un modelo de IA necesita ejecutar comandos en hosts Linux por SSH sin recibir
nunca una credencial reutilizable. El **broker** genera por operación un par
Ed25519 efímero en memoria, obtiene un certificado SSH de corta duración firmado
por una CA, abre la conexión, y descarta el material; el modelo solo recibe
`stdout/stderr/exit_code`.

En **modo remoto (producción)** un servicio aparte (`cmd/signer`) custodia la
clave CA y la política; un broker comprometido no puede robar la llave. El
frontend `cmd/mcp-broker-http` expone el broker por HTTP con OAuth2/OIDC para
despliegues multiusuario. El detalle del *por qué* está en
[ARCHITECTURE.md](ARCHITECTURE.md); el modelo de amenazas y sus límites en
[THREAT_MODEL.md](THREAT_MODEL.md).

---

## Estado actual del código

```
ssh-broker/
├── cmd/
│   ├── mcp-broker/           # servidor MCP (stdio) — frontend local
│   ├── mcp-broker-http/      # servidor MCP remoto (Streamable HTTP + OAuth2/OIDC)
│   ├── signer/               # servicio de firma externo (HTTPS+mTLS) — única custodia CA
│   ├── control-plane/        # PEP entre broker y signer (aprobación + behavior); sin clave CA
│   ├── broker-ctl/           # CLI de gestión de signer.json + audit + approvals
│   └── broker/               # frontend HTTP+mTLS alternativo (one-shot)
├── internal/
│   ├── ca/                   # loader (PEM/AKV), akv, sign (BuildAndSign), GenerateEphemeralKey
│   ├── signer/               # Signer/Local, PolicyTable.Resolve, cmdpolicy, remote (Wire*)
│   ├── broker/               # Engine, Caller, ExecOptions, sessionManager, session
│   ├── mcpserver/            # New + Register (5 tools compartidas stdio/HTTP)
│   ├── oauth/                # Verifier OIDC (JWKS, fail-closed groups/iat)
│   ├── ssh/                  # Dial/ExecOnce/Run, OpenShell/OpenShellPTY
│   ├── audit/                # log append-only encadenado y firmado (Ed25519)
│   ├── control/              # approval Registry, notifier, teams, behavior tracker
│   ├── recording/            # Recorder ASCIIcast v2
│   ├── httpserve/            # RunTLS: serve + graceful shutdown (SIGINT/SIGTERM)
│   └── auth/                 # mtls (ServerTLSConfig, ClientTLSConfig, CallerCN)
├── lab/                      # labs e2e (run_*.sh) + mcpclient
├── pki/                      # PKI local (NO git) — ver OPERATIONS.md §5
├── deploy/sshd_config.snippet
├── config.json / config.example.json
├── signer.json / signer.example.json
├── control-plane.example.json
└── signer.sh
```

**Compilación y tests:** `go build ./...` ✅ · `go vet ./...` ✅ ·
`go test -race ./...` ✅ (193 casos en 11 paquetes, sin data races).

**Binarios:** `~/bin/{mcp-broker,mcp-broker-http,signer,broker-ctl}`.
**MCP registrado:** `~/.claude.json` / config de OpenCode.

---

## Pendientes para producción

### Alta prioridad
- [ ] **Clave CA en HSM/KMS** para PEM local (AKV ya soportado, v1.11.0). Seam
  listo: `ca.LoadCAFromPEM` → `ssh.NewSignerFromSigner(kmsClient)`.
- [ ] **Rate limiting por CN de broker** en el signer (gap #4 del threat model).
- [ ] **Command firewall en sesiones exec** vía dry-run por comando (gap #1).

### Media prioridad
- [ ] **KRL (revocación)**: `/v1/revoke` por serial + `RevokedKeys` en sshd (gap #3).
- [ ] **Redacción de secretos** en audit logs y grabaciones: hoy los comandos se
  guardan verbatim (un `mysql -psecret` queda en texto plano). Lista de patrones
  de enmascarado configurable (gap #8 del threat model).
- [ ] **Audit fail-closed (opcional)**: hoy si falla el `Append` la operación
  continúa; toggle para bloquear emisión/ejecución sin traza (gap #9).
- [ ] **Logs a almacenamiento WORM** (S3/GCS/Loki/SIEM).
- [ ] **Sesiones/aprobaciones multi-instancia**: externalizar estado a Redis (gap #5).
- [ ] **`default_deny` en `callers`**: hoy CN ausente = sin restricción (gap #6).
- [x] **Validación de config en modo local del broker** (v1.14.0): `engine.buildSigner`
  ahora compila y valida vía `signer.CompileHostPolicies` (regex de `command_policy`,
  modos, refs de grupo, jumps, exclusión bastión), igual que `cmd/signer` en `buildState`.
- [ ] **Labs e2e**: sudo+PTY (`run_mcp_lab.sh`) y HTTP+OAuth (IdP OIDC local).

### Baja prioridad
- [ ] **Hosts dinámicos** (`allow_dynamic_hosts`): el modelo suministra addr/user/host_key.
- [ ] **Dashboard de auditoría** correlado por serial.
- [ ] **Anclaje externo del head de auditoría** (sidecar/WORM): `broker-ctl audit
  verify --all` (v1.13.0) ya detecta el borrado de un segmento rotado y el truncado
  del fichero activo cuando existen segmentos; queda el caso residual de truncar el
  ÚNICO fichero sin rotaciones (indistinguible de una instalación nueva sin un head
  persistido fuera del log).
- [ ] **`allowed_sudo_commands` por host** como segunda capa.
- [ ] **Rutas `/home/luislgf` en config.json/signer.json** mientras la máquina es
  macOS (`/Users/luislgf`) — revisar si son de la máquina Linux o están rotas.

Historial de completados: ver [CHANGELOG.md](CHANGELOG.md).

---

## Backlog de rendimiento y mantenibilidad

Hallazgos de la auditoría de rendimiento/mantenibilidad (v1.16.0) **diferidos**
para evaluación posterior. Los ítems de alta/media prioridad de esa auditoría
(BehaviorTracker acotado, evaluador único de command_policy, cache de host keys,
`shellQuote` O(n²), pool del parser, ciclo de vida de la goroutine de refresh) ya
están implementados en v1.16.0; lo que queda es esto:

- [ ] **P3 — `audit.Append` hace `fsync` bajo el mutex** (`internal/audit/log.go:174-205`),
  en la ruta síncrona de cada petición: serializa todas las peticiones auditadas
  tras un sync de disco (techo de throughput del sistema). **Enfoque preferido:
  solo micro-optimizar** (no cambiar el modelo de durabilidad): quitar el `Stat()`
  por-append rastreando el tamaño en memoria (`log.go:144,178`) y hacer un único
  `json.Marshal` por entrada (hoy son dos, `log.go:189,196`). Mantener el `fsync`
  síncrono. No introducir modo async salvo decisión explícita.
- [ ] **M1b — `buildHops`/`buildHopsWithPrefix` duplicados** (~50 líneas casi
  idénticas, `internal/broker/engine.go`): `buildHops` puede ser un wrapper fino
  sobre `buildHopsWithPrefix` (descartando el prefijo). Riesgo de drift en la
  construcción de la cadena de certs.
- [ ] **M3 — Propagación de `context`**: `SessionExec(_ context.Context, …)`
  descarta el ctx del llamante (`internal/broker/session.go`), así que una
  desconexión del cliente no cancela un comando de sesión en vuelo (modo exec sin
  timeout). Además `ca.BuildAndSign` afirma en su doc que propaga el ctx al firmante
  AKV, pero `akvSigner.Sign` crea su propio `context.Background()` con timeout fijo
  de 10s (`internal/ca/akv.go:101`, `sign.go:75-76,121`) — cablear el ctx o corregir
  el comentario.
- [ ] **M4 — Capa de validación de config + god-structs**: `LoadConfig` no valida
  combinaciones mutuamente excluyentes (`CAKey`/`CAKeys` vs `Signer`; `CommandPolicy`
  inline vs `Policies` compilado), que fallan tarde dentro de `buildSigner`. Añadir
  `Validate()` temprano. `broker.Config` (~25 campos) y `signer.HostPolicy` (~20,
  con `MaxTTL`/`MaxTTLSeconds` redundantes) mezclan conexión/emisión/cache: valorar
  dividir por responsabilidad.
- [ ] **M5 — Limpiezas menores**: `elevationLabelFromPrefix` es código muerto
  (solo lo usa un test, `internal/broker/session.go:476-490`); extraer
  `internal/shellutil` para el quoting hoy duplicado entre `broker` y `signer`;
  helper para construir `audit.Entry` (boilerplate repetido); constantes operativas
  hardcoded (`session.go:21,24-29`, geometría de grabación) → config; `newSessionID`
  ignora el error de `rand.Read` en un identificador de seguridad (`session.go:492-495`).
- [ ] **Normalización ES→EN amplia**: nombres de tests y comentarios en español
  por todo el repo (el código de producción de `cmdpolicy.go` ya está en inglés;
  el inglés debe prevalecer en lo nuevo).
- [ ] **Estado multi-instancia (HA)**: el registro de aprobaciones y el
  BehaviorTracker viven en memoria (una sola instancia de control-plane). Sembrar
  una interfaz (memoria ahora, Redis después) para despliegues HA.

---

## Estado del plan de pruebas (v1.12.3)

195 casos en 11 paquetes; todos pasan con `go test -race ./...`.

| Paquete | Casos | Notas |
|---|---|---|
| `internal/ca` | 23 | sign, bastion, TTL; LoadCA/LoadGroupCAs; akvSigner EC+RSA |
| `internal/signer` | 47 | policy, RBAC, sudo, PTY, dry-run, approval gate, multi-CA, newlines, config validation, KeyID format |
| `internal/control` | 35 | approval registry (+ purge), behavior tracker (+ eviction/cardinality caps), Teams notifier |
| `internal/oauth` | 9 | valid/expired/aud/sig/claim + fail-closed (groups/iat, token age) |
| `internal/audit` | 11 | cadena hash, firmas Ed25519, restoreChain, maybeRotate |
| `internal/broker` | 28 | sessionManager, ownership, newlines, filtro grupos, host-key cache, refresh goroutine lifecycle |
| `internal/recording` | 8 | cabecera ASCIIcast, eventos, deltas, concurrencia, close |
| `cmd/control-plane` | 8 | forwarding, approval flow, behavior, ownership |
| `cmd/signer` | 1 | resolveCaller (4 sub-tests); handlers indirectos vía control-plane |
| `cmd/mcp-broker-http` | 2 | OAuth auth, 401, RFC 9728 |
| `cmd/broker-ctl` | 32 | verifyLog, audit helpers; ca-keys/callers round-trip; policy preservation; parseGlobalFlags (--config global, --version) |
| `internal/version` | 4 | String (injected/fallback), Detailed (build provenance), vcsInfo |

### Gaps de cobertura conocidos
- `cmd/signer/main.go` handlers HTTP: solo `resolveCaller` con test directo (el
  resto se ejercita vía el stub de `cmd/control-plane`).
- `internal/ssh` con sshd real: el protocolo de marcadores de `ShellSession`
  requiere `gliderlabs/ssh` o un sshd embebido (hoy solo unitarios).
- `cmd/broker-ctl`: subcomandos completos sin tests de integración (requieren
  ficheros reales o mock de `exec.Command`); helpers internos sí cubiertos.

---

## Notas para retomar

1. **El signer debe estar corriendo** antes de arrancar el broker / abrir el MCP.
   `./signer.sh start`. Ver [OPERATIONS.md §1](OPERATIONS.md#1-starting-the-system).
2. **`hosts_refresh_seconds: 30`** es valor de desarrollo; en producción ≥ 300.
3. Tras editar `signer.json`: `broker-ctl reload` (SIGHUP local o `POST /v1/reload`).
   El broker NO necesita reinicio.
4. **Pendiente operativo de Fase B/C**: generar el cert del control plane
   (`CN=control-plane-1`) firmado por `pki/mtls_ca.crt` y añadirlo a
   `trusted_forwarders` del signer.
5. Antes de cada commit: seguir el checklist de
   [CONTRIBUTING.md](CONTRIBUTING.md) (docs vivas) y el de
   [CODING_STYLE.md](CODING_STYLE.md) (gofmt/vet/test).
