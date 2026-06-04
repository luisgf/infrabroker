# Changelog

## [v1.1.0] - 2026-06-04

### Added
- CLI `broker-ctl` (`cmd/broker-ctl`) para gestión de `signer.json` sin editar JSON a mano
  - `host add`: añade o actualiza un host con todos sus parámetros; `--scan` ejecuta `ssh-keyscan` automáticamente
  - `host list`: tabla formateada de hosts con addr, user, principal, TTL, sudo, PTY, groups
  - `host remove`: elimina un host de la configuración
  - `reload`: SIGHUP si el signer corre en local (detecta `signer.pid`), POST `/v1/reload` mTLS como fallback
  - Preserva campos `_comment` y anotaciones del JSON al escribir (escritura atómica vía rename)

## [v1.0.0] - 2026-06-03

### Added
- Broker SSH con generación de claves Ed25519 efímeras en memoria (nunca tocan disco)
- Servicio de firma externo (`cmd/signer`) con custodia exclusiva de la clave CA SSH vía HTTPS+mTLS
- Interfaz MCP stdio (`cmd/mcp-broker`): herramientas `ssh_execute`, `ssh_session_open`, `ssh_session_exec`, `ssh_session_close`, `ssh_list_servers`
- Soporte de ProxyJump (cadenas de salto a través de bastión)
- Elevación `sudo NOPASSWD` policy-gated en el signer: `allow_sudo`, `allowed_sudo_users`, sanitización anti-inyección
- Sesiones persistentes con tres modos: `exec`, `shell` (sin PTY) y `pty` (con PTY)
- Soporte de PTY en one-shot y sesiones: `allow_pty` por host, `permit-pty` en el certificado
- Recarga en caliente de `signer.json` sin reinicio: `SIGHUP` y `POST /v1/reload` (mTLS, gated por `reload_callers`)
- Auditoría triple firmada y encadenada por `serial` (Ed25519 + SHA-256): signer, broker y sshd correlados
- RBAC por grupos: campo `groups` por host y sección `callers` en `signer.json`; `GET /v1/hosts` filtra por grupos del caller, `POST /v1/sign` rechaza hosts fuera del grupo antes de `Resolve()`
- Frontend HTTP+mTLS alternativo (`cmd/broker`) para uso one-shot sin MCP
- PKI local generada: CA SSH Ed25519, CA mTLS, certs servidor/cliente, semillas de auditoría
- Scripts de laboratorio e2e: `lab/run_mcp_lab.sh`, `lab/run_signer_lab.sh`
