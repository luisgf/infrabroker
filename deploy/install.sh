#!/usr/bin/env bash
# ssh-broker production installer (idempotent). Run as root ON THE TARGET HOST.
#
# Installs the selected services following the reference layout of the systemd
# units in deploy/systemd/:
#
#   /usr/local/bin/{signer,control-plane,mcp-broker-http,broker-ctl}
#   /etc/ssh-broker/            configs (0750 root:ssh-broker)
#   /etc/ssh-broker/pki/        mTLS certs and keys (0750; keys 0640)
#   /var/lib/ssh-broker/<svc>/  state and audit logs (created by systemd)
#
# Existing real configs are NEVER overwritten; *.example.json references are
# refreshed on every run. Re-running after an upgrade replaces binaries and
# units only.
#
# Usage:
#   ./install.sh [--services "signer control-plane mcp-http"]
#                [--src DIR]      # tree with bin/ and configs (default: auto)
#                [--bindir DIR]   # default /usr/local/bin
#                [--enable]       # systemctl enable the installed units
#                [--start]        # implies --enable, also starts them
#
# The signer must be reachable before control-plane/mcp-http start, and the
# choice of CA custody (pem vs akv) is made in signer.json — see
# deploy/README.md before starting anything.

set -euo pipefail

SERVICES="signer control-plane mcp-http"
BINDIR="/usr/local/bin"
ETCDIR="/etc/ssh-broker"
SRC=""
ENABLE=0
START=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --services) SERVICES="$2"; shift 2 ;;
        --src)      SRC="$2";      shift 2 ;;
        --bindir)   BINDIR="$2";   shift 2 ;;
        --enable)   ENABLE=1;      shift ;;
        --start)    ENABLE=1; START=1; shift ;;
        -h|--help)  sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "$0"; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

[[ $(id -u) -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

# Locate the source tree: a dist tarball has deploy/install.sh with bin/ and
# the example configs at its root; in a git checkout binaries come from
# `make build BINDIR=<repo>/bin` (or pass --src).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SRC:-$(dirname "${SCRIPT_DIR}")}"
[[ -d "${ROOT}/bin" ]] || {
    echo "no bin/ under ${ROOT}. Build a dist tree first (make dist) or pass --src DIR" >&2
    exit 1
}

# Map service name -> binary : config-basename : unit.
svc_binary()  { case "$1" in signer) echo signer ;; control-plane) echo control-plane ;; mcp-http) echo mcp-broker-http ;; esac; }
svc_config()  { case "$1" in signer) echo signer.json ;; control-plane) echo control-plane.json ;; mcp-http) echo config.json ;; esac; }
svc_unit()    { case "$1" in signer) echo ssh-broker-signer.service ;; control-plane) echo ssh-broker-control-plane.service ;; mcp-http) echo ssh-broker-mcp-http.service ;; esac; }

for svc in ${SERVICES}; do
    [[ -n "$(svc_binary "${svc}")" ]] || { echo "unknown service '${svc}' (valid: signer control-plane mcp-http)" >&2; exit 2; }
done

# 1. System user (no shell, no home login).
if ! getent group ssh-broker >/dev/null; then
    groupadd --system ssh-broker
    echo "created group ssh-broker"
fi
if ! getent passwd ssh-broker >/dev/null; then
    useradd --system --gid ssh-broker --home-dir /var/lib/ssh-broker \
            --no-create-home --shell /usr/sbin/nologin ssh-broker
    echo "created user ssh-broker"
fi

# 2. Directories.
# /etc/ssh-broker holds the read-only material the services never rewrite: the
# mTLS PKI and the control-plane / mcp-http configs (root-owned, group-readable).
install -d -m 0750 -o root -g ssh-broker "${ETCDIR}" "${ETCDIR}/pki"
# The signer REWRITES its own config on a durable policy mutation
# (broker-ctl policy add/remove -> temp-file+rename), so its config lives in the
# service-owned state directory it can write, not under the read-only /etc tree.
STATEDIR="/var/lib/ssh-broker"
if [[ " ${SERVICES} " == *" signer "* ]]; then
    install -d -m 0750 -o ssh-broker -g ssh-broker "${STATEDIR}" "${STATEDIR}/signer"
fi

# 3. Binaries (broker-ctl always: it is the admin CLI).
install -d "${BINDIR}"
for svc in ${SERVICES}; do
    bin="$(svc_binary "${svc}")"
    install -m 0755 "${ROOT}/bin/${bin}" "${BINDIR}/${bin}"
    echo "installed ${BINDIR}/${bin}"
done
if [[ -f "${ROOT}/bin/broker-ctl" ]]; then
    install -m 0755 "${ROOT}/bin/broker-ctl" "${BINDIR}/broker-ctl"
    echo "installed ${BINDIR}/broker-ctl"
fi

# 4. Configs: refresh the .example reference, never touch a real config. The
# signer config goes to its writable state dir (step 2), owned by the service so
# the durable policy-mutation API can rewrite it; the others stay root-owned
# under /etc, read-only for their services.
for svc in ${SERVICES}; do
    cfg="$(svc_config "${svc}")"
    example="${ROOT}/${cfg%.json}.example.json"
    [[ -f "${example}" ]] || continue
    case "${svc}" in
        signer) confdir="${STATEDIR}/signer"; cowner="ssh-broker" ;;
        *)      confdir="${ETCDIR}";          cowner="root" ;;
    esac
    install -m 0640 -o "${cowner}" -g ssh-broker "${example}" "${confdir}/${cfg}.example"
    if [[ ! -f "${confdir}/${cfg}" ]]; then
        install -m 0640 -o "${cowner}" -g ssh-broker "${example}" "${confdir}/${cfg}"
        echo "installed ${confdir}/${cfg} (from example — EDIT BEFORE STARTING)"
    fi
done

# 4b. broker-ctl client parameters: /etc/ssh-broker/broker-ctl.json is the
# last entry of broker-ctl's search order, so the admin CLI works without
# --url/--cert/--key/--ca flags once it points at the real PKI.
if [[ -f "${ROOT}/broker-ctl.example.json" ]]; then
    install -m 0640 -o root -g ssh-broker "${ROOT}/broker-ctl.example.json" "${ETCDIR}/broker-ctl.json.example"
    if [[ ! -f "${ETCDIR}/broker-ctl.json" ]]; then
        install -m 0640 -o root -g ssh-broker "${ROOT}/broker-ctl.example.json" "${ETCDIR}/broker-ctl.json"
        echo "installed ${ETCDIR}/broker-ctl.json (from example — EDIT BEFORE USING)"
    fi
fi

# 5. systemd units.
for svc in ${SERVICES}; do
    unit="$(svc_unit "${svc}")"
    install -m 0644 "${SCRIPT_DIR}/systemd/${unit}" "/etc/systemd/system/${unit}"
    echo "installed /etc/systemd/system/${unit}"
done
systemctl daemon-reload

# 6. Enable/start only on request: a fresh install has configs that still
# point at example values and an empty pki/.
for svc in ${SERVICES}; do
    unit="$(svc_unit "${svc}")"
    [[ ${ENABLE} -eq 1 ]] && systemctl enable "${unit}"
    [[ ${START}  -eq 1 ]] && systemctl restart "${unit}"
done

cat <<EOF

Done. Before starting (see deploy/README.md for the full checklist):

 1. Edit the configs — use ABSOLUTE paths (${ETCDIR}/pki/...) for certs/keys;
    relative audit_log paths land in /var/lib/ssh-broker/<svc>/. Note the
    SIGNER config lives in ${STATEDIR}/signer/signer.json (service-owned, so
    the durable policy-mutation API can rewrite it); control-plane / mcp-http
    configs are in ${ETCDIR}.
 2. Choose CA custody in signer.json (ca_keys._default.type):
      "akv"  Azure Key Vault (production; credentials via managed identity or
             ${ETCDIR}/signer.env with AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET)
      "pem"  local key file (lab/dev only)
 3. Place the mTLS PKI under ${ETCDIR}/pki (keys 0640 root:ssh-broker).
 4. Production hardening: callers should contain "_default": {"allowed_groups": []}
    (default-deny) and sign_rate_limit_per_min should be set.
 5. systemctl enable --now ssh-broker-signer   # signer first, then the rest
EOF
