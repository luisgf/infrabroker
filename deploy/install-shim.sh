#!/usr/bin/env bash
# infrabroker sealed-exec host installer (idempotent). Run as root ON A MANAGED
# TARGET HOST — the machine agents connect TO. The service hosts (signer,
# control-plane, mcp-http) use deploy/install.sh instead; this script installs
# no daemon, no systemd unit and no service user.
#
# A host whose signer policy sets "sealed_exec": true gets
# force-command=infrabroker-shim <host> baked into its session certificate, so
# sshd hands every session command to the shim. The shim runs the inner command
# only if it carries a signer-signed envelope that verifies against a PINNED
# public key, has not expired, and whose nonce has not been used before — which
# is what makes per-command authorization survive a compromised broker
# (THREAT_MODEL gap #1). This script places the three host-side artifacts that
# requires:
#
#   /usr/local/bin/infrabroker-shim      the verifier (static, no dependencies)
#   /usr/bin/infrabroker-shim            symlink — see PATH below
#   /etc/infrabroker/envelope.pub        the pinned envelope public key(s)
#   /var/lib/infrabroker-shim/nonces     the single-use nonce store
#
# PATH. The certificate's force-command is the BARE name "infrabroker-shim", and
# sshd runs it through the account's login shell as a NON-login, NON-interactive
# shell — so /etc/profile, ~/.profile and ~/.bashrc are never sourced and PATH is
# whatever sshd hands down: its compiled-in default, possibly overridden by PAM
# (pam_env / /etc/environment).
#
# The distro packages do include /usr/local/bin in that default — Debian/Ubuntu
# build with --with-default-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:
# /sbin:/bin:/usr/games, Fedora/RHEL with /usr/local/bin:/usr/bin — so installing
# to /usr/local/bin works on a stock host. What does NOT include it is OpenSSH's
# own fallback (_PATH_STDPATH = /usr/bin:/bin:/usr/sbin:/sbin), which applies to a
# locally-built or minimally-configured sshd. This script therefore also symlinks
# the shim into /usr/bin, the one directory present in every one of those lists,
# so resolution does not depend on how sshd was built. Pass --no-path-symlink to
# skip it and take that on yourself.
#
# Permissions model. The shim runs as the UNPRIVILEGED SSH login account, not as
# root, so:
#   - the pinned key is public material: 0644 root:root, world-readable;
#   - the nonce store must be WRITABLE by every SSH account sealed sessions land
#     on. It is 1770 root:infrabroker-shim — group-writable for the accounts
#     added to the infrabroker-shim group, plus the sticky bit so one account
#     cannot delete another's nonce claims (deleting a claim would re-open the
#     replay window the store exists to close).
#
# Rotation. The pinned-key file may hold MORE THAN ONE key, one base64 line each
# (# comments and blank lines allowed). A host that pins both the outgoing and
# the incoming key keeps working while the signer is switched over, so an
# envelope-key rotation costs no downtime — use --add-pubkey for the overlap and
# --pubkey to collapse back to one key. The file is re-read on every command, so
# a change takes effect immediately, with no restart and no signal.
# The full runbook is in docs/OPERATIONS.md § "Sealing a host".
#
# Usage:
#   ./install-shim.sh --accounts "deploy appuser" --pubkey KEYFILE
#   ./install-shim.sh --accounts deploy --pubkey -        # key on stdin
#   ./install-shim.sh --accounts deploy --add-pubkey NEW  # rotation overlap
#   ./install-shim.sh --check                             # verify, change nothing
#
#   --accounts "a b"   SSH login accounts sealed sessions use (required unless --check)
#   --pubkey FILE|-    envelope public key: REPLACES the pinned set
#   --add-pubkey FILE|-  append a key to the pinned set (idempotent; for rotation)
#   --src DIR          tree containing bin/infrabroker-shim (default: auto)
#   --bindir DIR       default /usr/local/bin
#   --no-path-symlink  skip the /usr/bin symlink (you guarantee sshd's PATH)
#   --check            report the current state and exit; changes nothing
#
# The signer logs the value to pin at startup:
#   sealed exec: N host(s) [...]; envelope public key (pin this on those hosts): <base64>

set -euo pipefail

ACCOUNTS=""
PUBKEY=""
ADDPUBKEY=""
BINDIR="/usr/local/bin"
ETCDIR="/etc/infrabroker"
NONCEDIR="/var/lib/infrabroker-shim/nonces"
SHIMGROUP="infrabroker-shim"
SRC=""
CHECK=0
SYMLINK=1
# PATHLINK is the one directory present in sshd's compiled-in default PATH on
# both the Debian (/usr/bin:/bin:/usr/sbin:/sbin) and RHEL
# (/usr/local/bin:/usr/bin) families — see the PATH note in the header.
PATHLINK="/usr/bin/infrabroker-shim"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --accounts)         ACCOUNTS="$2";  shift 2 ;;
        --pubkey)           PUBKEY="$2";    shift 2 ;;
        --add-pubkey)       ADDPUBKEY="$2"; shift 2 ;;
        --src)              SRC="$2";       shift 2 ;;
        --bindir)           BINDIR="$2";    shift 2 ;;
        --no-path-symlink)  SYMLINK=0;      shift ;;
        --check)            CHECK=1;        shift ;;
        -h|--help)  sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "$0"; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

[[ $(id -u) -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

if [[ -n "${PUBKEY}" && -n "${ADDPUBKEY}" ]]; then
    echo "--pubkey and --add-pubkey are mutually exclusive (one replaces the pinned set, the other appends)" >&2
    exit 2
fi

PUBFILE="${ETCDIR}/envelope.pub"

# valid_key reports whether its argument is one pinned envelope key: base64 of
# exactly 32 bytes, the form sealed.ParsePublicKey accepts. Applying the shim's
# own predicate at WRITE time — and again in --check — is what stops this script
# from pinning something the shim will refuse on every command.
valid_key() {
    local k="$1" n
    [[ "${k}" =~ ^[A-Za-z0-9+/]+=*$ ]] || return 1
    n="$(printf '%s' "${k}" | base64 -d 2>/dev/null | wc -c | tr -d ' ')" || return 1
    [[ "${n}" == "32" ]]
}

# count_keys prints how many valid keys a pinned file holds, or fails if ANY
# non-blank, non-comment line is not a key — mirroring ParsePublicKeys, which
# rejects the whole file rather than skipping a bad line.
count_keys() {
    local f="$1" line n=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="$(printf '%s' "${line}" | tr -d '\r')"
        line="${line#"${line%%[![:space:]]*}"}"   # ltrim
        line="${line%"${line##*[![:space:]]}"}"   # rtrim
        [[ -z "${line}" || "${line}" == '#'* ]] && continue
        valid_key "${line}" || return 1
        n=$((n + 1))
    done < "${f}"
    [[ ${n} -gt 0 ]] || return 1
    printf '%s\n' "${n}"
}

# read_key_arg emits the key material named by its argument: a path, or "-" for
# stdin. Every line is VALIDATED here: a key rejected now is a clear error on the
# operator's terminal, where a key rejected later is a host that refuses every
# command with exit 126.
read_key_arg() {
    local src="$1" data line out=""
    if [[ "${src}" == "-" ]]; then
        data="$(cat)"
    else
        [[ -f "${src}" ]] || { echo "key file not found: ${src}" >&2; exit 1; }
        data="$(cat -- "${src}")"
    fi
    while IFS= read -r line; do
        line="$(printf '%s' "${line}" | tr -d '\r')"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "${line}" || "${line}" == '#'* ]] && continue
        valid_key "${line}" || {
            echo "not an envelope public key (expect base64 of 32 bytes): ${line}" >&2
            echo "the signer logs the value to pin; or derive it with: broker-ctl envelope pubkey --seed <file>" >&2
            exit 1
        }
        out+="${line}"$'\n'
    done <<< "${data}"
    [[ -n "${out}" ]] || { echo "no key material read from ${src}" >&2; exit 1; }
    printf '%s' "${out}"
}

# ── --check: report, change nothing ───────────────────────────────────────────
if [[ ${CHECK} -eq 1 ]]; then
    rc=0
    echo "infrabroker sealed-exec host check"
    if [[ -x "${BINDIR}/infrabroker-shim" ]]; then
        echo "  ok    shim binary   ${BINDIR}/infrabroker-shim"
    else
        echo "  FAIL  shim binary   ${BINDIR}/infrabroker-shim is missing or not executable"; rc=1
    fi
    if [[ -f "${PUBFILE}" ]]; then
        # Apply the shim's own predicate, not a line count: a file the shim
        # rejects must never read as "ok" here.
        if keys="$(count_keys "${PUBFILE}")"; then
            echo "  ok    pinned key    ${PUBFILE} ($(stat -c '%a %U:%G' "${PUBFILE}" 2>/dev/null || echo '?'), ${keys} key(s))"
        else
            echo "  FAIL  pinned key    ${PUBFILE} does not parse — the shim refuses EVERY command."
            echo "                      Every non-blank, non-# line must be base64 of 32 bytes, and one"
            echo "                      malformed line rejects the whole file (fail-closed by design)."
            rc=1
        fi
    else
        echo "  FAIL  pinned key    ${PUBFILE} is missing"; rc=1
    fi
    if [[ -d "${NONCEDIR}" ]]; then
        echo "  ok    nonce store   ${NONCEDIR} ($(stat -c '%a %U:%G' "${NONCEDIR}" 2>/dev/null || echo '?'))"
    else
        echo "  FAIL  nonce store   ${NONCEDIR} is missing"; rc=1
    fi
    # PATH: do NOT probe with `su ... command -v`. su's PATH comes from
    # /etc/login.defs, sshd's from its compiled-in default (possibly overridden by
    # PAM) — they differ, so that probe can pass while every real sealed command
    # fails. /usr/bin is in every one of those default lists, so a binary there
    # resolves regardless of how sshd was built.
    if [[ -x "${PATHLINK}" ]]; then
        echo "  ok    PATH          ${PATHLINK} present (resolvable from sshd's default PATH)"
    else
        echo "  WARN  PATH          ${PATHLINK} missing. sshd runs the BARE force-command"
        echo "                      'infrabroker-shim' with its compiled-in PATH (a force-command is a"
        echo "                      non-login shell, so /etc/profile is never sourced). The distro"
        echo "                      packages do include /usr/local/bin, so ${BINDIR} may still resolve —"
        echo "                      but OpenSSH's own fallback does not. Re-run without --no-path-symlink"
        echo "                      to stop depending on how sshd was built."
        rc=1
    fi
    # sshd -T exits non-zero on a config it cannot evaluate; capture that instead
    # of letting set -e abort the report half-written.
    if command -v sshd >/dev/null 2>&1; then
        if [[ -z "${ACCOUNTS}" ]]; then
            echo "  SKIP  sshd_config   no --accounts given; ForceCommand probe not run"
        fi
        for acct in ${ACCOUNTS}; do
            if ! sshd_out="$(sshd -T -C "user=${acct},host=localhost,addr=127.0.0.1" 2>&1)"; then
                echo "  WARN  sshd_config   could not evaluate sshd config for ${acct}: ${sshd_out%%$'\n'*}"
                rc=1
                continue
            fi
            fc="$(printf '%s\n' "${sshd_out}" | awk 'tolower($1)=="forcecommand"{$1=""; sub(/^ /,""); print}')"
            if [[ -z "${fc}" || "${fc}" == "none" ]]; then
                echo "  ok    sshd_config   no ForceCommand applies to ${acct} (probed as host=localhost,"
                echo "                      addr=127.0.0.1 — a Match Address/Host block scoped elsewhere is"
                echo "                      NOT covered; re-probe with the real client address)"
            else
                echo "  FAIL  sshd_config   ForceCommand applies to ${acct}: ${fc}"
                echo "                      sshd_config's ForceCommand OVERRIDES the certificate's, so the shim"
                echo "                      never runs and the signed envelope is handed to that command in"
                echo "                      \$SSH_ORIGINAL_COMMAND. Remove it for sealed hosts."
                rc=1
            fi
        done
    else
        echo "  SKIP  sshd_config   sshd not on PATH; ForceCommand probe not run"
    fi
    if [[ -z "${ACCOUNTS}" ]]; then
        echo
        echo "NOTE: --accounts was not given, so the per-account checks (login shell,"
        echo "      nonce-store write access, pinned-key readability, ForceCommand) were"
        echo "      SKIPPED. This is not a clean bill of health — re-run as:"
        echo "        $0 --check --accounts \"<the SSH account(s) sealed sessions use>\""
        exit 1
    fi
    for acct in ${ACCOUNTS}; do
        entry="$(getent passwd "${acct}" || true)"
        [[ -n "${entry}" ]] || { echo "  FAIL  account       ${acct} does not exist"; rc=1; continue; }
        shell="${entry##*:}"
        case "${shell}" in
            */nologin|*/false)
                echo "  FAIL  login shell   ${acct} has ${shell}; sshd runs the force-command via the"
                echo "                      account's shell, so no sealed command can ever run"
                rc=1 ;;
            *)  echo "  ok    login shell   ${acct} uses ${shell}" ;;
        esac
        if su -s /bin/sh -c "test -w '${NONCEDIR}'" "${acct}"; then
            echo "  ok    nonce write   ${acct} can write ${NONCEDIR}"
        else
            echo "  FAIL  nonce write   ${acct} cannot write ${NONCEDIR} — every sealed command will fail closed"; rc=1
        fi
        # The shim reads the pinned key AS THIS ACCOUNT. Root being able to read
        # it proves nothing: on a host that also runs a service, install.sh owns
        # /etc/infrabroker as 0750 root:infrabroker and an SSH account outside
        # that group cannot even traverse it.
        if su -s /bin/sh -c "test -r '${PUBFILE}'" "${acct}"; then
            echo "  ok    key readable  ${acct} can read ${PUBFILE}"
        else
            echo "  FAIL  key readable  ${acct} cannot read ${PUBFILE} (check the mode of $(dirname "${PUBFILE}")"
            echo "                      too — a service host has it 0750 root:infrabroker)"; rc=1
        fi
    done
    [[ ${rc} -eq 0 ]] && echo "all checks passed"
    exit ${rc}
fi

[[ -n "${ACCOUNTS}" ]] || {
    echo "--accounts is required: list the SSH login account(s) sealed sessions land on," >&2
    echo "so the nonce store can be made writable by them (e.g. --accounts \"deploy\")." >&2
    exit 2
}
for acct in ${ACCOUNTS}; do
    getent passwd "${acct}" >/dev/null || { echo "unknown account: ${acct}" >&2; exit 1; }
done

# 1. Shim binary. Located like install.sh: this script sits at <tree>/deploy/,
# with the built binaries at <tree>/bin/.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SRC:-$(dirname "${SCRIPT_DIR}")}"
[[ -f "${ROOT}/bin/infrabroker-shim" ]] || {
    echo "no bin/infrabroker-shim under ${ROOT}. Unpack the release tarball (it ships one) or pass --src DIR" >&2
    exit 1
}
install -d "${BINDIR}"
install -m 0755 "${ROOT}/bin/infrabroker-shim" "${BINDIR}/infrabroker-shim"
echo "installed ${BINDIR}/infrabroker-shim"

# 1b. Put it where sshd will actually find it. The certificate's force-command is
# the BARE name, run by a NON-login shell, so PATH is sshd's compiled-in default —
# /usr/bin:/bin:/usr/sbin:/sbin on Debian/Ubuntu (no /usr/local/bin) and
# /usr/local/bin:/usr/bin on RHEL/Fedora. /usr/bin is the intersection.
# Compare RESOLVED paths, not strings: "--bindir /usr/bin/" (a trailing slash is
# what shell completion produces) or a merged-usr /bin would otherwise make this
# link the file onto itself and destroy the binary just installed.
SHIMBIN="${BINDIR}/infrabroker-shim"
if [[ ${SYMLINK} -eq 1 ]]; then
    if [[ "$(readlink -f "${SHIMBIN}" 2>/dev/null || echo "${SHIMBIN}")" == "$(readlink -f "${PATHLINK}" 2>/dev/null || echo "${PATHLINK}")" ]]; then
        echo "skipped ${PATHLINK} symlink (--bindir already resolves there)"
    else
        ln -sfn "${SHIMBIN}" "${PATHLINK}"
        echo "linked ${PATHLINK} -> ${SHIMBIN}"
    fi
fi

# 2. Group for the nonce store. One shared system group holding every SSH account
# sealed sessions use; it grants nothing but write access to that directory.
if ! getent group "${SHIMGROUP}" >/dev/null; then
    groupadd --system "${SHIMGROUP}"
    echo "created group ${SHIMGROUP}"
fi
for acct in ${ACCOUNTS}; do
    # usermod fails on an account that is not local (LDAP/SSSD/AD) even though
    # getent resolved it. Do not abort a half-done install: report it and let the
    # operator add the account to the group in their directory, which the
    # nonce-write check below then confirms.
    if usermod -aG "${SHIMGROUP}" "${acct}" 2>/dev/null; then
        echo "added ${acct} to ${SHIMGROUP}"
    else
        echo "WARNING: could not add '${acct}' to ${SHIMGROUP} with usermod." >&2
        echo "         Not a local account? Add it to that group in your directory," >&2
        echo "         then re-run with --check to confirm it can write ${NONCEDIR}." >&2
    fi
done

# 3. Nonce store. 1770: group-writable so each account can CLAIM a nonce, sticky
# so one account cannot REMOVE ANOTHER'S claim (that would re-open someone else's
# replay window). It deliberately does not try to stop an account removing its
# own claim — that would only let it replay an envelope minted for itself, for a
# command already authorised for it — nor a group member filling the directory to
# deny sealed exec host-wide; both are inside the trust boundary of an account
# you have already granted sealed access to. The shim's own sweep only drops
# entries older than twice the envelope lifetime, and with the sticky bit each
# account sweeps its own — best-effort by design, and a missed sweep only ever
# makes the store stricter.
install -d -m 0755 -o root -g root "$(dirname "${NONCEDIR}")"
install -d -m 1770 -o root -g "${SHIMGROUP}" "${NONCEDIR}"
echo "installed ${NONCEDIR} (1770 root:${SHIMGROUP})"

# 4. Pinned envelope public key. PUBLIC material, world-readable: the shim reads
# it as the unprivileged SSH account. Only create ${ETCDIR} when it is absent —
# on a machine that also runs a service, install.sh owns that directory's mode
# and this script must not widen it.
if [[ ! -d "${ETCDIR}" ]]; then
    install -d -m 0755 -o root -g root "${ETCDIR}"
fi
if [[ -n "${PUBKEY}" ]]; then
    # Build beside the target and rename: a reader never sees a partial file, and
    # the mode is set before the content is visible under the real name.
    read_key_arg "${PUBKEY}" > "${PUBFILE}.new"
    chown root:root "${PUBFILE}.new"
    chmod 0644 "${PUBFILE}.new"
    mv -f "${PUBFILE}.new" "${PUBFILE}"
    echo "pinned $(count_keys "${PUBFILE}") key(s) in ${PUBFILE}"
elif [[ -n "${ADDPUBKEY}" ]]; then
    newkeys="$(read_key_arg "${ADDPUBKEY}")"
    touch "${PUBFILE}"
    # A file pinned BY HAND before this script existed (echo -n, Ansible
    # `copy: content:`) may have no trailing newline. Appending to it blind would
    # fuse the outgoing and incoming keys onto one line, which ParsePublicKeys
    # rejects — bricking the host mid-rotation. Terminate the last line first.
    if [[ -s "${PUBFILE}" ]] && [[ "$(tail -c 1 "${PUBFILE}" | od -An -c | tr -d ' ')" != '\n' ]]; then
        printf '\n' >> "${PUBFILE}"
        echo "note: ${PUBFILE} lacked a trailing newline; added one before appending"
    fi
    added=0
    while IFS= read -r k; do
        [[ -n "${k}" ]] || continue
        if grep -qxF -- "${k}" "${PUBFILE}"; then
            echo "already pinned, skipping: ${k:0:16}…"
        else
            printf '%s\n' "${k}" >> "${PUBFILE}"
            added=$((added + 1))
        fi
    done <<< "${newkeys}"
    chown root:root "${PUBFILE}"
    chmod 0644 "${PUBFILE}"
    # Re-parse with the shim's predicate: never report success on a file it would
    # refuse (e.g. a pre-existing line this script did not write).
    if total="$(count_keys "${PUBFILE}")"; then
        echo "appended ${added} key(s); ${PUBFILE} now pins ${total}"
    else
        echo "ERROR: ${PUBFILE} no longer parses — the shim will refuse every command." >&2
        echo "       Every non-blank, non-# line must be base64 of 32 bytes. Inspect it," >&2
        echo "       or re-pin the whole set with --pubkey." >&2
        exit 1
    fi
elif [[ ! -f "${PUBFILE}" ]]; then
    cat >&2 <<EOF

WARNING: no envelope public key pinned at ${PUBFILE}.
The shim refuses EVERY command until one is present. Re-run with --pubkey once
the signer has logged it:

    sealed exec: N host(s) [...]; envelope public key (pin this on those hosts): <base64>

EOF
fi

# 5. Verify what the operator cannot easily check by hand: that sshd's bare
# force-command "infrabroker-shim" actually resolves for each account, and that
# the account can claim a nonce. Both are WARNINGS, not failures — the house
# style of install.sh — because the fix is a local decision (a symlink, or a
# different account), but each one means every sealed command fails closed.
if [[ ${SYMLINK} -eq 0 && ! -x "${PATHLINK}" ]]; then
    cat >&2 <<EOF

WARNING: --no-path-symlink was given and ${PATHLINK} does not exist.
sshd runs the certificate's BARE force-command "infrabroker-shim" through the
account's login shell as a NON-login shell, so /etc/profile is never sourced and
PATH is sshd's compiled-in default. The distro packages do put /usr/local/bin on
it, so ${BINDIR} may work here — but OpenSSH's own fallback does not, so you are
now depending on how this host's sshd was built. Verify before you seal the host.

EOF
fi

for acct in ${ACCOUNTS}; do
    entry="$(getent passwd "${acct}")"
    case "${entry##*:}" in
        */nologin|*/false) cat >&2 <<EOF

WARNING: '${acct}' has login shell ${entry##*:}.
sshd runs a force-command via the account's shell, so no sealed command can run
on this host for that account. Give it a real shell, or seal a different account.

EOF
            ;;
    esac
    su -s /bin/sh -c "test -w '${NONCEDIR}'" "${acct}" || cat >&2 <<EOF

WARNING: '${acct}' cannot write ${NONCEDIR}.
Every sealed command for that account will fail closed until this is fixed — do
not treat it as transient. Likely causes: the usermod above failed (a directory
account), or the account is not in the ${SHIMGROUP} group. Confirm with
'id ${acct}' and re-check:

    ${BASH_SOURCE[0]} --check --accounts "${ACCOUNTS}"

EOF
    su -s /bin/sh -c "test -r '${PUBFILE}'" "${acct}" 2>/dev/null || cat >&2 <<EOF

WARNING: '${acct}' cannot read ${PUBFILE}.
The shim reads the pinned key AS THIS ACCOUNT, so it will refuse every command.
On a host that also runs an infrabroker service, install.sh owns $(dirname "${PUBFILE}")
as 0750 root:infrabroker and an SSH account outside that group cannot traverse it.

EOF
done

cat <<EOF

Done. This host is prepared. Seal it from the SIGNER side, IN THIS ORDER —
flipping sealed_exec before the host is ready refuses every session command:

 1. Set a dedicated envelope key (32 random bytes) if you have not already:
      umask 077 && head -c 32 /dev/urandom > /var/lib/infrabroker/signer/envelope.seed
      chown infrabroker-signer: /var/lib/infrabroker/signer/envelope.seed
    then in signer.json: "envelope_key": "/var/lib/infrabroker/signer/envelope.seed"
 2. Confirm THIS host already pins that key — compare the two:
      broker-ctl envelope pubkey --seed /var/lib/infrabroker/signer/envelope.seed
      cat ${PUBFILE}
    (the signer also logs it at startup:
      journalctl -u infrabroker-signer | grep 'envelope public key')
 3. Only then mark the host sealed in signer.json ("sealed_exec": true) and
    reload: systemctl reload infrabroker-signer
 4. Sealed hosts accept mode=exec sessions only (shell/pty are not
    envelope-verifiable), and turning sealed_exec on does NOT seal sessions that
    are already open — close them.

Verify any time with:  ${BASH_SOURCE[0]} --check --accounts "${ACCOUNTS}"
Full runbook, including envelope-key rotation: docs/OPERATIONS.md section 2.2.
EOF
