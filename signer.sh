#!/usr/bin/env bash
# ssh-signer service management.
# Usage: ./signer.sh {start|stop|status|restart|log}

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${HOME}/bin/signer"
CONFIG="${DIR}/signer.json"
PIDFILE="${DIR}/signer.pid"
LOGFILE="${DIR}/signer.log"

cmd_start() {
    if [[ -f "${PIDFILE}" ]]; then
        local pid
        pid=$(cat "${PIDFILE}")
        if kill -0 "${pid}" 2>/dev/null; then
            echo "signer is already running (PID ${pid})"
            exit 1
        else
            echo "Stale PID file found, cleaning up..."
            rm -f "${PIDFILE}"
        fi
    fi

    echo "Starting signer..."
    "${BINARY}" -config "${CONFIG}" >> "${LOGFILE}" 2>&1 &
    local pid=$!
    echo "${pid}" > "${PIDFILE}"

    # Wait up to 3s for the process to start or fail.
    local i=0
    while (( i < 6 )); do
        sleep 0.5
        if ! kill -0 "${pid}" 2>/dev/null; then
            rm -f "${PIDFILE}"
            echo "ERROR: signer exited unexpectedly. Last log lines:"
            tail -20 "${LOGFILE}"
            exit 1
        fi
        i=$((i + 1))
    done

    echo "signer started (PID ${pid})"
    echo "Log: ${LOGFILE}"
}

cmd_stop() {
    if [[ ! -f "${PIDFILE}" ]]; then
        echo "signer is not running (no PID file)"
        # return, not exit: `exit` terminates the whole script even under
        # `cmd_stop || true`, so `restart` on a stopped signer never started it.
        return 0
    fi
    local pid
    pid=$(cat "${PIDFILE}")
    if kill -0 "${pid}" 2>/dev/null; then
        echo "Stopping signer (PID ${pid})..."
        kill "${pid}"
        # Wait up to 5s for the process to exit.
        local i=0
        while (( i < 10 )) && kill -0 "${pid}" 2>/dev/null; do
            sleep 0.5
            i=$((i + 1))
        done
        if kill -0 "${pid}" 2>/dev/null; then
            echo "Did not exit, sending SIGKILL..."
            kill -9 "${pid}"
        fi
        echo "signer stopped"
    else
        echo "Process ${pid} not found (already exited)"
    fi
    rm -f "${PIDFILE}"
}

cmd_status() {
    if [[ -f "${PIDFILE}" ]]; then
        local pid
        pid=$(cat "${PIDFILE}")
        if kill -0 "${pid}" 2>/dev/null; then
            echo "signer RUNNING  (PID ${pid})"
        else
            echo "signer STOPPED  (stale PID file: ${pid})"
        fi
    else
        echo "signer STOPPED"
    fi

    if [[ -f "${LOGFILE}" ]]; then
        echo ""
        echo "--- Last lines of ${LOGFILE} ---"
        tail -10 "${LOGFILE}"
    fi
}

cmd_restart() {
    cmd_stop || true
    sleep 0.5
    cmd_start
}

cmd_log() {
    if [[ ! -f "${LOGFILE}" ]]; then
        echo "${LOGFILE} does not exist yet"
        exit 1
    fi
    exec tail -f "${LOGFILE}"
}

case "${1:-}" in
    start)   cmd_start   ;;
    stop)    cmd_stop    ;;
    status)  cmd_status  ;;
    restart) cmd_restart ;;
    log)     cmd_log     ;;
    *)
        echo "Usage: $(basename "$0") {start|stop|status|restart|log}"
        exit 1
        ;;
esac
