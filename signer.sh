#!/usr/bin/env bash
# Gestión del servicio ssh-signer.
# Uso: ./signer.sh {start|stop|status|restart|log}

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
            echo "signer ya está corriendo (PID ${pid})"
            exit 1
        else
            echo "PID file huérfano encontrado, limpiando..."
            rm -f "${PIDFILE}"
        fi
    fi

    echo "Arrancando signer..."
    "${BINARY}" -config "${CONFIG}" >> "${LOGFILE}" 2>&1 &
    local pid=$!
    echo "${pid}" > "${PIDFILE}"

    # Esperar hasta 3s a que arranque o falle
    local i=0
    while (( i < 6 )); do
        sleep 0.5
        if ! kill -0 "${pid}" 2>/dev/null; then
            rm -f "${PIDFILE}"
            echo "ERROR: el signer terminó inesperadamente. Últimas líneas del log:"
            tail -20 "${LOGFILE}"
            exit 1
        fi
        i=$((i + 1))
    done

    echo "signer arrancado (PID ${pid})"
    echo "Log: ${LOGFILE}"
}

cmd_stop() {
    if [[ ! -f "${PIDFILE}" ]]; then
        echo "signer no está corriendo (no hay PID file)"
        exit 0
    fi
    local pid
    pid=$(cat "${PIDFILE}")
    if kill -0 "${pid}" 2>/dev/null; then
        echo "Parando signer (PID ${pid})..."
        kill "${pid}"
        # Esperar hasta 5s a que termine
        local i=0
        while (( i < 10 )) && kill -0 "${pid}" 2>/dev/null; do
            sleep 0.5
            i=$((i + 1))
        done
        if kill -0 "${pid}" 2>/dev/null; then
            echo "No terminó, enviando SIGKILL..."
            kill -9 "${pid}"
        fi
        echo "signer parado"
    else
        echo "Proceso ${pid} no encontrado (ya había terminado)"
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
            echo "signer STOPPED  (PID file huérfano: ${pid})"
        fi
    else
        echo "signer STOPPED"
    fi

    if [[ -f "${LOGFILE}" ]]; then
        echo ""
        echo "--- Últimas líneas de ${LOGFILE} ---"
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
        echo "No existe ${LOGFILE} todavía"
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
        echo "Uso: $(basename "$0") {start|stop|status|restart|log}"
        exit 1
        ;;
esac
