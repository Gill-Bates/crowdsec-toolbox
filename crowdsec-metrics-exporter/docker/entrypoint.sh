#!/usr/bin/env bash
#
# crowdsec-metrics-exporter/docker/entrypoint.sh
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

set -euo pipefail

# The only runtime file is the heartbeat the health check reads, so this is a
# fixed path on the container's tmpfs and deliberately not configurable: there
# is no persistent state to relocate, and an operator-supplied path would be
# handed to the recursive chown below — which must never touch /app or a system
# path, since /app is executed as root on the next start.
readonly STATE_DIR=/tmp/state

if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
    echo "[entrypoint] ERROR: cannot create $STATE_DIR" >&2
    echo "[entrypoint] This path must be writable: the container filesystem is" >&2
    echo "[entrypoint] read-only apart from the tmpfs mounted at /tmp." >&2
    echo "[entrypoint] Check that docker-compose.yml still declares that tmpfs." >&2
    exit 1
fi

# $STATE_DIR lives on the tmpfs and is created by the mkdir above as root,
# even though the app runs as uid:gid 10001:10001. Fix ownership once as root,
# then drop privileges for the rest of the container's life — nothing past this
# point runs as root. Access to
# The exporter reaches CrowdSec over the Local API, so the container needs no
# Docker socket and therefore no supplementary groups across the drop.
if [ "$(id -u)" = "0" ]; then
    chown -R app:app "$STATE_DIR" 2>/dev/null \
        || echo "[entrypoint] WARNING: chown -R on $STATE_DIR had permission errors; continuing" >&2

    exec gosu app:app "$0" "$@"
fi

# $STATE_DIR only holds the heartbeat file the health check reads and is a
# tmpfs path, not a mounted volume: the exporter keeps no local state since
# both backends deduplicate server-side.


# Track child PIDs so a container stop signal (TERM/INT) is forwarded to the
# main run and any in-progress sleep — otherwise the foreground job keeps
# running until Docker's stop timeout escalates to SIGKILL, which can
# interrupt a DB write mid-flight.
_MAIN_PID=""
_SLEEP_PID=""

_shutdown() {
    echo "[entrypoint] Received stop signal — shutting down"
    for _pid in "${_MAIN_PID}" "${_SLEEP_PID}"; do
        if [ -n "${_pid}" ]; then
            kill "${_pid}" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    exit 0
}
trap _shutdown TERM INT

# Sleep as a background job and wait on it. bash defers a trap until a
# foreground command returns, but interrupts the `wait` builtin immediately —
# so this keeps shutdown responsive during the inter-run and jitter sleeps.
interruptible_sleep() {
    sleep "$1" &
    _SLEEP_PID=$!
    wait "${_SLEEP_PID}"
    _SLEEP_PID=""
}

run_once() {
    set +e
    # Run in the background and wait, so a TERM/INT trap can fire mid-run and
    # forward the signal to main.py instead of being deferred until it exits.
    python main.py "$@" &
    _MAIN_PID=$!
    wait "${_MAIN_PID}"
    local rc=$?
    _MAIN_PID=""
    set -e

    # main.py exits 1 when the TLS check, the LAPI fetch or a backend
    # write failed, so the heartbeat only advances after a successful run.
    if [ "$rc" -eq 0 ]; then
        touch "$STATE_DIR/heartbeat"
    else
        echo "[entrypoint] WARNING: main.py exited non-zero (rc=$rc); heartbeat not updated" >&2
    fi
    return "$rc"
}

resolve_run_interval_seconds() {
    if [ -n "${RUN_EVERY_HOUR:-}" ]; then
        case "${RUN_EVERY_HOUR}" in
            ''|*[!0-9]*)
                echo "[entrypoint] ERROR: RUN_EVERY_HOUR must be a positive integer." >&2
                exit 1
                ;;
        esac
        if [ "${RUN_EVERY_HOUR}" -le 0 ]; then
            echo "[entrypoint] ERROR: RUN_EVERY_HOUR must be greater than 0." >&2
            exit 1
        fi
        echo $(( RUN_EVERY_HOUR * 3600 ))
        return
    fi

    local interval="${RUN_INTERVAL:-60}"
    case "${interval}" in
        ''|*[!0-9]*)
            echo "[entrypoint] ERROR: RUN_INTERVAL must be a positive integer number of seconds." >&2
            exit 1
            ;;
    esac
    if [ "${interval}" -le 0 ]; then
        echo "[entrypoint] ERROR: RUN_INTERVAL must be greater than 0." >&2
        exit 1
    fi
    echo "${interval}"
}

if [ "${RUN_ONCE:-false}" = "true" ]; then
    run_once "$@"
    exit $?
fi

RUN_JITTER="${RUN_JITTER:-0}"
case "${RUN_JITTER}" in
    ''|*[!0-9]*)
        echo "[entrypoint] ERROR: RUN_JITTER must be a non-negative integer." >&2
        exit 1
        ;;
esac

RUN_INTERVAL_SECONDS="$(resolve_run_interval_seconds)"
if [ -n "${RUN_EVERY_HOUR:-}" ]; then
    echo "[entrypoint] Periodic mode: running every ${RUN_EVERY_HOUR} hour(s) (${RUN_INTERVAL_SECONDS}s)"
else
    echo "[entrypoint] Periodic mode: running every ${RUN_INTERVAL_SECONDS}s"
fi
while true; do
    run_once "$@" || echo "[entrypoint] run exited non-zero (rc=$?), continuing"
    if [ "${RUN_JITTER}" -gt 0 ]; then
        jitter=$(( RANDOM % (RUN_JITTER + 1) ))
        echo "[entrypoint] Jitter: sleeping ${jitter}s before next run"
        interruptible_sleep "${jitter}"
    fi
    next_run="$(date -u -d "+${RUN_INTERVAL_SECONDS} seconds" '+%Y%m%d %H:%M:%S UTC' 2>/dev/null || echo "in ${RUN_INTERVAL_SECONDS}s")"
    echo "[entrypoint] Run complete — sleeping ${RUN_INTERVAL_SECONDS}s, next run at ${next_run}"
    interruptible_sleep "${RUN_INTERVAL_SECONDS}"
done
