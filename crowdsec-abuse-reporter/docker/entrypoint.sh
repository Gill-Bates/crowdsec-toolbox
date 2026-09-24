#!/usr/bin/env bash
#
# crowdsec-abuse-reporter/docker/entrypoint.sh
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

set -euo pipefail

DATA_DIR="/data"

mkdir -p "$DATA_DIR"

# $GEOIP_DIR is a tmpfs, so it starts empty on every container start. Seed it
# from the read-only baseline baked into the image at build time, so enrichment
# works immediately and a failed or slow update check cannot leave the run
# without a database. app/geoip.py replaces these files in place once the mirror
# offers a newer release; that copy is intentionally not persisted.
GEOIP_DIR="${GEOIP_DIR:-/tmp/geoip}"
GEOIP_BASELINE_DIR="/opt/geoip-baseline"

seed_geoip_baseline() {
    mkdir -p "$GEOIP_DIR"
    if [ -d "$GEOIP_BASELINE_DIR" ]; then
        for src in "$GEOIP_BASELINE_DIR"/*.mmdb; do
            [ -e "$src" ] || continue
            target="$GEOIP_DIR/$(basename "$src")"
            # Only seed what is missing: a restart inside the same container
            # would otherwise discard an already updated database.
            if [ ! -f "$target" ]; then
                cp "$src" "$target" \
                    && echo "[entrypoint] Seeded $(basename "$src") from the image baseline"
            fi
        done
    else
        echo "[entrypoint] WARNING: no GeoIP baseline at $GEOIP_BASELINE_DIR; the first run depends on the update check" >&2
    fi
    chown -R app:app "$GEOIP_DIR" 2>/dev/null || true
}

# Docker creates a missing bind-mount source dir as root, so a fresh ./data
# on the host ends up root-owned even though the app runs as uid:gid
# 10001:10001. Fix ownership once as root, then drop privileges for the rest
# of the container's life — nothing past this point runs as root.
if [ "$(id -u)" = "0" ]; then
    # chown the top-level data dir unconditionally; descend into subdirectories
    # best-effort only — a subdirectory with restrictive host permissions is
    # not readable by root with -R
    # and would otherwise abort the container start with "Permission denied".
    chown app:app "$DATA_DIR" 2>/dev/null || true
    chown -R app:app "$DATA_DIR" 2>/dev/null \
        || echo "[entrypoint] WARNING: chown -R on $DATA_DIR had permission errors (subdirectory with restricted access); continuing" >&2
    seed_geoip_baseline
    exec gosu app:app "$0" "$@"
fi

export ABUSE_DB_PATH="${ABUSE_DB_PATH:-$DATA_DIR/abuse_alerts.db}"

if [ -z "${SMTP_SERVER:-}" ]; then
    echo "[entrypoint] ERROR: no settings available." >&2
    echo "[entrypoint] Provide ./settings.env via compose env_file or set the required variables." >&2
    exit 1
fi

# Track child PIDs so a container stop signal (TERM/INT) is forwarded to the
# main run, the heartbeat loop, and any in-progress sleep — otherwise the
# foreground job keeps running until Docker's stop timeout escalates to SIGKILL,
# which can interrupt a DB write or an outbound report mid-flight.
_MAIN_PID=""
_HEARTBEAT_PID=""
_METRICS_PID=""
_SLEEP_PID=""

require_positive_integer() {
    local name="$1"
    local value="$2"
    case "${value}" in
        ''|*[!0-9]*)
            echo "[entrypoint] ERROR: ${name} must be a positive integer." >&2
            exit 1
            ;;
    esac
    if [ "${value}" -le 0 ]; then
        echo "[entrypoint] ERROR: ${name} must be greater than 0." >&2
        exit 1
    fi
}

_shutdown() {
    echo "[entrypoint] Received stop signal — shutting down"
    for _pid in "${_MAIN_PID}" "${_HEARTBEAT_PID}" "${_METRICS_PID}" "${_SLEEP_PID}"; do
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
# so this keeps shutdown responsive during the long inter-run and jitter sleeps.
interruptible_sleep() {
    sleep "$1" &
    _SLEEP_PID=$!
    wait "${_SLEEP_PID}"
    _SLEEP_PID=""
}

run_once() {
    set +e
    # Run in the background and wait, so a TERM/INT trap can fire mid-run and
    # forward the signal to run.py instead of being deferred until it exits.
    python run.py "$@" &
    _MAIN_PID=$!
    wait "${_MAIN_PID}"
    local rc=$?
    _MAIN_PID=""
    set -e

    # Only refresh the heartbeat on a successful run. run.py exits non-zero only
    # for hard failures (DB init, LAPI fetch, finalize/DB errors); per-report
    # send/DNS issues still exit 0. Touching unconditionally would keep the
    # HEALTHCHECK green while the main processing repeatedly fails.
    if [ "$rc" -eq 0 ]; then
        touch "$DATA_DIR/heartbeat"
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

    local interval="${RUN_INTERVAL:-21600}"
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

# Background LAPI heartbeat loop — runs every API_HEARTBEAT_INTERVAL seconds
# (default 300 = 5 min). Updates /data/api_heartbeat on success so the Docker
# HEALTHCHECK can detect a prolonged LAPI outage between main processing runs.
_api_heartbeat_loop() {
    local interval="${API_HEARTBEAT_INTERVAL:-300}"
    require_positive_integer "API_HEARTBEAT_INTERVAL" "${interval}"
    echo "[heartbeat] Starting LAPI heartbeat loop (interval: ${interval}s)"
    while true; do
        python -m app.heartbeat \
            || echo "[heartbeat] WARNING: LAPI unreachable" >&2
        sleep "${interval}"
    done
}
_api_heartbeat_loop &
_HEARTBEAT_PID=$!

RUN_JITTER="${RUN_JITTER:-0}"
case "${RUN_JITTER}" in
    ''|*[!0-9]*)
        echo "[entrypoint] ERROR: RUN_JITTER must be a non-negative integer." >&2
        exit 1
        ;;
esac

metrics_loop() {
    local interval="${METRICS_INTERVAL:-60}"
    require_positive_integer "METRICS_INTERVAL" "${interval}"
    echo "[metrics] Starting metrics loop (interval: ${interval}s)"
    while true; do
        METRICS_ONLY=true python run.py \
            || echo "[metrics] WARNING: metrics snapshot failed" >&2
        sleep "${interval}"
    done
}
if [ "${RUN_ONCE:-false}" != "true" ] && [ -n "${METRICS_BACKEND:-}" ] && [ "${METRICS_BACKEND}" != "none" ]; then
    metrics_loop &
    _METRICS_PID=$!
fi

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
