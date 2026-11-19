#!/usr/bin/env bash
#
# crowdsec-abuse-reporter/docker/entrypoint.sh
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

set -euo pipefail

# Unified log line: "<UTC time> | LEVEL | source | message". WARNING and above go
# to stderr; colour only on a TTY with NO_COLOR unset. Duplicated per tool on purpose.
log_time() {
    TZ=UTC printf '%(%Y-%m-%d %H:%M:%S UTC)T' -1
}

log() {
    local level="$1" source="$2" message="$3" line fd=1 color="" reset=""
    message="${message//$'\r'/\\r}"
    message="${message//$'\n'/\\n}"
    case "${level}" in
        WARNING|ERROR|CRITICAL) fd=2 ;;
    esac
    if [ -t "${fd}" ] && [ -z "${NO_COLOR:-}" ]; then
        reset=$'\033[0m'
        case "${level}" in
            WARNING) color=$'\033[33m' ;;
            ERROR|CRITICAL) color=$'\033[31m' ;;
            *) color=$'\033[36m' ;;
        esac
    fi
    printf -v line '%s | %-8s | %s | %s' "$(log_time)" "${level}" "${source}" "${message}"
    printf '%s%s%s\n' "${color}" "${line}" "${reset}" >&"${fd}"
}

# `wait -n -p` (used to notice a dying helper loop) needs bash >= 5.1.
if [ "${BASH_VERSINFO[0]}" -lt 5 ] || { [ "${BASH_VERSINFO[0]}" -eq 5 ] && [ "${BASH_VERSINFO[1]}" -lt 1 ]; }; then
    log ERROR entrypoint "bash >= 5.1 required (found ${BASH_VERSION})."
    exit 1
fi

DATA_DIR="/data"
# tmpfs state the HEALTHCHECK reads (see docker/Dockerfile); never persisted.
RUNTIME_DIR="/tmp"
API_PID_FILE="$RUNTIME_DIR/api_heartbeat.pid"
METRICS_PID_FILE="$RUNTIME_DIR/metrics.pid"
METRICS_HEARTBEAT_FILE="$RUNTIME_DIR/metrics_heartbeat"
HEALTH_LIMITS_FILE="$RUNTIME_DIR/health_limits"

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
                    && log INFO entrypoint "Seeded $(basename "$src") from the image baseline"
            fi
        done
    else
        log WARNING entrypoint "no GeoIP baseline at $GEOIP_BASELINE_DIR; the first run depends on the update check"
    fi
    chown -R app:app "$GEOIP_DIR" 2>/dev/null || true
}

# Docker creates a missing bind-mount source dir as root, so a fresh ./data
# on the host ends up root-owned even though the app runs as uid:gid
# 10001:10001. Fix ownership once as root, then drop privileges for the rest
# of the container's life — nothing past this point runs as root.
if [ "$(id -u)" = "0" ]; then
    # chown the top-level data dir unconditionally; descend into subdirectories
    # best-effort only — a subdirectory with restrictive host permissions is not
    # readable by root with -R and would otherwise abort the container start
    # with "Permission denied".
    chown app:app "$DATA_DIR" 2>/dev/null || true
    chown -R app:app "$DATA_DIR" 2>/dev/null \
        || log WARNING entrypoint "chown -R on $DATA_DIR had permission errors (subdirectory with restricted access); continuing"
    seed_geoip_baseline
    exec gosu app:app "$0" "$@"
fi

export ABUSE_DB_PATH="${ABUSE_DB_PATH:-$DATA_DIR/abuse_alerts.db}"

if [ -z "${SMTP_SERVER:-}" ]; then
    log ERROR entrypoint "no settings available."
    log ERROR entrypoint "Provide ./settings.env via compose env_file or set the required variables."
    exit 1
fi

# Track child PIDs so a container stop signal (TERM/INT) reaches the main run,
# both helper loops, and any in-progress sleep — otherwise the foreground job
# keeps running until Docker's stop timeout escalates to SIGKILL, which can
# interrupt a DB write or an outbound report mid-flight.
# Job control gives every background job its own process group, so the signal
# also reaches the python/sleep children of a helper loop instead of orphaning
# them; a group id always equals its leader's pid and never our own group.
set -m
_MAIN_PID=""
_SLEEP_PID=""
_HELPER_PIDS=()
declare -A _HELPER_NAMES=()

# Upper bounds, compared as strings so no value can overflow bash's 64-bit
# arithmetic (an oversized number makes `[ -le ]` fail and `$(( ))` wrap).
readonly MAX_HOURS=8760        # one year
readonly MAX_SECONDS=31536000  # one year

require_at_most() {
    local name="$1" value="$2" max="$3"
    # Leading zeros do not count towards the length (08 stays 8).
    value="${value#"${value%%[!0]*}"}"
    if [ "${#value}" -gt "${#max}" ] || { [ "${#value}" -eq "${#max}" ] && [[ "${value}" > "${max}" ]]; }; then
        log ERROR entrypoint "${name} must be at most ${max}."
        exit 1
    fi
}

require_positive_integer() {
    local name="$1" value="$2" max="${3:-${MAX_SECONDS}}"
    case "${value}" in
        ''|*[!0-9]*)
            log ERROR entrypoint "${name} must be a positive integer."
            exit 1
            ;;
    esac
    require_at_most "${name}" "${value}" "${max}"
    if [ "${value}" -le 0 ]; then
        log ERROR entrypoint "${name} must be greater than 0."
        exit 1
    fi
}

_terminate_children() {
    # A second stop signal must not re-enter while children are being reaped.
    trap '' TERM INT
    local pid
    for pid in "${_MAIN_PID}" "${_SLEEP_PID}" "${_HELPER_PIDS[@]}"; do
        if [ -n "${pid}" ]; then
            kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
}

_shutdown() {
    log INFO entrypoint "Received stop signal — shutting down"
    _terminate_children
    exit 0
}
trap _shutdown TERM INT

# A required helper loop ended on its own: stop everything and exit non-zero,
# so Docker's restart policy restarts the container. Failing python calls inside
# the loops never get here — they are tolerated there.
_helper_exited() {
    log ERROR entrypoint "${_HELPER_NAMES[$1]:-helper} loop (pid $1) exited unexpectedly (rc=$2) — stopping container"
    _terminate_children
    exit 1
}

# Wait for job $1 and return its exit status, but notice a dying helper loop
# at once: `wait -n` returns for whichever of the listed jobs ends first.
# A trapped TERM/INT interrupts it and the handler exits.
_await_job() {
    local pid="$1" finished rc helper
    while true; do
        # A helper that died before this wait is already reaped, and `wait -n`
        # would never report it, so check for it explicitly first.
        for helper in "${_HELPER_PIDS[@]}"; do
            kill -0 "${helper}" 2>/dev/null || _helper_exited "${helper}" "unknown"
        done
        finished=""
        wait -n -p finished "${_HELPER_PIDS[@]}" "${pid}" && rc=0 || rc=$?
        if [ "${finished}" = "${pid}" ] || [ -z "${finished}" ]; then
            return "${rc}"
        fi
        _helper_exited "${finished}" "${rc}"
    done
}

# Record "<pid> <start time>" so the HEALTHCHECK can tell the helper from a
# reused pid (field 22 of /proc/<pid>/stat, after the parenthesised comm).
_register_helper() {
    local name="$1" pid="$2" file="$3" line rest
    local -a fields
    _HELPER_PIDS+=("${pid}")
    _HELPER_NAMES["${pid}"]="${name}"
    line="$(< "/proc/${pid}/stat")"
    rest="${line##*) }"
    read -ra fields <<< "${rest}"
    echo "${pid} ${fields[19]}" > "${file}"
}

# A persisted success from an earlier container must not make this instance
# healthy before it has completed a successful processing run.
rm -f "$DATA_DIR/heartbeat" "$API_PID_FILE" "$METRICS_PID_FILE" "$METRICS_HEARTBEAT_FILE" "$HEALTH_LIMITS_FILE"

# Sleep as a background job and wait on it. bash defers a trap until a
# foreground command returns, but interrupts the `wait` builtin immediately —
# so this keeps shutdown responsive during the long inter-run and jitter sleeps.
# The same wait also ends the sleep as soon as a helper loop dies.
interruptible_sleep() {
    sleep "$1" &
    _SLEEP_PID=$!
    _await_job "${_SLEEP_PID}" || true
    _SLEEP_PID=""
}

run_once() {
    set +e
    # Run in the background and wait, so a TERM/INT trap can fire mid-run and
    # forward the signal to run.py instead of being deferred until it exits.
    python run.py "$@" &
    _MAIN_PID=$!
    _await_job "${_MAIN_PID}"
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
        require_positive_integer "RUN_EVERY_HOUR" "${RUN_EVERY_HOUR}" "${MAX_HOURS}"
        echo $(( 10#${RUN_EVERY_HOUR} * 3600 ))
        return
    fi

    local interval="${RUN_INTERVAL:-21600}"
    case "${interval}" in
        ''|*[!0-9]*)
            log ERROR entrypoint "RUN_INTERVAL must be a positive integer number of seconds."
            exit 1
            ;;
    esac
    require_at_most "RUN_INTERVAL" "${interval}" "${MAX_SECONDS}"
    if [ "${interval}" -le 0 ]; then
        log ERROR entrypoint "RUN_INTERVAL must be greater than 0."
        exit 1
    fi
    echo "${interval}"
}

if [ "${RUN_ONCE:-false}" = "true" ]; then
    run_once "$@"
    exit $?
fi

API_HEARTBEAT_INTERVAL="${API_HEARTBEAT_INTERVAL:-300}"
require_positive_integer "API_HEARTBEAT_INTERVAL" "${API_HEARTBEAT_INTERVAL}"

if [ -n "${METRICS_BACKEND:-}" ] && [ "${METRICS_BACKEND}" != "none" ]; then
    METRICS_INTERVAL="${METRICS_INTERVAL:-60}"
    require_positive_integer "METRICS_INTERVAL" "${METRICS_INTERVAL}"
    # Optional: an explicit value replaces the limit derived below.
    if [ -n "${METRICS_HEARTBEAT_MAX_AGE_SECONDS:-}" ]; then
        require_positive_integer "METRICS_HEARTBEAT_MAX_AGE_SECONDS" "${METRICS_HEARTBEAT_MAX_AGE_SECONDS}"
    fi
fi

RUN_INTERVAL_SECONDS="$(resolve_run_interval_seconds)"

# Jitter is derived from the interval: a tenth of it, capped at 5 minutes.
# Plain 10# arithmetic keeps a leading zero (RUN_INTERVAL=08) decimal.
interval_s=$(( 10#${RUN_INTERVAL_SECONDS} ))
max_jitter=$(( interval_s / 10 ))
if [ "${max_jitter}" -gt 300 ]; then
    max_jitter=300
fi

# Health limits the HEALTHCHECK reads, derived once from the schedule so it
# never needs arithmetic on config values; an explicit *_MAX_AGE_SECONDS wins.
# Format: "<main> <LAPI> <metrics>" seconds, metrics 0 when the backend is off.
main_max="${HEALTHCHECK_MAX_AGE_SECONDS:-}"
if [ -n "${main_max}" ]; then
    require_positive_integer "HEALTHCHECK_MAX_AGE_SECONDS" "${main_max}"
else
    main_max=$(( interval_s + max_jitter + 7200 ))
fi
api_max="${API_HEARTBEAT_MAX_AGE_SECONDS:-}"
if [ -n "${api_max}" ]; then
    require_positive_integer "API_HEARTBEAT_MAX_AGE_SECONDS" "${api_max}"
else
    api_max=$(( 10#${API_HEARTBEAT_INTERVAL} + 400 ))
fi
metrics_max=0
if [ -n "${METRICS_BACKEND:-}" ] && [ "${METRICS_BACKEND}" != "none" ]; then
    metrics_max="${METRICS_HEARTBEAT_MAX_AGE_SECONDS:-}"
    if [ -z "${metrics_max}" ]; then
        metrics_max=$(( 10 * 10#${METRICS_INTERVAL} + 300 ))
    fi
fi
# Atomic replace: the HEALTHCHECK must never read a half-written file.
printf '%d %d %d\n' "$(( 10#${main_max} ))" "$(( 10#${api_max} ))" "$(( 10#${metrics_max} ))" \
    > "${HEALTH_LIMITS_FILE}.tmp"
mv -f "${HEALTH_LIMITS_FILE}.tmp" "${HEALTH_LIMITS_FILE}"

# Background LAPI heartbeat loop — runs every API_HEARTBEAT_INTERVAL seconds
# (default 300 = 5 min). Updates /data/api_heartbeat on success so the Docker
# HEALTHCHECK can detect a prolonged LAPI outage between main processing runs.
# A failing python call is tolerated; only the loop itself ending is fatal.
_api_heartbeat_loop() {
    local interval="${API_HEARTBEAT_INTERVAL:-300}"
    log INFO heartbeat "Starting LAPI heartbeat loop (interval: ${interval}s)"
    while true; do
        python -m app.heartbeat \
            || log WARNING heartbeat "LAPI unreachable"
        sleep "${interval}"
    done
}
_api_heartbeat_loop &
_register_helper "LAPI heartbeat" "$!" "${API_PID_FILE}"

# Touches a tmpfs file after each successful snapshot; the HEALTHCHECK reads its
# age, so a backend outage only turns the container unhealthy (no restart).
metrics_loop() {
    local interval="${METRICS_INTERVAL:-60}"
    log INFO metrics "Starting metrics loop (interval: ${interval}s)"
    while true; do
        if METRICS_ONLY=true python run.py; then
            touch "${METRICS_HEARTBEAT_FILE}" \
                || log WARNING metrics "cannot update ${METRICS_HEARTBEAT_FILE}"
        else
            log WARNING metrics "metrics snapshot failed"
        fi
        sleep "${interval}"
    done
}
if [ -n "${METRICS_BACKEND:-}" ] && [ "${METRICS_BACKEND}" != "none" ]; then
    metrics_loop &
    _register_helper "metrics" "$!" "${METRICS_PID_FILE}"
fi

if [ -n "${RUN_EVERY_HOUR:-}" ]; then
    log INFO entrypoint "Periodic mode: running every ${RUN_EVERY_HOUR} hour(s) (${RUN_INTERVAL_SECONDS}s)"
else
    log INFO entrypoint "Periodic mode: running every ${RUN_INTERVAL_SECONDS}s"
fi

# One-time start offset so hosts started together do not fire together; runs
# then follow a fixed grid (base + k * interval), so run time does not drift it.
start_offset=$(( RANDOM % (max_jitter + 1) ))
log INFO entrypoint "Scheduling: max jitter ${max_jitter}s (interval/10, capped at 300s), start offset ${start_offset}s"
if [ "${start_offset}" -gt 0 ]; then
    interruptible_sleep "${start_offset}"
fi
printf -v base '%(%s)T' -1
slot=0
while true; do
    run_once "$@" || log INFO entrypoint "run exited non-zero (rc=$?), continuing"
    printf -v now '%(%s)T' -1
    # A run that outlasts its slot skips the missed slots instead of catching up.
    next_slot=$(( (now - base) / interval_s + 1 ))
    if [ "${next_slot}" -gt $(( slot + 1 )) ]; then
        log WARNING entrypoint "run overran the ${interval_s}s interval; skipping $(( next_slot - slot - 1 )) missed slot(s)"
    fi
    slot="${next_slot}"
    jitter=$(( RANDOM % (max_jitter + 1) ))
    wait_s=$(( base + slot * interval_s + jitter - now ))
    if [ "${wait_s}" -lt 0 ]; then
        wait_s=0
    fi
    next_run="$(date -u -d "@$(( now + wait_s ))" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo "in ${wait_s}s")"
    log INFO entrypoint "Run complete — jitter ${jitter}s, sleeping ${wait_s}s, next run at ${next_run}"
    interruptible_sleep "${wait_s}"
done
