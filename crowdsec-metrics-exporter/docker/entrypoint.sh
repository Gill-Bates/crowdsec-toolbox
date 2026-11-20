#!/usr/bin/env bash
#
# crowdsec-metrics-exporter/docker/entrypoint.sh
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

# Runtime state lives on the container's tmpfs and is deliberately not configurable.
readonly STATE_DIR=/tmp/state
readonly HEALTH_LIMITS_FILE=/tmp/health_limits

# The container runs as uid 10001 from the start; /tmp is the only writable
# mount (tmpfs with mode=1777), so this user can create its own subdirectory.
if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
    log ERROR entrypoint "cannot create $STATE_DIR"
    log ERROR entrypoint "This path must be writable: the container filesystem is"
    log ERROR entrypoint "read-only apart from the tmpfs mounted at /tmp."
    log ERROR entrypoint "Check that docker-compose.yml still declares that tmpfs."
    exit 1
fi
rm -f "$HEALTH_LIMITS_FILE" "${HEALTH_LIMITS_FILE}.tmp"

# Track child PIDs so a container stop signal (TERM/INT) is forwarded to the
# main run and any in-progress sleep — otherwise the foreground job keeps
# running until Docker's stop timeout escalates to SIGKILL, which can
# interrupt a DB write mid-flight.
_MAIN_PID=""
_SLEEP_PID=""

_shutdown() {
    log INFO entrypoint "Received stop signal — shutting down"
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

    # main.py exits 1 when the QuestDB version, the LAPI fetch, a backend write or the dedup/TTL
    # step failed, or the data is incomplete, so the heartbeat only advances
    # after a fully successful run.
    if [ "$rc" -eq 0 ]; then
        touch "$STATE_DIR/heartbeat"
    else
        log WARNING entrypoint "main.py exited non-zero (rc=$rc); heartbeat not updated"
    fi
    return "$rc"
}

# Upper bounds, compared as strings so no value can overflow bash's 64-bit
# arithmetic (an oversized number makes `[ -le ]` fail and `$(( ))` wrap).
readonly MAX_HOURS=8760        # one year
readonly MAX_SECONDS=31536000  # one year
readonly HEALTHCHECK_RUNTIME_RESERVE_SECONDS=300
readonly MAX_HEALTH_SECONDS=$((MAX_SECONDS + 600))

require_at_most() {
    local name="$1" value="$2" max="$3"
    # Leading zeros do not count towards the length (08 stays 8).
    value="${value#"${value%%[!0]*}"}"
    if [ "${#value}" -gt "${#max}" ] || { [ "${#value}" -eq "${#max}" ] && [[ "${value}" > "${max}" ]]; }; then
        log ERROR entrypoint "${name} must be at most ${max}."
        exit 1
    fi
}

resolve_run_interval_seconds() {
    if [ -n "${RUN_EVERY_HOUR:-}" ]; then
        case "${RUN_EVERY_HOUR}" in
            ''|*[!0-9]*)
                log ERROR entrypoint "RUN_EVERY_HOUR must be a positive integer."
                exit 1
                ;;
        esac
        require_at_most "RUN_EVERY_HOUR" "${RUN_EVERY_HOUR}" "${MAX_HOURS}"
        if [ "${RUN_EVERY_HOUR}" -le 0 ]; then
            log ERROR entrypoint "RUN_EVERY_HOUR must be greater than 0."
            exit 1
        fi
        echo $(( 10#${RUN_EVERY_HOUR} * 3600 ))
        return
    fi

    local interval="${RUN_INTERVAL:-60}"
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

max_jitter_for_interval() {
    local interval_s="$1" max_jitter
    max_jitter=$((interval_s / 10))
    if [ "${max_jitter}" -gt 300 ]; then
        max_jitter=300
    fi
    echo "${max_jitter}"
}

healthcheck_max_age_for_schedule() {
    local interval_s="$1" max_jitter="$2" minimum max_age
    minimum=$((interval_s + max_jitter + HEALTHCHECK_RUNTIME_RESERVE_SECONDS))
    if [ "${minimum}" -lt 900 ]; then
        minimum=900
    fi
    max_age="${HEALTHCHECK_MAX_AGE_SECONDS:-${minimum}}"
    if [ -n "${HEALTHCHECK_MAX_AGE_SECONDS:-}" ]; then
        case "${max_age}" in
            ''|*[!0-9]*)
                log ERROR entrypoint "HEALTHCHECK_MAX_AGE_SECONDS must be a positive integer."
                exit 1
                ;;
        esac
        require_at_most "HEALTHCHECK_MAX_AGE_SECONDS" "${max_age}" "${MAX_HEALTH_SECONDS}"
        max_age="${max_age#"${max_age%%[!0]*}"}"
        [ -n "${max_age}" ] || max_age=0
        if [ "${max_age}" -le 0 ]; then
            log ERROR entrypoint "HEALTHCHECK_MAX_AGE_SECONDS must be greater than 0."
            exit 1
        fi
        if [ "${max_age}" -lt "${minimum}" ]; then
            log ERROR entrypoint "HEALTHCHECK_MAX_AGE_SECONDS must be at least ${minimum}s for this schedule."
            exit 1
        fi
    fi
    printf '%s\n' "${max_age}"
}

if [ "${RUN_ONCE:-false}" = "true" ]; then
    run_once "$@"
    exit $?
fi

RUN_INTERVAL_SECONDS="$(resolve_run_interval_seconds)"
if [ -n "${RUN_EVERY_HOUR:-}" ]; then
    log INFO entrypoint "Periodic mode: running every ${RUN_EVERY_HOUR} hour(s) (${RUN_INTERVAL_SECONDS}s)"
else
    log INFO entrypoint "Periodic mode: running every ${RUN_INTERVAL_SECONDS}s"
fi

# Jitter is derived from the interval: a tenth of it, capped at 5 minutes.
# Plain 10# arithmetic keeps a leading zero (RUN_INTERVAL=08) decimal.
interval_s=$(( 10#${RUN_INTERVAL_SECONDS} ))
max_jitter="$(max_jitter_for_interval "${interval_s}")"
healthcheck_max_age="$(healthcheck_max_age_for_schedule "${interval_s}" "${max_jitter}")"
printf '%s\n' "${healthcheck_max_age}" > "${HEALTH_LIMITS_FILE}.tmp"
mv -f "${HEALTH_LIMITS_FILE}.tmp" "${HEALTH_LIMITS_FILE}"
# Events older than the gap between two runs are lost unless EVENTS_SINCE covers
# interval + jitter. Warn only; app/config.py rejects an invalid format.
# Same reading as app/config.py _env_bool: surrounding blanks and case are ignored.
events_enabled="${EVENTS_ENABLED:-false}"
events_enabled="${events_enabled#"${events_enabled%%[![:space:]]*}"}"
events_enabled="${events_enabled%"${events_enabled##*[![:space:]]}"}"
if [ "${events_enabled,,}" = "true" ] && [[ "${EVENTS_SINCE:-30m}" =~ ^([0-9]+)([smhd])$ ]]; then
    case "${BASH_REMATCH[2]}" in
        s) events_unit=1 ;;
        m) events_unit=60 ;;
        h) events_unit=3600 ;;
        *) events_unit=86400 ;;
    esac
    # Bounded digits keep the multiplication inside 64-bit arithmetic.
    events_n="${BASH_REMATCH[1]}"
    if [ "${#events_n}" -le 9 ] && [ $(( 10#${events_n} * events_unit )) -lt $(( interval_s + max_jitter )) ]; then
        log WARNING entrypoint "EVENTS_SINCE=${EVENTS_SINCE:-30m} is shorter than the run interval plus jitter ($(( interval_s + max_jitter ))s); events may fall between two runs"
    fi
fi

# One-time start offset so hosts started together do not fire together; runs
# then follow a fixed grid (base + k * interval), so run time does not drift it.
start_offset=$(( RANDOM % (max_jitter + 1) ))
log INFO entrypoint "Scheduling: max jitter ${max_jitter}s (interval/10, capped at 300s), start offset ${start_offset}s"
if [ "${start_offset}" -gt 0 ]; then
    interruptible_sleep "${start_offset}"
fi
base="$(date +%s)"
slot=0
while true; do
    run_once "$@" || log INFO entrypoint "run exited non-zero (rc=$?), continuing"
    now="$(date +%s)"
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
