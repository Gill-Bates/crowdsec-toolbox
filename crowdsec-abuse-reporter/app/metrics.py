#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/metrics.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Optional export of abuse-report outcomes to InfluxDB 2.x or QuestDB.

Mirrors crowdsec-metrics-exporter: the same METRICS_BACKEND / INFLUXDB_* /
QUESTDB_* settings and the same InfluxDB Line Protocol payload, sent to
InfluxDB's /api/v2/write or QuestDB's ILP-over-HTTP /write endpoint. Unlike
the sibling tool, both backends go through httpx (this project has no
requests/urllib3 dependency); httpx negotiates TLS 1.2+ by default.
"""

import socket
import ssl
import time
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path

import httpx
from gillbates_questdb_client import (
    DownsamplingProfile,
    LogSink,
    QuestDBClient,
    QuestDBConfig,
    RetentionSettings,
    RollupSpec,
)

from app.config import (
    INFLUXDB_BUCKET,
    INFLUXDB_ORGANIZATION,
    INFLUXDB_PORT,
    INFLUXDB_TOKEN,
    INFLUXDB_URL,
    INFLUXDB_USE_HTTPS,
    INFLUXDB_VALIDATE_CERTIFICATE,
    METRICS_BACKEND,
    METRICS_ENABLED,
    METRICS_OUTBOX_MAX_AGE_DAYS,
    METRICS_OUTBOX_MAX_ROWS,
    METRICS_RETRY_BACKOFF,
    METRICS_WRITE_RETRIES,
    QUESTDB_DOWNSAMPLING,
    QUESTDB_DOWNSAMPLING_DISABLED_PROFILE,
    QUESTDB_DOWNSAMPLING_PROFILES,
    QUESTDB_DOWNSAMPLING_SCHEMA_VERSION,
    QUESTDB_DOWNSAMPLING_STATE_TABLE,
    QUESTDB_PASSWORD,
    QUESTDB_PORT,
    QUESTDB_TABLE,
    QUESTDB_TOKEN,
    QUESTDB_TTL,
    QUESTDB_TTL_DAYS,
    QUESTDB_URL,
    QUESTDB_USE_HTTPS,
    QUESTDB_USERNAME,
    QUESTDB_VALIDATE_CERTIFICATE,
    REQUEST_TIMEOUT,
)
from app.database import (
    count_metric_points,
    delete_metric_points,
    load_metric_points,
    prune_metric_outbox,
    spool_metric_points,
)
from app.logger import print_config_info, print_database_error, print_debug, print_error, print_info, print_warning

HOST_HOSTNAME_PATH = Path("/run/host/hostname")

# Upper bound on the points sent in one request. After a long outage the spool
# can hold far more than a single run produced; the remainder follows on the next
# run rather than in one oversized POST.
_FLUSH_BATCH_LIMIT = 5000

# Columns that identify a report point, passed to QuestDB's
# `DEDUP ENABLE UPSERT KEYS`. These are exactly the tag columns written by
# `format_report_line()` plus the designated timestamp, which must come first —
# i.e. the same identity InfluxDB 2.x derives from series + timestamp and
# overwrites on its own. Re-writing a batch therefore updates rows instead of
# appending copies.
#
# `alert_id` is a field, not a tag, so it cannot serve as a key. It is not
# needed either: a report is claimed per (AlertId, IPAddress) in SQLite, and
# `ip_address` + `scenario` + `status` already separate the points that a run
# can legitimately produce.
#
# This does **not** replace the SQLite claim protocol. Deduplication makes
# storage idempotent; it cannot decide whether a mail may be sent, since that
# decision happens before the write and needs an atomic compare-and-set.
DEDUP_KEYS = (
    "timestamp",
    "host",
    "ip_address",
    "scenario",
    "status",
    "country",
    "as_number",
    "as_name",
)


def get_source_host() -> str:
    """Read the Docker host name, or the local host name for direct runs."""
    try:
        hostname = HOST_HOSTNAME_PATH.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return socket.gethostname()
    if not hostname or any(char in hostname for char in "\r\n\x00"):
        raise ValueError(f"Host hostname file is invalid: {HOST_HOSTNAME_PATH}")
    return hostname


def escape_tag(value: object) -> str:
    """Escape a measurement/tag value for line protocol."""
    text = " ".join(str(value).splitlines())
    return text.replace("\\", "\\\\").replace(",", "\\,").replace("=", "\\=").replace(" ", "\\ ")


def escape_string_field(value: object) -> str:
    """Quote and escape a string field value for line protocol."""
    text = " ".join(str(value).splitlines())
    # Backslashes first: escaping quotes first would double the escape character.
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def format_report_line(
    measurement: str,
    *,
    host: str | None = None,
    alert_id: int,
    ip: str,
    scenario: str,
    status: str,
    recipient: str,
    error: str | None,
    country: str,
    as_number: str,
    as_name: str,
    processing_time: float,
    timestamp: datetime | None = None,
) -> str:
    """Build one line-protocol point for a finalized report."""
    tags = {
        "ip_address": ip,
        "scenario": scenario,
        "status": status,
        "country": country,
        "as_number": as_number,
        "as_name": as_name,
    }
    if host:
        tags["host"] = host
    tags_str = ",".join(f"{key}={escape_tag(value)}" for key, value in tags.items() if value)
    fields = [
        f"alert_id={int(alert_id)}i",
        f"abuse_email={escape_string_field(recipient)}",
        f"processing_time={float(processing_time)}",
        # Always written, even empty: ILP creates a column lazily on its first
        # point, so a conditional field would leave `error_message` missing
        # from the table until the first failed report — and a dashboard
        # query that selects it as a plain column fails with QuestDB's
        # "Invalid column" until then.
        f"error_message={escape_string_field(error or '')}",
    ]

    ts = timestamp or datetime.now(UTC)
    ts_ns = int(ts.timestamp() * 1_000_000) * 1000
    head = escape_tag(measurement) + (f",{tags_str}" if tags_str else "")
    return f"{head} {','.join(fields)} {ts_ns}"


def measurement_name(hostname: str) -> str:
    """Same rule as crowdsec-metrics-exporter: QuestDB table vs. hostname."""
    return QUESTDB_TABLE if METRICS_BACKEND == "questdb" else hostname


def _post(
    url: str,
    *,
    payload: str,
    headers: dict[str, str],
    params: dict[str, str],
    verify: bool,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """POST the payload, retrying transient transport failures.

    Only connection-level errors are retried, never an HTTP status: a 4xx means
    the payload or the credentials are wrong and repeating it cannot help. A
    resolver hiccup or a reset connection, on the other hand, is usually gone by
    the next attempt, which keeps the points out of the outbox entirely.
    """
    attempts = METRICS_WRITE_RETRIES + 1
    for attempt in range(attempts):
        try:
            with httpx.Client(verify=verify, timeout=REQUEST_TIMEOUT) as client:
                return client.post(url, headers=headers, params=params, content=payload, auth=auth)
        except (httpx.HTTPError, ssl.SSLError) as e:
            if attempt == attempts - 1:
                raise
            delay = METRICS_RETRY_BACKOFF * (2**attempt)
            print_warning(
                f"Metrics write failed (attempt {attempt + 1}/{attempts}): {e} — retrying in {delay:.1f}s",
            )
            time.sleep(delay)
    # Unreachable: the final attempt either returns or raises.
    raise RuntimeError("metrics write retry loop exited without a result")


def send_to_influxdb(payload: str) -> bool:
    protocol = "https" if INFLUXDB_USE_HTTPS else "http"
    url = f"{protocol}://{INFLUXDB_URL}:{INFLUXDB_PORT}/api/v2/write"
    headers = {
        "Authorization": f"Token {INFLUXDB_TOKEN}",
        "Content-Type": "text/plain; charset=utf-8",
    }
    params = {
        "org": INFLUXDB_ORGANIZATION,
        "bucket": INFLUXDB_BUCKET,
        "precision": "ns",
    }
    try:
        response = _post(
            url,
            payload=payload,
            headers=headers,
            params=params,
            verify=INFLUXDB_VALIDATE_CERTIFICATE,
        )
    except (httpx.HTTPError, ssl.SSLError) as e:
        print_database_error(0, f"Connection error to InfluxDB at {url}: {e}")
        return False
    if response.status_code == 204:
        return True
    print_database_error(0, f"InfluxDB API error: {response.status_code} - {response.text[:500]}")
    return False


def build_client(
    *,
    downsampling: str = QUESTDB_DOWNSAMPLING,
    ttl: str | None = QUESTDB_TTL,
    ttl_days: int | None = QUESTDB_TTL_DAYS,
    transport=None,
    sleep=time.sleep,
) -> QuestDBClient:
    """Build the QuestDB client from the reporter's settings; the keyword arguments exist for tests."""
    return QuestDBClient(
        QuestDBConfig(
            host=QUESTDB_URL,
            port=QUESTDB_PORT,
            https=QUESTDB_USE_HTTPS,
            token=QUESTDB_TOKEN,
            username=QUESTDB_USERNAME,
            password=QUESTDB_PASSWORD,
            verify_certificate=QUESTDB_VALIDATE_CERTIFICATE,
            timeout=REQUEST_TIMEOUT,
        ),
        log=_LOG,
        retention=RetentionSettings(
            ttl=ttl,
            ttl_days=ttl_days,
            downsampling=downsampling,
            profiles={
                name: DownsamplingProfile(profile.raw_retention_days, profile.rollup_interval)
                for name, profile in QUESTDB_DOWNSAMPLING_PROFILES.items()
            },
            schema_version=QUESTDB_DOWNSAMPLING_SCHEMA_VERSION,
            state_table=QUESTDB_DOWNSAMPLING_STATE_TABLE,
            disabled_profile=QUESTDB_DOWNSAMPLING_DISABLED_PROFILE,
            duplicate_cleanup_hint="See the duplicate cleanup runbook in docs/reference/metrics-backends.md",
        ),
        transport=transport,
        sleep=sleep,
    )


# Call-time lookups keep the print_* helpers patchable and the reporter's log format.
def _debug(message: str) -> None:
    print_debug(message)


def _info(message: str) -> None:
    print_info(message)


def _warning(message: str) -> None:
    print_warning(message)


def _error(message: str) -> None:
    print_error(message)


_LOG = LogSink(debug=_debug, info=_info, success=_info, warning=_warning, error=_error)
# One server per process: the client caches the version verdict and the table-gate results.
_CLIENT = build_client()


def send_to_questdb(payload: str) -> bool:
    url = _CLIENT.config.url("write")
    headers, auth = _CLIENT.config.credentials()
    headers["Content-Type"] = "text/plain; charset=utf-8"
    try:
        response = _post(
            url,
            payload=payload,
            headers=headers,
            params={"precision": "ns"},
            verify=QUESTDB_VALIDATE_CERTIFICATE,
            auth=auth,
        )
    except (httpx.HTTPError, ssl.SSLError) as e:
        print_database_error(0, f"Connection error to QuestDB at {url}: {e}")
        return False
    if response.status_code in (200, 204):
        return True
    print_database_error(0, f"QuestDB API error: {response.status_code} - {response.text[:500]}")
    return False


class WriteStatus(IntEnum):
    """Outcome of a bare write; the int values keep `if write_points(...)` meaningful.

    "Data written" and "database correctly configured" are separate facts: a
    failed TTL after an accepted batch is WRITTEN_TTL_FAILED, never NOT_WRITTEN,
    so the delivered rows are not sent again for a DDL failure.
    """

    NOT_WRITTEN = 0
    OK = 1
    WRITTEN_TTL_FAILED = 2


def write_points(lines: list[str], *, quiet: bool = False) -> WriteStatus:
    """Send all points in one request to the configured backend.

    Truthy when there is nothing to send or the backend accepted the batch.
    For QuestDB the version and table gates (`ensure_questdb_version`,
    `ensure_questdb_table`) run first and raise MetricsGateError without writing
    anything when the server is not QuestDB 10.x or dedup cannot be verified.
    Callers that must not lose the points use `flush_points()`, which persists
    them first; this function is the bare write.
    """
    if not lines:
        return WriteStatus.OK
    payload = "\n".join(lines)
    status = WriteStatus.OK
    if METRICS_BACKEND == "questdb":
        if not ensure_questdb_version():
            raise MetricsGateError(f"QuestDB version check failed; {len(lines)} point(s) were not written")
        if not ensure_questdb_table(QUESTDB_TABLE, DEDUP_KEYS):
            raise MetricsGateError(
                f"QuestDB dedup on {QUESTDB_TABLE!r} could not be verified; {len(lines)} point(s) were not written. "
                "See the duplicate cleanup runbook in docs/reference/metrics-backends.md"
            )
        baseline_txn = questdb_rollup_baseline(QUESTDB_TABLE, ROLLUP)
        if not send_to_questdb(payload):
            return WriteStatus.NOT_WRITTEN
        if not apply_questdb_retention(QUESTDB_TABLE, ROLLUP, baseline_txn):
            status = WriteStatus.WRITTEN_TTL_FAILED
    elif METRICS_BACKEND == "influxdb2":
        if not send_to_influxdb(payload):
            return WriteStatus.NOT_WRITTEN
    else:
        return WriteStatus.OK
    (print_debug if quiet else print_config_info)(f"Wrote {len(lines)} report point(s) to {METRICS_BACKEND}")
    return status


class MetricsError(RuntimeError):
    """Base of the metrics failures that must fail the run (exit 1)."""


class MetricsGateError(MetricsError):
    """The QuestDB gate failed before writing any points."""


class MetricsTtlError(MetricsError):
    """The batch was written and acknowledged, but QuestDB retention or rollup setup failed."""


class MetricsLostError(MetricsError):
    """Points were neither persisted to the outbox nor accepted by the backend."""


class MetricsPrunedError(MetricsLostError):
    """Undelivered points were dropped from the outbox by its row or age bound."""


def flush_points(lines: list[str] | None = None) -> bool:
    """Persist *lines*, then send everything the backend has not acknowledged.

    The durable path for report points. New points are spooled before network
    access when the SQLite write succeeds. If that spool write fails, a direct
    backend write is attempted once. Spooled rows are deleted only after the
    backend acknowledges their batch; pending rows are read in bounded batches.

    Replaying is deliberately not selective within a batch: each point carries
    its timestamp and dedup keys, so a failed batch can be resent as a unit
    without tracking which individual point of a batch failed.

    Returns True when metrics are disabled, nothing was pending, or the backend
    acknowledged the sent batch (rows beyond the batch limit may remain spooled).
    A False return means the points are still spooled, not lost — the caller
    decides whether a deferred batch is worth failing the run for. Raises
    MetricsLostError when the spool failed and the direct write failed too:
    nothing durable exists, and MetricsPrunedError when the bounds dropped
    undelivered rows. Either is raised only after the remaining rows were
    flushed, once per run however many losses it saw.

    Two further failures are distinct from an outage and from loss. A failed
    QuestDB dedup gate raises MetricsGateError before anything is written: the
    outbox is untouched, because writing without verified dedup would store
    points that later replays duplicate. A failed TTL after an acknowledged
    batch raises MetricsTtlError once the delivered rows were deleted; they are
    never resent for that reason.
    """
    if not METRICS_ENABLED:
        return True

    # Persist first: from here on a crash or a dead backend costs a retry, not
    # the data. A spool failure is the one case that can still lose points, so it
    # is reported and the run continues with the bare write as a last attempt.
    spooled = spool_metric_points(lines or [])

    # Bound the spool before reading it, so a long outage cannot grow the
    # database without limit.
    pruned = prune_metric_outbox(METRICS_OUTBOX_MAX_ROWS, METRICS_OUTBOX_MAX_AGE_DAYS)
    try:
        status = _send_spooled(lines, spooled)
    except MetricsError as e:
        if pruned:
            raise type(e)(f"{e}; {pruned} undelivered point(s) were also dropped from the outbox") from e
        raise
    ok = bool(status)
    if pruned:
        # Pruned rows were never acknowledged by the backend, so they are lost.
        raise MetricsPrunedError(
            f"{pruned} undelivered metrics point(s) were dropped from the outbox "
            f"(METRICS_OUTBOX_MAX_ROWS={METRICS_OUTBOX_MAX_ROWS}, "
            f"METRICS_OUTBOX_MAX_AGE_DAYS={METRICS_OUTBOX_MAX_AGE_DAYS})"
        )
    if status == WriteStatus.WRITTEN_TTL_FAILED:
        raise MetricsTtlError(
            f"QuestDB retention (TTL {QUESTDB_TTL!r}, downsampling {QUESTDB_DOWNSAMPLING or 'off'!r}) could not "
            f"be applied to {QUESTDB_TABLE!r}; the points were written and are not sent again"
        )
    return ok


def _send_spooled(lines: list[str] | None, spooled: bool) -> WriteStatus:
    """Send the spooled rows (or the bare lines when spooling failed)."""
    if not spooled:
        try:
            status = write_points(lines or [])
        except MetricsGateError as e:
            # Not spooled and not written: the gate failure is a real loss here.
            raise MetricsLostError(
                f"{len(lines or [])} metrics point(s) could neither be spooled nor written: {e}"
            ) from e
        if status:
            return status
        raise MetricsLostError(f"{len(lines or [])} metrics point(s) could neither be spooled nor written")

    pending = load_metric_points(_FLUSH_BATCH_LIMIT)
    if not pending:
        return WriteStatus.OK

    ids = [row_id for row_id, _ in pending]
    # A MetricsGateError propagates from here with every row still in the outbox.
    status = write_points([line for _, line in pending])
    if not status:
        print_warning(
            f"{len(pending)} metrics point(s) stay in the outbox and will be retried on the next run (nothing lost)",
        )
        return WriteStatus.NOT_WRITTEN

    delete_metric_points(ids)
    remaining = count_metric_points()
    if remaining:
        print_config_info(f"{remaining} spooled metrics point(s) left for the next run")
    return status


def ensure_questdb_version() -> bool:
    """Accept only a QuestDB server of major version 10; the verdict is cached per process."""
    return _CLIENT.ensure_version()


def ensure_questdb_table(table: str, keys: tuple[str, ...]) -> bool:
    """Make sure the table exists with verified deduplication before it is written."""
    return _CLIENT.ensure_table(table, keys)


def ensure_questdb_ttl(table: str, ttl: str | None) -> bool:
    """Apply a TTL clause to the table via `/exec`; None lifts an existing TTL."""
    return _CLIENT.ensure_ttl(table, ttl)


def questdb_rollup_baseline(table: str, rollup: RollupSpec | None) -> int | None:
    """Base-table transaction of the rollup view before this run writes."""
    return _CLIENT.rollup_baseline(table, rollup)


def apply_questdb_retention(table: str, rollup: RollupSpec | None, baseline_txn: int | None = None) -> bool:
    """Verify the rollup, apply the raw TTL, then publish the effective state."""
    return _CLIENT.apply_retention(table, rollup, baseline_txn)


# Downsampling rollup for the report table. Dimensions must be a subset of
# DEDUP_KEYS (QuestDB rule); `ip_address`, `as_number` and `as_name` are dropped,
# which is what shrinks the history. `abuse_email`, `error_message` (strings) and
# `alert_id` (an identity) have no meaningful aggregate and are not carried over.
ROLLUP = RollupSpec(
    dimensions=("host", "country", "scenario", "status"),
    aggregates=(
        ("reports_count", "count", ""),
        ("processing_time_avg", "avg", "processing_time"),
        ("processing_time_max", "max", "processing_time"),
    ),
)
