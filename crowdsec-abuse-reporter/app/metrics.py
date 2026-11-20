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

import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, IntEnum
from pathlib import Path

import httpx

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


def _questdb_auth() -> tuple[dict[str, str], tuple[str, str] | None]:
    """Build the headers/auth pair for a QuestDB request.

    QuestDB accepts either a bearer token or HTTP basic auth for its
    ILP-over-HTTP endpoints; a token takes precedence if both are set.
    """
    headers: dict[str, str] = {}
    auth = None
    if QUESTDB_TOKEN:
        headers["Authorization"] = f"Bearer {QUESTDB_TOKEN}"
    elif QUESTDB_USERNAME and QUESTDB_PASSWORD:
        auth = (QUESTDB_USERNAME, QUESTDB_PASSWORD)
    return headers, auth


def _questdb_url(endpoint: str) -> str:
    """Build a QuestDB endpoint URL from the configured protocol/host/port."""
    protocol = "https" if QUESTDB_USE_HTTPS else "http"
    return f"{protocol}://{QUESTDB_URL}:{QUESTDB_PORT}/{endpoint}"


def send_to_questdb(payload: str) -> bool:
    url = _questdb_url("write")
    headers, auth = _questdb_auth()
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


def _quote_ident(name: str) -> str:
    """Double-quote a QuestDB identifier, doubling embedded quotes."""
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def _quote_literal(value: str) -> str:
    """Single-quote a QuestDB string literal, doubling embedded quotes."""
    return "'" + str(value).replace("'", "''") + "'"


# Bounded backoff for transient /exec failures (transport errors, 5xx, 429).
# A 4xx is a definite answer and is never retried.
_RETRY_BACKOFF_SECONDS = (0.5, 1.0, 2.0)
# The WAL apply of an ALTER can lag behind its HTTP response; the gate polls
# the metadata this many times, this long apart, before giving up.
_VERIFY_POLLS = 5
_VERIFY_INTERVAL_SECONDS = 1.0


def _query_exec(query: str, *, warning_prefix: str, retries: int = 0) -> list | None:
    """Run a statement against QuestDB's `/exec` SQL endpoint.

    Returns the result rows (an empty list for DDL) on HTTP 200, None
    otherwise. Failures are only warned about, never raised: callers decide
    what a failed statement means. With `retries`, transport errors, 5xx and
    429 are repeated with a bounded backoff; any other status is final.
    """
    headers, auth = _questdb_auth()
    response = None
    for attempt in range(retries + 1):
        try:
            with httpx.Client(verify=QUESTDB_VALIDATE_CERTIFICATE, timeout=REQUEST_TIMEOUT) as client:
                response = client.get(_questdb_url("exec"), params={"query": query}, headers=headers, auth=auth)
            if response.status_code == 200:
                break
            problem = f"{response.status_code} - {response.text[:300]}"
            transient = response.status_code == 429 or response.status_code >= 500
        except httpx.HTTPError as e:
            problem, transient = str(e), True
        if not transient or attempt == retries:
            print_warning(f"{warning_prefix}: {problem}")
            return None
        print_info(f"{warning_prefix}: {problem} - retrying ({attempt + 1}/{retries})")
        time.sleep(_RETRY_BACKOFF_SECONDS[min(attempt, len(_RETRY_BACKOFF_SECONDS) - 1)])
    try:
        payload = response.json()
    except ValueError:
        return []
    dataset = payload.get("dataset") if isinstance(payload, dict) else None
    return dataset if isinstance(dataset, list) else []


def _run_exec(query: str, *, warning_prefix: str, retries: int = 0) -> bool:
    """Run a statement and report only whether it succeeded."""
    return _query_exec(query, warning_prefix=warning_prefix, retries=retries) is not None


def ensure_questdb_ttl(table: str, ttl: str | None) -> bool:
    """Apply a TTL clause to the table via QuestDB's /exec SQL endpoint.

    `ttl` is the raw TTL from `ensure_questdb_downsampling()`: QUESTDB_TTL, or
    the shorter raw window when a profile is active. ILP auto-creates tables
    without a TTL, so this runs after every successful write; ALTER TABLE ...
    SET TTL is idempotent. Needs a partitioned table (ILP tables are
    partitioned by DAY). `None` (retention off) lifts an existing TTL.
    Returns False when the TTL could not be set; the data is already stored
    and is never resent for that reason.
    """
    # TTL 0 removes a TTL (https://questdb.com/docs/concepts/ttl/#removing-ttl).
    query = f"ALTER TABLE {_quote_ident(table)} SET TTL {ttl or '0 HOURS'}"
    return _run_exec(query, warning_prefix=f"QuestDB TTL not applied to {table!r}")


# Per-process outcome of the table gate; the container starts a new process per run.
_GATE_RESULTS: dict[str, tuple[tuple[str, ...], bool]] = {}

_VERIFIED, _PENDING, _FAILED = "verified", "pending", "failed"


def _verify_dedup(table: str, keys: tuple[str, ...]) -> tuple[str, str]:
    """Check the table's WAL flag, dedup flag, key set and mode from QuestDB metadata.

    Returns (verdict, detail). `_PENDING` means the metadata may still be
    catching up with the ALTER; `_FAILED` is final.
    """
    literal = _quote_literal(table)
    state = _query_exec(
        f"SELECT dedup, walEnabled FROM tables() WHERE table_name = {literal}",
        warning_prefix=f"QuestDB table state of {table!r} not readable",
        retries=len(_RETRY_BACKOFF_SECONDS),
    )
    if state is None:
        return _FAILED, "table state not readable"
    if not state:
        return _PENDING, "table is not listed yet"
    dedup, wal_enabled = state[0][:2]
    if wal_enabled is not True:
        return _FAILED, "table is not a WAL table, so DEDUP cannot apply"
    if dedup is not True:
        return _PENDING, "dedup is not active yet"

    rows = _query_exec(
        f'SELECT "column" FROM table_columns({literal}) WHERE upsertKey = true',
        warning_prefix=f"QuestDB upsert keys of {table!r} not readable",
        retries=len(_RETRY_BACKOFF_SECONDS),
    )
    if rows is None:
        return _FAILED, "upsert keys not readable"
    actual = {str(row[0]) for row in rows if row}
    expected = set(keys)
    if actual != expected:
        return _PENDING, (
            f"upsert keys differ: missing {sorted(expected - actual)}, unexpected {sorted(actual - expected)}"
        )

    # tables() and table_columns() expose dedup state and keys, but only SHOW
    # CREATE TABLE exposes whether duplicates replace old rows or are skipped.
    ddl = _query_exec(
        f"SHOW CREATE TABLE {_quote_ident(table)}",
        warning_prefix=f"QuestDB DDL of {table!r} not readable, dedup mode not checked",
    )
    if not ddl or not ddl[0] or not ddl[0][0]:
        return _FAILED, "dedup mode not readable"
    if not re.search(r"\bDEDUP\s+UPSERT\s+KEYS\s*\(", str(ddl[0][0]), re.IGNORECASE):
        return _FAILED, "dedup mode is not UPSERT"
    return _VERIFIED, ""


def _provision_table(table: str, keys: tuple[str, ...]) -> bool:
    """Create the table with its dedup keys, enable dedup and verify it; see `ensure_questdb_table`."""
    quoted_table = _quote_ident(table)
    quoted_keys = ", ".join(_quote_ident(key) for key in keys)
    retries = len(_RETRY_BACKOFF_SECONDS)

    before = _query_exec(
        f"SELECT dedup FROM tables() WHERE table_name = {_quote_literal(table)}",
        warning_prefix=f"QuestDB table state of {table!r} not readable",
        retries=retries,
    )
    if before is None:
        return False
    had_duplicate_risk = bool(before) and before[0][0] is False

    # Only the key columns are declared; ILP adds every other column on first write.
    columns = ", ".join(f"{_quote_ident(key)} {'TIMESTAMP' if i == 0 else 'SYMBOL'}" for i, key in enumerate(keys))
    create = (
        f"CREATE TABLE IF NOT EXISTS {quoted_table} ({columns}) TIMESTAMP({_quote_ident(keys[0])}) "
        f"PARTITION BY DAY WAL DEDUP UPSERT KEYS({quoted_keys})"
    )
    if not _run_exec(create, warning_prefix=f"QuestDB table {table!r} not created", retries=retries):
        return False
    alter = f"ALTER TABLE {quoted_table} DEDUP ENABLE UPSERT KEYS({quoted_keys})"
    if not _run_exec(alter, warning_prefix=f"QuestDB dedup not enabled on {table!r}", retries=retries):
        return False

    verdict, detail = _PENDING, ""
    for poll in range(_VERIFY_POLLS):
        verdict, detail = _verify_dedup(table, keys)
        if verdict != _PENDING:
            break
        if poll < _VERIFY_POLLS - 1:
            time.sleep(_VERIFY_INTERVAL_SECONDS)
    if verdict != _VERIFIED:
        print_error(f"QuestDB dedup on {table!r} could not be verified: {detail}")
        return False

    print_debug(f"QuestDB dedup verified on {table!r}: {', '.join(keys)}")
    if had_duplicate_risk:
        print_warning(
            f"Dedup was just enabled on existing table {table!r}: rows stored earlier are NOT deduplicated. "
            "See the duplicate cleanup runbook in docs/reference/metrics-backends.md"
        )
    return True


def ensure_questdb_table(table: str, keys: tuple[str, ...]) -> bool:
    """Make sure the table exists with verified deduplication before it is written.

    ILP auto-creates a table without dedup, so a write that precedes this gate
    can store a first batch that later replays duplicate. The gate runs
    `CREATE TABLE IF NOT EXISTS` with only the key columns, re-declares
    `DEDUP ENABLE UPSERT KEYS` (WAL table) and reads the flags,
    key set and mode back; any mismatch, including a table another tool owns
    with different keys, fails it. The caller must not write on False. The
    designated timestamp is `keys[0]`. The result is cached per table and process.
    Enabling dedup does not remove rows stored before; that is a manual step.
    """
    if not keys:
        return True
    cached = _GATE_RESULTS.get(table)
    if cached is not None:
        cached_keys, result = cached
        if cached_keys != keys:
            print_error(f"QuestDB table {table!r} was already checked with different dedup keys")
            return False
        return result
    result = _provision_table(table, keys)
    _GATE_RESULTS[table] = (keys, result)
    return result


REQUIRED_QUESTDB_MAJOR = 10
_BUILD_VERSION = re.compile(r"\bQuestDB\s+(\d+)\.(\d+)(?:\.(\d+))?")
# Per-process verdict of the version check, keyed by nothing: one server per process.
_VERSION_RESULT: dict[str, bool] = {}


def _parse_questdb_version(build_info: object) -> tuple[int, ...] | None:
    """Extract the version from a `build()` answer like `Build Information: QuestDB 10.0.0, JDK 25, ...`."""
    match = _BUILD_VERSION.search(str(build_info))
    if match is None:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def ensure_questdb_version() -> bool:
    """Accept only a QuestDB server of major version 10; the verdict is cached per process.

    Reads `SELECT build()` via `/exec` (transient errors are retried). An
    unreachable server, an error response, an unparsable answer and any other
    major version are rejected; the caller must then neither write nor run DDL.
    """
    if "ok" in _VERSION_RESULT:
        return _VERSION_RESULT["ok"]
    rows = _query_exec(
        "SELECT build()",
        warning_prefix="QuestDB version not readable",
        retries=len(_RETRY_BACKOFF_SECONDS),
    )
    version = _parse_questdb_version(rows[0][0]) if rows and rows[0] else None
    ok = version is not None and version[0] == REQUIRED_QUESTDB_MAJOR
    if ok:
        print_debug(f"QuestDB version {'.'.join(map(str, version))} accepted")
    else:
        found = ".".join(map(str, version)) if version else "unknown"
        print_error(
            f"Unsupported QuestDB version at {_questdb_url('').rstrip('/')}: found {found}, "
            f"required {REQUIRED_QUESTDB_MAJOR}.x; nothing was written"
        )
    _VERSION_RESULT["ok"] = ok
    return ok


@dataclass(frozen=True)
class RollupSpec:
    """How one table is aggregated into its downsampling rollup view.

    `dimensions` are the tag columns the rollup keeps; every tag left out is
    what actually shrinks the long-term history. `aggregates` are
    (alias, function, column) triples, where an empty column means a
    no-argument aggregate such as `count()`.

    QuestDB requires the non-aggregate columns of a materialized view to be a
    subset of the base table's DEDUP keys, so `dimensions` must stay within the
    dedup keys declared for that table.
    """

    dimensions: tuple[str, ...]
    aggregates: tuple[tuple[str, str, str], ...]


class DownsamplingStatus(Enum):
    DISABLED = "disabled"
    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"


@dataclass(frozen=True)
class DownsamplingResult:
    """Raw TTL to apply plus the effective state to publish once it is in force."""

    raw_ttl: str | None
    status: DownsamplingStatus
    raw_days: int = 0
    profile: str = QUESTDB_DOWNSAMPLING_DISABLED_PROFILE
    rollup_interval: str = ""
    rollup_view: str = ""


def questdb_rollup_view_name(table: str, interval: str) -> str:
    """Name of the rollup view for a table and sample interval.

    The schema-version suffix makes definition changes additive: a bump creates
    a new view instead of colliding with one an older build defined.
    """
    return f"{table}_rollup_{interval}_v{QUESTDB_DOWNSAMPLING_SCHEMA_VERSION}"


def _table_columns(table: str) -> set[str] | None:
    """Column names of an existing table, or None when they cannot be read."""
    # "column" is a SQL keyword and has to stay quoted.
    rows = _query_exec(
        f'SELECT "column" FROM table_columns({_quote_literal(table)})',
        warning_prefix=f"QuestDB columns of {table!r} not readable",
    )
    if rows is None:
        return None
    return {str(row[0]) for row in rows if row}


def _rollup_ddl(table: str, interval: str, rollup: RollupSpec, columns: set[str], ttl: str | None) -> str | None:
    """Build the CREATE MATERIALIZED VIEW statement, or None if it cannot apply.

    Dimensions and aggregate sources are filtered against the columns that
    actually exist: ILP creates a column only once a line carries it, so an
    empty tag can still be missing on an otherwise populated table.
    """
    aggregates = [
        f"{function}({_quote_ident(column) if column else ''}) AS {_quote_ident(alias)}"
        for alias, function, column in rollup.aggregates
        if not column or column in columns
    ]
    if not aggregates:
        return None

    projections = ["timestamp"]
    projections.extend(_quote_ident(name) for name in rollup.dimensions if name in columns)
    projections.extend(aggregates)

    view_name = questdb_rollup_view_name(table, interval)
    select_list = ",\n        ".join(projections)
    ttl_clause = f" TTL {ttl}" if ttl else ""
    return (
        f"CREATE MATERIALIZED VIEW IF NOT EXISTS {_quote_ident(view_name)} "
        f"WITH BASE {_quote_ident(table)} REFRESH IMMEDIATE AS (\n"
        f"    SELECT\n        {select_list}\n"
        f"    FROM {_quote_ident(table)}\n"
        f"    SAMPLE BY {interval} ALIGN TO CALENDAR\n"
        f") PARTITION BY DAY{ttl_clause}"
    )


# Consecutive runs a rollup view has stayed behind, per view and process. A one-shot
# process never reaches the threshold; the state table still shows `enabled = false`.
_PENDING_RUNS: dict[str, int] = {}
_PENDING_WARN_AFTER = 5


def _rollup_status_rows(view_name: str) -> list | None:
    """Row of `materialized_views()` for the view, or None when it cannot be read."""
    return _query_exec(
        "SELECT view_name, base_table_name, view_status, refresh_base_table_txn, "
        f"base_table_txn FROM materialized_views() WHERE view_name = {_quote_literal(view_name)}",
        warning_prefix=f"QuestDB rollup status of {view_name!r} not readable",
    )


def questdb_rollup_baseline(table: str, rollup: RollupSpec | None) -> int | None:
    """Base-table transaction of the rollup view before this run writes.

    Call it before the ILP write: the refresh is asynchronous, so a check after
    the write races its own data. None when downsampling is off, the view does
    not exist yet or the value is unreadable; the view then counts as not caught up.
    """
    if not QUESTDB_DOWNSAMPLING or rollup is None:
        return None
    view_name = questdb_rollup_view_name(table, QUESTDB_DOWNSAMPLING_PROFILES[QUESTDB_DOWNSAMPLING].rollup_interval)
    rows = _rollup_status_rows(view_name)
    if not rows or len(rows[0]) < 5 or not isinstance(rows[0][4], int):
        return None
    return rows[0][4]


def _rollup_pending(view_name: str, reason: str) -> DownsamplingStatus:
    """Log a view that is not caught up: INFO at first, WARNING once it persists."""
    runs = _PENDING_RUNS.get(view_name, 0) + 1
    _PENDING_RUNS[view_name] = runs
    message = f"QuestDB rollup view {view_name!r} {reason}; raw TTL unchanged"
    if runs >= _PENDING_WARN_AFTER:
        print_warning(f"{message} ({runs} consecutive runs)")
    else:
        print_info(message)
    return DownsamplingStatus.PENDING


def _rollup_is_current(view_name: str, table: str, baseline_txn: int | None = None) -> DownsamplingStatus:
    """Report whether the view covers all data older than this run, or failed verification.

    The view is current once `refresh_base_table_txn` has reached `baseline_txn`,
    the base-table transaction read before this run's write. The refresh is
    asynchronous, so comparing against `base_table_txn` after the write would lag
    on every run; this run's own rows are newer than any raw TTL. The raw TTL is
    shortened only when current, so no interval is dropped before the rollup
    covers it. Still refreshing or lagging is the normal path (INFO); an invalid
    view, an unreadable or wrong status warn.
    """
    rows = _rollup_status_rows(view_name)
    if rows is None:
        print_warning(f"QuestDB rollup status of {view_name!r} could not be verified; raw TTL unchanged")
        return DownsamplingStatus.FAILED
    if not rows:
        return _rollup_pending(view_name, "is not listed yet")

    if len(rows[0]) < 5:
        print_warning(f"QuestDB rollup status of {view_name!r} is incomplete; raw TTL unchanged")
        return DownsamplingStatus.FAILED

    actual_view, actual_base, status, refresh_txn, _base_txn = rows[0][:5]
    if str(actual_view) != view_name or str(actual_base) != table:
        print_warning(f"QuestDB rollup view {view_name!r} has an unexpected base table; raw TTL unchanged")
        return DownsamplingStatus.FAILED
    state = str(status).lower()
    if state in {"invalid", "failed"}:
        print_warning(f"QuestDB rollup view {view_name!r} is {state}; raw TTL unchanged")
        return DownsamplingStatus.FAILED
    if state not in {"valid", "refreshing"}:
        print_warning(f"QuestDB rollup view {view_name!r} has an unknown status {status!r}; raw TTL unchanged")
        return DownsamplingStatus.PENDING
    if baseline_txn is None:
        return _rollup_pending(view_name, "was just created and is still populating")
    if not isinstance(refresh_txn, int):
        return _rollup_pending(view_name, f"has not refreshed yet (status={state})")
    if refresh_txn >= baseline_txn:
        _PENDING_RUNS.pop(view_name, None)
        return DownsamplingStatus.ACTIVE
    return _rollup_pending(
        view_name,
        f"is still refreshing (status={state}, refresh txn={refresh_txn}, base txn at run start={baseline_txn})",
    )


def _publish_downsampling_state(
    table: str,
    *,
    enabled: bool,
    profile_name: str,
    raw_days: int,
    rollup_interval: str = "",
    rollup_view: str = "",
) -> None:
    """Write the effective retention of a table into the state table.

    This is what makes retention visible to Grafana: the raw window, the rollup
    view and the configured total TTL are queryable instead of living only in
    `settings.env`. A row is only inserted when the state actually changed.
    """
    state_table = _quote_ident(QUESTDB_DOWNSAMPLING_STATE_TABLE)
    total_ttl = QUESTDB_TTL or ""
    created = _run_exec(
        f"CREATE TABLE IF NOT EXISTS {state_table} ("
        "timestamp TIMESTAMP, table_name SYMBOL, profile SYMBOL, schema_version LONG, "
        "enabled BOOLEAN, raw_days LONG, rollup_interval SYMBOL, rollup_view SYMBOL, "
        "total_ttl SYMBOL) TIMESTAMP(timestamp) PARTITION BY DAY",
        warning_prefix="QuestDB downsampling state table not available",
    )
    if not created:
        return

    current = _query_exec(
        "SELECT profile, schema_version, enabled, raw_days, rollup_interval, rollup_view, "
        f"total_ttl FROM {state_table} WHERE table_name = {_quote_literal(table)} "
        "LATEST ON timestamp PARTITION BY table_name",
        warning_prefix=f"QuestDB downsampling state of {table!r} not readable",
    )
    if current is None:
        return

    expected = [
        profile_name,
        QUESTDB_DOWNSAMPLING_SCHEMA_VERSION,
        enabled,
        raw_days,
        rollup_interval,
        rollup_view,
        total_ttl,
    ]
    # Empty SYMBOL values may come back as NULL, which would otherwise re-insert every run.
    if current and ["" if value is None else value for value in current[0][:7]] == expected:
        return

    _run_exec(
        f"INSERT INTO {state_table} (timestamp, table_name, profile, schema_version, enabled, "
        "raw_days, rollup_interval, rollup_view, total_ttl) VALUES ("
        f"now(), {_quote_literal(table)}, {_quote_literal(profile_name)}, "
        f"{QUESTDB_DOWNSAMPLING_SCHEMA_VERSION}, {'true' if enabled else 'false'}, "
        f"{int(raw_days)}, {_quote_literal(rollup_interval)}, {_quote_literal(rollup_view)}, "
        f"{_quote_literal(total_ttl)})",
        warning_prefix=f"QuestDB downsampling state of {table!r} not updated",
    )


def _unchanged(status: DownsamplingStatus) -> DownsamplingResult:
    """Full raw retention and no rollup in effect."""
    return DownsamplingResult(QUESTDB_TTL, status, raw_days=QUESTDB_TTL_DAYS or 0)


def ensure_questdb_downsampling(
    table: str, rollup: RollupSpec | None, baseline_txn: int | None = None
) -> DownsamplingResult:
    """Verify the rollup view and decide the raw TTL; nothing is published here.

    Order: columns, `CREATE MATERIALIZED VIEW IF NOT EXISTS`, the view's own TTL
    (independent of the base table; `0 HOURS` removes it when QUESTDB_TTL is off),
    then readiness from `materialized_views()`. The profile's short raw window is
    returned only for a valid, caught-up view; otherwise QUESTDB_TTL stays, so no
    interval is dropped before the rollup covers it. A pending refresh does not
    fail the run, failed DDL or verification does (status FAILED).
    """
    if not QUESTDB_DOWNSAMPLING or rollup is None:
        return _unchanged(DownsamplingStatus.DISABLED)

    profile = QUESTDB_DOWNSAMPLING_PROFILES[QUESTDB_DOWNSAMPLING]
    raw_days = profile.raw_retention_days
    if QUESTDB_TTL_DAYS is not None:
        if QUESTDB_TTL_DAYS <= 0:
            # A sub-day QUESTDB_TTL is already shorter than any profile window.
            return _unchanged(DownsamplingStatus.PENDING)
        raw_days = min(raw_days, QUESTDB_TTL_DAYS)

    columns = _table_columns(table)
    if columns is None:
        return _unchanged(DownsamplingStatus.FAILED)
    if not columns:
        return _unchanged(DownsamplingStatus.PENDING)

    ddl = _rollup_ddl(table, profile.rollup_interval, rollup, columns, QUESTDB_TTL)
    if ddl is None:
        print_warning(f"QuestDB rollup for {table!r} skipped: none of its aggregate columns exist yet")
        return _unchanged(DownsamplingStatus.FAILED)

    view_name = questdb_rollup_view_name(table, profile.rollup_interval)
    if not _run_exec(ddl, warning_prefix=f"QuestDB rollup view {view_name!r} not provisioned"):
        print_error(f"QuestDB downsampling is inactive on {table!r}: the raw TTL stays at its full length")
        return _unchanged(DownsamplingStatus.FAILED)
    # A view created before a TTL change keeps its old TTL, and QUESTDB_TTL=0 must lift it:
    # SET TTL is idempotent, so re-declare it every run.
    if not _run_exec(
        f"ALTER MATERIALIZED VIEW {_quote_ident(view_name)} SET TTL {QUESTDB_TTL or '0 HOURS'}",
        warning_prefix=f"QuestDB TTL not applied to rollup view {view_name!r}",
    ):
        return _unchanged(DownsamplingStatus.FAILED)
    readiness = _rollup_is_current(view_name, table, baseline_txn)
    if readiness is not DownsamplingStatus.ACTIVE:
        return _unchanged(readiness)
    return DownsamplingResult(
        f"{raw_days} DAYS",
        DownsamplingStatus.ACTIVE,
        raw_days=raw_days,
        profile=QUESTDB_DOWNSAMPLING,
        rollup_interval=profile.rollup_interval,
        rollup_view=view_name,
    )


def apply_questdb_retention(table: str, rollup: RollupSpec | None, baseline_txn: int | None = None) -> bool:
    """Verify the rollup, apply the raw TTL, then publish the effective state.

    Returns True only when retention and rollup are fully configured. The state
    is published only after the raw TTL is in force and says `enabled` only for a
    rollup that is valid and current, so it never claims more than QuestDB holds.
    """
    result = ensure_questdb_downsampling(table, rollup, baseline_txn)
    if not ensure_questdb_ttl(table, result.raw_ttl):
        return False
    active = result.status is DownsamplingStatus.ACTIVE
    _publish_downsampling_state(
        table,
        enabled=active,
        profile_name=result.profile,
        raw_days=result.raw_days,
        rollup_interval=result.rollup_interval,
        rollup_view=result.rollup_view,
    )
    if active:
        print_info(
            f"QuestDB downsampling {result.profile!r} active on {table!r}: "
            f"raw {result.raw_days} day(s), rollup {result.rollup_interval} in {result.rollup_view!r}"
        )
    return result.status is not DownsamplingStatus.FAILED


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
