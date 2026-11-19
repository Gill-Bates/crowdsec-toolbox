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
from datetime import UTC, datetime
from enum import IntEnum
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
    QUESTDB_PASSWORD,
    QUESTDB_PORT,
    QUESTDB_TABLE,
    QUESTDB_TOKEN,
    QUESTDB_TTL,
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
from app.logger import TAGS, print_config_info, print_database_error, print_log

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
            print_log(
                "WARNING",
                TAGS["WARNING"],
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

    A bearer token takes precedence over basic auth, as in the sibling tool.
    """
    headers: dict[str, str] = {}
    auth = None
    if QUESTDB_TOKEN:
        headers["Authorization"] = f"Bearer {QUESTDB_TOKEN}"
    elif QUESTDB_USERNAME and QUESTDB_PASSWORD:
        auth = (QUESTDB_USERNAME, QUESTDB_PASSWORD)
    return headers, auth


def send_to_questdb(payload: str) -> bool:
    protocol = "https" if QUESTDB_USE_HTTPS else "http"
    url = f"{protocol}://{QUESTDB_URL}:{QUESTDB_PORT}/write"
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


def write_points(lines: list[str]) -> WriteStatus:
    """Send all points in one request to the configured backend.

    Truthy when there is nothing to send or the backend accepted the batch.
    For QuestDB the table gate (`ensure_questdb_table`) runs first and raises
    MetricsGateError without writing anything when the server is not QuestDB 10.x
    or dedup cannot be verified.
    Callers that must not lose the points use `flush_points()`, which persists
    them first; this function is the bare write.
    """
    if not lines:
        return WriteStatus.OK
    payload = "\n".join(lines)
    status = WriteStatus.OK
    if METRICS_BACKEND == "questdb":
        if not ensure_questdb_version():
            raise MetricsGateError(
                f"QuestDB version check failed; {len(lines)} point(s) were not written (they stay in the outbox)"
            )
        if not ensure_questdb_table(QUESTDB_TABLE, DEDUP_KEYS):
            raise MetricsGateError(
                f"QuestDB dedup on {QUESTDB_TABLE!r} could not be verified; {len(lines)} point(s) were not written "
                "(they stay in the outbox). See the duplicate cleanup runbook in docs/reference/metrics-backends.md"
            )
        if not send_to_questdb(payload):
            return WriteStatus.NOT_WRITTEN
        if not ensure_questdb_ttl(QUESTDB_TABLE):
            status = WriteStatus.WRITTEN_TTL_FAILED
    elif METRICS_BACKEND == "influxdb2":
        if not send_to_influxdb(payload):
            return WriteStatus.NOT_WRITTEN
    else:
        return WriteStatus.OK
    print_config_info(f"Wrote {len(lines)} report point(s) to {METRICS_BACKEND}")
    return status


class MetricsError(RuntimeError):
    """Base of the metrics failures that must fail the run (exit 1)."""


class MetricsGateError(MetricsError):
    """The QuestDB dedup gate failed: nothing was written, the outbox rows are kept."""


class MetricsTtlError(MetricsError):
    """The batch was written and acknowledged, but the configured QuestDB TTL was not applied."""


class MetricsLostError(MetricsError):
    """Points were neither persisted to the outbox nor accepted by the backend."""


class MetricsPrunedError(MetricsLostError):
    """Undelivered points were dropped from the outbox by its row or age bound."""


def flush_points(lines: list[str] | None = None) -> bool:
    """Persist *lines*, then send everything the backend has not acknowledged.

    The durable path for report points. New points go into the SQLite outbox
    before any network call, so a failed write defers them to the next run
    instead of losing them. Everything still spooled is sent together, and rows
    are deleted only after the backend acknowledged the batch.

    Replaying is deliberately not selective: a point carries its own timestamp
    and every dedup key, so re-sending one the backend already has collapses onto
    the same row. That is what makes it safe to resend the whole spool rather
    than track which point of a batch failed.

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
            f"QuestDB TTL {QUESTDB_TTL!r} could not be applied to {QUESTDB_TABLE!r}; the points were written "
            "and are not sent again"
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

    # A batch cap keeps one run from building a multi-megabyte request after a
    # long outage; the remainder goes out on the following run.
    pending = load_metric_points(_FLUSH_BATCH_LIMIT)
    if not pending:
        return WriteStatus.OK

    ids = [row_id for row_id, _ in pending]
    # A MetricsGateError propagates from here with every row still in the outbox.
    status = write_points([line for _, line in pending])
    if not status:
        print_log(
            "WARNING",
            TAGS["WARNING"],
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
    protocol = "https" if QUESTDB_USE_HTTPS else "http"
    url = f"{protocol}://{QUESTDB_URL}:{QUESTDB_PORT}/exec"
    headers, auth = _questdb_auth()
    response = None
    for attempt in range(retries + 1):
        try:
            with httpx.Client(verify=QUESTDB_VALIDATE_CERTIFICATE, timeout=REQUEST_TIMEOUT) as client:
                response = client.get(url, params={"query": query}, headers=headers, auth=auth)
            if response.status_code == 200:
                break
            problem = f"{response.status_code} - {response.text[:300]}"
            transient = response.status_code == 429 or response.status_code >= 500
        except httpx.HTTPError as e:
            problem, transient = str(e), True
        if not transient or attempt == retries:
            print_log("WARNING", TAGS["WARNING"], f"{warning_prefix}: {problem}")
            return None
        print_log("INFO", TAGS["INFO"], f"{warning_prefix}: {problem} - retrying ({attempt + 1}/{retries})")
        time.sleep(_RETRY_BACKOFF_SECONDS[min(attempt, len(_RETRY_BACKOFF_SECONDS) - 1)])
    try:
        payload = response.json()
    except ValueError:
        return []
    dataset = payload.get("dataset") if isinstance(payload, dict) else None
    return dataset if isinstance(dataset, list) else []


def ensure_questdb_ttl(table: str) -> bool:
    """Apply QUESTDB_TTL to the table via QuestDB's /exec SQL endpoint.

    ILP auto-creates tables without a TTL, so this runs after every successful
    write; ALTER TABLE ... SET TTL is idempotent. Needs a
    partitioned table (ILP tables are partitioned by DAY). Returns False when a
    configured TTL could not be set; the data is already stored and is never
    resent for that reason.
    """
    if not QUESTDB_TTL:
        return True
    query = f"ALTER TABLE {_quote_ident(table)} SET TTL {QUESTDB_TTL}"
    return _query_exec(query, warning_prefix=f"QuestDB TTL not applied to {table!r}") is not None


# Per-process outcome of the table gate; the container starts a new process per run.
_GATE_RESULTS: dict[str, bool] = {}

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

    # The mode is only readable through SHOW CREATE TABLE; where it cannot be
    # read, the key check above stands, since ENABLE UPSERT KEYS sets the mode.
    ddl = _query_exec(
        f"SHOW CREATE TABLE {_quote_ident(table)}",
        warning_prefix=f"QuestDB DDL of {table!r} not readable, dedup mode not checked",
    )
    if ddl and ddl[0] and "DEDUP SKIP" in str(ddl[0][0]).upper():
        return _FAILED, "dedup runs in SKIP mode, UPSERT is required"
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
    # Empty tags are omitted from a line, so a key column would otherwise be missing.
    columns = ", ".join(f"{_quote_ident(key)} {'TIMESTAMP' if i == 0 else 'SYMBOL'}" for i, key in enumerate(keys))
    create = (
        f"CREATE TABLE IF NOT EXISTS {quoted_table} ({columns}) TIMESTAMP({_quote_ident(keys[0])}) "
        f"PARTITION BY DAY WAL DEDUP UPSERT KEYS({quoted_keys})"
    )
    if _query_exec(create, warning_prefix=f"QuestDB table {table!r} not created", retries=retries) is None:
        return False
    alter = f"ALTER TABLE {quoted_table} DEDUP ENABLE UPSERT KEYS({quoted_keys})"
    if _query_exec(alter, warning_prefix=f"QuestDB dedup not enabled on {table!r}", retries=retries) is None:
        return False

    verdict, detail = _PENDING, ""
    for poll in range(_VERIFY_POLLS):
        verdict, detail = _verify_dedup(table, keys)
        if verdict != _PENDING:
            break
        if poll < _VERIFY_POLLS - 1:
            time.sleep(_VERIFY_INTERVAL_SECONDS)
    if verdict != _VERIFIED:
        print_log("ERROR", TAGS["ERROR"], f"QuestDB dedup on {table!r} could not be verified: {detail}")
        return False

    print_log("INFO", TAGS["INFO"], f"QuestDB dedup verified on {table!r}: {', '.join(keys)}")
    if had_duplicate_risk:
        print_log(
            "WARNING",
            TAGS["WARNING"],
            f"Dedup was just enabled on existing table {table!r}: rows stored earlier are NOT deduplicated. "
            "See the duplicate cleanup runbook in docs/reference/metrics-backends.md",
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

    InfluxDB 2.x needs no equivalent: it overwrites a point that repeats an
    existing series and timestamp.
    """
    if not keys:
        return True
    if table not in _GATE_RESULTS:
        _GATE_RESULTS[table] = _provision_table(table, keys)
    return _GATE_RESULTS[table]


REQUIRED_QUESTDB_MAJOR = 10
_BUILD_VERSION = re.compile(r"\bQuestDB\s+(\d+)\.(\d+)(?:\.(\d+))?")
# Per-process verdict of the version check, keyed by nothing: one server per process.
_VERSION_RESULT: dict[str, bool] = {}


def ensure_questdb_version() -> bool:
    """Accept only a QuestDB server of major version 10; the verdict is cached per process.

    Reads `SELECT build()` via `/exec` (transient errors are retried). An
    unreachable server, an error response, an unparsable answer and any other
    major version are rejected, and the caller must not write anything.
    """
    if "ok" in _VERSION_RESULT:
        return _VERSION_RESULT["ok"]
    rows = _query_exec(
        "SELECT build()",
        warning_prefix="QuestDB version not readable",
        retries=len(_RETRY_BACKOFF_SECONDS),
    )
    match = _BUILD_VERSION.search(str(rows[0][0])) if rows and rows[0] else None
    version = ".".join(part for part in match.groups() if part is not None) if match else None
    ok = match is not None and int(match.group(1)) == REQUIRED_QUESTDB_MAJOR
    if ok:
        print_log("INFO", TAGS["INFO"], f"QuestDB version {version} accepted")
    else:
        protocol = "https" if QUESTDB_USE_HTTPS else "http"
        print_log(
            "ERROR",
            TAGS["ERROR"],
            f"Unsupported QuestDB version at {protocol}://{QUESTDB_URL}:{QUESTDB_PORT}: "
            f"found {version or 'unknown'}, required {REQUIRED_QUESTDB_MAJOR}.x; nothing was written",
        )
    _VERSION_RESULT["ok"] = ok
    return ok
