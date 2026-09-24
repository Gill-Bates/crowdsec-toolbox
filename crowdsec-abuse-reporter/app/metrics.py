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
    return (
        text.replace("\\", "\\\\")
        .replace(",", "\\,")
        .replace("=", "\\=")
        .replace(" ", "\\ ")
    )


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
    tags_str = ",".join(
        f"{key}={escape_tag(value)}" for key, value in tags.items() if value
    )
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
                return client.post(
                    url, headers=headers, params=params, content=payload, auth=auth
                )
        except (httpx.HTTPError, ssl.SSLError) as e:
            if attempt == attempts - 1:
                raise
            delay = METRICS_RETRY_BACKOFF * (2**attempt)
            print_log(
                "WARNING",
                TAGS["WARNING"],
                f"Metrics write failed (attempt {attempt + 1}/{attempts}): {e} — "
                f"retrying in {delay:.1f}s",
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
    print_database_error(
        0, f"InfluxDB API error: {response.status_code} - {response.text[:500]}"
    )
    return False


def send_to_questdb(payload: str) -> bool:
    protocol = "https" if QUESTDB_USE_HTTPS else "http"
    url = f"{protocol}://{QUESTDB_URL}:{QUESTDB_PORT}/write"
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    # Bearer token takes precedence over basic auth, as in the sibling tool.
    auth = None
    if QUESTDB_TOKEN:
        headers["Authorization"] = f"Bearer {QUESTDB_TOKEN}"
    elif QUESTDB_USERNAME and QUESTDB_PASSWORD:
        auth = (QUESTDB_USERNAME, QUESTDB_PASSWORD)
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
    print_database_error(
        0, f"QuestDB API error: {response.status_code} - {response.text[:500]}"
    )
    return False


def write_points(lines: list[str]) -> bool:
    """Send all points in one request to the configured backend.

    Returns True when there is nothing to send or the backend accepted the
    batch. Callers that must not lose the points use `flush_points()`, which
    persists them first; this function is the bare write.
    """
    if not lines:
        return True
    payload = "\n".join(lines)
    if METRICS_BACKEND == "questdb":
        ok = send_to_questdb(payload)
        if ok:
            ensure_questdb_ttl(QUESTDB_TABLE)
            ensure_questdb_dedup(QUESTDB_TABLE, DEDUP_KEYS)
    elif METRICS_BACKEND == "influxdb2":
        ok = send_to_influxdb(payload)
    else:
        return True
    if ok:
        print_config_info(f"✓ {len(lines)} report point(s) written to {METRICS_BACKEND}")
    return ok


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

    Returns True when nothing is outstanding afterwards. A False return means the
    points are still spooled, not that they are lost — the caller decides whether
    a deferred batch is worth failing the run for.
    """
    if not METRICS_ENABLED:
        return True

    # Persist first: from here on a crash or a dead backend costs a retry, not
    # the data. A spool failure is the one case that can still lose points, so it
    # is reported and the run continues with the bare write as a last attempt.
    spooled = spool_metric_points(lines or [])

    # Bound the spool before reading it, so a long outage cannot grow the
    # database without limit.
    prune_metric_outbox(METRICS_OUTBOX_MAX_ROWS, METRICS_OUTBOX_MAX_AGE_DAYS)

    if not spooled:
        return write_points(lines or [])

    # A batch cap keeps one run from building a multi-megabyte request after a
    # long outage; the remainder goes out on the following run.
    pending = load_metric_points(_FLUSH_BATCH_LIMIT)
    if not pending:
        return True

    ids = [row_id for row_id, _ in pending]
    if not write_points([line for _, line in pending]):
        print_log(
            "WARNING",
            TAGS["WARNING"],
            f"{len(pending)} metrics point(s) stay in the outbox and will be "
            f"retried on the next run (nothing lost)",
        )
        return False

    delete_metric_points(ids)
    remaining = count_metric_points()
    if remaining:
        print_config_info(
            f"{remaining} spooled metrics point(s) left for the next run"
        )
    return True


def ensure_questdb_ttl(table: str) -> bool:
    """Apply QUESTDB_TTL to the table via QuestDB's /exec SQL endpoint.

    ILP auto-creates tables without a TTL, so this runs after every successful
    write; ALTER TABLE ... SET TTL is idempotent. Needs QuestDB 8.3+ and a
    partitioned table (ILP tables are partitioned by DAY). Failure only warns:
    the data itself is already stored.
    """
    if not QUESTDB_TTL:
        return True
    protocol = "https" if QUESTDB_USE_HTTPS else "http"
    url = f"{protocol}://{QUESTDB_URL}:{QUESTDB_PORT}/exec"
    quoted = table.replace('"', '""')
    query = f'ALTER TABLE "{quoted}" SET TTL {QUESTDB_TTL}'
    headers = {}
    auth = None
    if QUESTDB_TOKEN:
        headers["Authorization"] = f"Bearer {QUESTDB_TOKEN}"
    elif QUESTDB_USERNAME and QUESTDB_PASSWORD:
        auth = (QUESTDB_USERNAME, QUESTDB_PASSWORD)
    try:
        with httpx.Client(verify=QUESTDB_VALIDATE_CERTIFICATE, timeout=REQUEST_TIMEOUT) as client:
            response = client.get(url, params={"query": query}, headers=headers, auth=auth)
    except httpx.HTTPError as e:
        print_log("WARNING", TAGS["WARNING"], f"QuestDB TTL not applied to {table!r}: {e}")
        return False
    if response.status_code != 200:
        print_log("WARNING", TAGS["WARNING"], 
            f"QuestDB TTL not applied to {table!r}: "
            f"{response.status_code} - {response.text[:300]}"
        )
        return False
    return True


def ensure_questdb_dedup(table: str, keys: tuple[str, ...]) -> bool:
    """Enable QuestDB row deduplication on the table's upsert keys.

    ILP auto-creates tables append-only, so a repeated write of the same point
    would add a copy. This runs after every successful write; `DEDUP ENABLE` is
    idempotent and re-declaring the same keys is a no-op. Needs QuestDB 7.3+
    and a WAL table (ILP tables are WAL). The designated timestamp is always
    part of the key set and must be listed first. Failure only warns: the rows
    themselves are already stored.

    InfluxDB 2.x needs no equivalent — it overwrites a point that repeats an
    existing series and timestamp.
    """
    if not keys:
        return True
    protocol = "https" if QUESTDB_USE_HTTPS else "http"
    url = f"{protocol}://{QUESTDB_URL}:{QUESTDB_PORT}/exec"
    quoted_table = table.replace('"', '""')
    quoted_keys = ", ".join(f'"{key.replace(chr(34), chr(34) * 2)}"' for key in keys)
    query = f'ALTER TABLE "{quoted_table}" DEDUP ENABLE UPSERT KEYS({quoted_keys})'
    headers = {}
    auth = None
    if QUESTDB_TOKEN:
        headers["Authorization"] = f"Bearer {QUESTDB_TOKEN}"
    elif QUESTDB_USERNAME and QUESTDB_PASSWORD:
        auth = (QUESTDB_USERNAME, QUESTDB_PASSWORD)
    try:
        with httpx.Client(verify=QUESTDB_VALIDATE_CERTIFICATE, timeout=REQUEST_TIMEOUT) as client:
            response = client.get(url, params={"query": query}, headers=headers, auth=auth)
    except httpx.HTTPError as e:
        print_log(
            "WARNING", TAGS["WARNING"], f"QuestDB dedup not enabled on {table!r}: {e}"
        )
        return False
    if response.status_code != 200:
        print_log(
            "WARNING",
            TAGS["WARNING"],
            f"QuestDB dedup not enabled on {table!r}: "
            f"{response.status_code} - {response.text[:300]}",
        )
        return False
    return True
