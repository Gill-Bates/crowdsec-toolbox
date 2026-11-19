#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/questdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
QuestDB integration: ILP-over-HTTP writes via httpx, plus TTL, dedup and rollup DDL.
Line protocol formatting is shared with InfluxDB (see `app.influxdb`); only the
endpoint and auth differ.
"""

import re
import time
from dataclasses import dataclass
from enum import Enum

import httpx

from .config import (
    QUESTDB_DOWNSAMPLING,
    QUESTDB_DOWNSAMPLING_DISABLED_PROFILE,
    QUESTDB_DOWNSAMPLING_PROFILES,
    QUESTDB_DOWNSAMPLING_SCHEMA_VERSION,
    QUESTDB_DOWNSAMPLING_STATE_TABLE,
    QUESTDB_PASSWORD,
    QUESTDB_PORT,
    QUESTDB_TOKEN,
    QUESTDB_TTL,
    QUESTDB_TTL_DAYS,
    QUESTDB_URL,
    QUESTDB_USE_HTTPS,
    QUESTDB_USERNAME,
    QUESTDB_VALIDATE_CERTIFICATE,
    REQUEST_TIMEOUT,
)
from .logger import print_error, print_info, print_success, print_warning


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
    raw_ttl: str | None
    status: DownsamplingStatus


def _questdb_url(endpoint: str) -> str:
    """Build a QuestDB endpoint URL from the configured protocol/host/port."""
    protocol = "https" if QUESTDB_USE_HTTPS else "http"
    return f"{protocol}://{QUESTDB_URL}:{QUESTDB_PORT}/{endpoint}"


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


REQUIRED_QUESTDB_MAJOR = 10
_BUILD_VERSION = re.compile(r"\bQuestDB\s+(\d+)\.(\d+)(?:\.(\d+))?")


def _parse_questdb_version(build_info: object) -> tuple[int, ...] | None:
    """Extract the version from a `build()` answer like `Build Information: QuestDB 10.0.0, JDK 25, ...`."""
    match = _BUILD_VERSION.search(str(build_info))
    if match is None:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def ensure_questdb_version() -> bool:
    """Accept only a QuestDB server of major version 10.

    Reads `SELECT build()` via `/exec` (transient errors are retried). An
    unreachable server, an error response, an unparsable answer and any other
    major version are rejected; the caller must then neither write nor run DDL.
    """
    rows = _query_exec(
        "SELECT build()",
        warning_prefix="QuestDB version not readable",
        retries=len(_RETRY_BACKOFF_SECONDS),
    )
    version = _parse_questdb_version(rows[0][0]) if rows and rows[0] else None
    if version is not None and version[0] == REQUIRED_QUESTDB_MAJOR:
        print_info(f"QuestDB version {'.'.join(map(str, version))} accepted")
        return True
    found = ".".join(map(str, version)) if version else "unknown"
    print_error(
        f"Unsupported QuestDB version at {_questdb_url('').rstrip('/')}: found {found}, "
        f"required {REQUIRED_QUESTDB_MAJOR}.x; nothing was written"
    )
    return False


def send_to_questdb(line_protocol_data: str) -> bool:
    """Send line protocol data to QuestDB's `/write` endpoint.

    Returns True on HTTP 200 or 204, False on any failure.
    """
    url = _questdb_url("write")
    headers, auth = _questdb_auth()
    headers["Content-Type"] = "text/plain; charset=utf-8"
    params = {"precision": "ns"}

    try:
        print_info(f"Writing data to QuestDB at {url}")

        with httpx.Client(verify=QUESTDB_VALIDATE_CERTIFICATE) as client:
            response = client.post(
                url,
                headers=headers,
                auth=auth,
                params=params,
                content=line_protocol_data,
                timeout=REQUEST_TIMEOUT,
            )

        if response.status_code in (200, 204):
            print_success(f"Wrote data to QuestDB at {url}")
            return True
        print_error(f"QuestDB API error: {response.status_code} - {response.text}")
        return False

    except httpx.HTTPError as e:
        print_error(f"Connection error to QuestDB: {e}")
        return False
    except Exception as e:
        # Last resort: an unexpected error fails the write instead of crashing the run.
        print_error(f"Unexpected error sending to QuestDB: {e}")
        return False


def ensure_questdb_ttl(table: str, ttl: str | None) -> bool:
    """Apply a TTL clause to the table via QuestDB's /exec SQL endpoint.

    `ttl` is the raw TTL from `ensure_questdb_downsampling()`: QUESTDB_TTL, or
    the shorter raw window when a profile is active. ILP auto-creates tables without a TTL,
    so this runs after every successful write; ALTER TABLE ... SET TTL is
    idempotent. Needs a partitioned table (ILP tables are
    partitioned by DAY). Returns False when a configured TTL could not be set;
    the data is already stored and is never resent for that reason.
    """
    if not ttl:
        return True
    query = f"ALTER TABLE {_quote_ident(table)} SET TTL {ttl}"
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

    print_info(f"QuestDB dedup verified on {table!r}: {', '.join(keys)}")
    if had_duplicate_risk:
        print_warning(
            f"Dedup was just enabled on existing table {table!r}: rows stored earlier are NOT deduplicated. "
            "See the duplicate cleanup runbook in docs/reference/metrics-backends.md"
        )
    return True


def ensure_questdb_table(table: str, keys: tuple[str, ...]) -> bool:
    """Make sure the table exists with verified deduplication before it is written.

    ILP auto-creates a table without dedup, so a write that precedes this gate
    can store a first batch that later runs duplicate. The gate runs
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


def _rollup_is_current(view_name: str, table: str) -> DownsamplingStatus:
    """Report whether the view is ready, still refreshing, or failed verification.

    The raw TTL is shortened only when the view is current, so no interval is
    dropped from the base table before the rollup covers it.
    """
    rows = _query_exec(
        "SELECT view_name, base_table_name, view_status, refresh_base_table_txn, "
        f"base_table_txn FROM materialized_views() WHERE view_name = {_quote_literal(view_name)}",
        warning_prefix=f"QuestDB rollup status of {view_name!r} not readable",
    )
    if rows is None:
        print_warning(f"QuestDB rollup status of {view_name!r} could not be verified; raw TTL unchanged")
        return DownsamplingStatus.FAILED
    if not rows:
        print_warning(f"QuestDB rollup view {view_name!r} is not ready yet; raw TTL unchanged")
        return DownsamplingStatus.PENDING

    if len(rows[0]) < 5:
        print_warning(f"QuestDB rollup status of {view_name!r} is incomplete; raw TTL unchanged")
        return DownsamplingStatus.FAILED

    actual_view, actual_base, status, refresh_txn, base_txn = rows[0][:5]
    if str(actual_view) != view_name or str(actual_base) != table:
        print_warning(f"QuestDB rollup view {view_name!r} has an unexpected base table; raw TTL unchanged")
        return DownsamplingStatus.FAILED
    state = str(status).lower()
    if state in {"invalid", "failed"}:
        print_warning(f"QuestDB rollup view {view_name!r} is {state}; raw TTL unchanged")
        return DownsamplingStatus.FAILED
    if state != "valid":
        print_warning(f"QuestDB rollup view {view_name!r} is not ready yet; raw TTL unchanged")
        return DownsamplingStatus.PENDING
    if not isinstance(refresh_txn, int) or not isinstance(base_txn, int):
        print_warning(f"QuestDB rollup transaction state of {view_name!r} is unreadable; raw TTL unchanged")
        return DownsamplingStatus.FAILED
    if refresh_txn >= base_txn:
        return DownsamplingStatus.ACTIVE

    print_warning(
        f"QuestDB rollup view {view_name!r} is not refreshed (status={status}, "
        f"refresh txn={refresh_txn}, base txn={base_txn}); raw TTL unchanged"
    )
    return DownsamplingStatus.PENDING


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
    if current and list(current[0][:7]) == expected:
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


def ensure_questdb_downsampling(table: str, rollup: RollupSpec | None) -> DownsamplingResult:
    """Provision a rollup and report raw retention plus its setup status.

    Returns the TTL the *raw* table should carry: the profile's short raw window
    once the rollup is valid and current, otherwise QUESTDB_TTL unchanged. The
    rollup view itself carries QUESTDB_TTL, so the long-term history survives in
    aggregated form. Pending refreshes keep the full raw retention without
    failing the run; failed DDL or verification also keeps full retention and
    reports a setup failure to the caller.
    """
    if not QUESTDB_DOWNSAMPLING or rollup is None:
        _publish_downsampling_state(
            table,
            enabled=False,
            profile_name=QUESTDB_DOWNSAMPLING_DISABLED_PROFILE,
            raw_days=QUESTDB_TTL_DAYS or 0,
        )
        return DownsamplingResult(QUESTDB_TTL, DownsamplingStatus.DISABLED)

    profile = QUESTDB_DOWNSAMPLING_PROFILES[QUESTDB_DOWNSAMPLING]
    raw_days = profile.raw_retention_days
    if QUESTDB_TTL_DAYS is not None:
        if QUESTDB_TTL_DAYS <= 0:
            # A sub-day QUESTDB_TTL is already shorter than any profile window.
            return DownsamplingResult(QUESTDB_TTL, DownsamplingStatus.PENDING)
        raw_days = min(raw_days, QUESTDB_TTL_DAYS)

    columns = _table_columns(table)
    if columns is None:
        return DownsamplingResult(QUESTDB_TTL, DownsamplingStatus.FAILED)
    if not columns:
        return DownsamplingResult(QUESTDB_TTL, DownsamplingStatus.PENDING)

    ddl = _rollup_ddl(table, profile.rollup_interval, rollup, columns, QUESTDB_TTL)
    if ddl is None:
        print_warning(f"QuestDB rollup for {table!r} skipped: none of its aggregate columns exist yet")
        return DownsamplingResult(QUESTDB_TTL, DownsamplingStatus.FAILED)

    view_name = questdb_rollup_view_name(table, profile.rollup_interval)
    if not _run_exec(ddl, warning_prefix=f"QuestDB rollup view {view_name!r} not provisioned"):
        print_error(f"QuestDB downsampling is inactive on {table!r}: the raw TTL stays at its full length")
        return DownsamplingResult(QUESTDB_TTL, DownsamplingStatus.FAILED)
    readiness = _rollup_is_current(view_name, table)
    if readiness is not DownsamplingStatus.ACTIVE:
        return DownsamplingResult(QUESTDB_TTL, readiness)

    # A view created before this build, or before a TTL change, keeps its old
    # TTL: SET TTL is idempotent and cheap, so re-declare it every run.
    if QUESTDB_TTL and not _run_exec(
        f"ALTER MATERIALIZED VIEW {_quote_ident(view_name)} SET TTL {QUESTDB_TTL}",
        warning_prefix=f"QuestDB TTL not applied to rollup view {view_name!r}",
    ):
        return DownsamplingResult(QUESTDB_TTL, DownsamplingStatus.FAILED)

    print_info(
        f"QuestDB downsampling {QUESTDB_DOWNSAMPLING!r} active on {table!r}: "
        f"raw {raw_days} day(s), rollup {profile.rollup_interval} in {view_name!r}"
    )
    _publish_downsampling_state(
        table,
        enabled=True,
        profile_name=QUESTDB_DOWNSAMPLING,
        raw_days=raw_days,
        rollup_interval=profile.rollup_interval,
        rollup_view=view_name,
    )
    return DownsamplingResult(f"{raw_days} DAYS", DownsamplingStatus.ACTIVE)
