#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/questdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
QuestDB integration module.
Sends InfluxDB Line Protocol data to QuestDB's ILP-over-HTTP `/write` endpoint,
using httpx (no external QuestDB client library).
Line protocol formatting/escaping is shared with InfluxDB (see `app.influxdb`),
since QuestDB accepts the same wire format; only the target endpoint and auth differ.
"""

import httpx

from .config import (
    QUESTDB_PASSWORD,
    QUESTDB_PORT,
    QUESTDB_TOKEN,
    QUESTDB_TTL,
    QUESTDB_URL,
    QUESTDB_USE_HTTPS,
    QUESTDB_USERNAME,
    QUESTDB_VALIDATE_CERTIFICATE,
    REQUEST_TIMEOUT,
)
from .logger import print_error, print_info, print_success, print_warning


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


def _run_exec(query: str, *, warning_prefix: str) -> bool:
    """Run a statement against QuestDB's `/exec` SQL endpoint.

    Returns True on HTTP 200, False otherwise. Failures are only warned about,
    never raised: callers use this for post-write DDL (TTL, dedup) where the
    data itself is already stored.
    """
    headers, auth = _questdb_auth()
    try:
        with httpx.Client(verify=QUESTDB_VALIDATE_CERTIFICATE, timeout=REQUEST_TIMEOUT) as client:
            response = client.get(
                _questdb_url("exec"), params={"query": query}, headers=headers, auth=auth
            )
    except httpx.HTTPError as e:
        print_warning(f"{warning_prefix}: {e}")
        return False
    if response.status_code != 200:
        print_warning(f"{warning_prefix}: {response.status_code} - {response.text[:300]}")
        return False
    return True


def send_to_questdb(line_protocol_data: str) -> bool:
    """
    Send line protocol data to QuestDB's ILP-over-HTTP `/write` endpoint.

    Args:
        line_protocol_data: Data formatted in line protocol

    Returns:
        True if successful, False otherwise
    """
    url = _questdb_url("write")
    headers, auth = _questdb_auth()
    headers["Content-Type"] = "text/plain; charset=utf-8"
    params = {"precision": "ns"}

    try:
        print_info(f"Sending data to QuestDB at {url}...")

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
            print_success("Data successfully sent to QuestDB")
            return True
        else:
            print_error(f"QuestDB API error: {response.status_code} - {response.text}")
            return False

    except httpx.HTTPError as e:
        print_error(f"Connection error to QuestDB: {e}")
        return False
    except Exception as e:
        # Last-resort guard so an unexpected error is logged and turned into a
        # clean False instead of crashing the run; more specific excepts above
        # handle the expected cases.
        print_error(f"Unexpected error sending to QuestDB: {e}")
        return False


def ensure_questdb_ttl(table: str) -> bool:
    """Apply QUESTDB_TTL to the table via QuestDB's /exec SQL endpoint.

    ILP auto-creates tables without a TTL, so this runs after every successful
    write; ALTER TABLE ... SET TTL is idempotent. Needs QuestDB 8.3+ and a
    partitioned table (ILP tables are partitioned by DAY). Failure only warns:
    the data itself is already stored.
    """
    if not QUESTDB_TTL:
        return True
    query = f"ALTER TABLE {_quote_ident(table)} SET TTL {QUESTDB_TTL}"
    return _run_exec(query, warning_prefix=f"QuestDB TTL not applied to {table!r}")


def ensure_questdb_dedup(table: str, keys: tuple[str, ...]) -> bool:
    """Enable QuestDB row deduplication on the table's upsert keys.

    This replaces the former SQLite watermark: every run re-sends the full
    current data set and QuestDB collapses rows that repeat an existing
    (timestamp, keys...) combination instead of appending duplicates.

    Runs after every successful write because ILP auto-creates the table
    without deduplication; `DEDUP ENABLE` is idempotent and re-declaring the
    same keys is a no-op. Needs QuestDB 7.3+ and a WAL table (ILP tables are
    WAL). The designated timestamp is always part of the key set and must be
    listed first. Failure only warns: the rows themselves are already stored.
    """
    if not keys:
        return True
    quoted_keys = ", ".join(_quote_ident(key) for key in keys)
    query = f"ALTER TABLE {_quote_ident(table)} DEDUP ENABLE UPSERT KEYS({quoted_keys})"
    if not _run_exec(query, warning_prefix=f"QuestDB dedup not enabled on {table!r}"):
        return False
    print_info(f"QuestDB dedup active on {table!r}: {', '.join(keys)}")
    return True
