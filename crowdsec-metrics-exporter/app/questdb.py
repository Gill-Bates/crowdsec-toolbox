#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/questdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
QuestDB integration. The client (ILP-over-HTTP writes, /exec SQL, dedup gate, TTL, rollup
retention, version check) lives in the external ``gillbates-questdb-client`` package; this
module binds it to the exporter's settings and log helpers and keeps the function names
`main.py` calls. Line protocol formatting is shared with InfluxDB (see `app.influxdb`).
"""

import time

from gillbates_questdb_client import (
    DownsamplingProfile,
    DownsamplingStatus,
    LogSink,
    QuestDBClient,
    QuestDBConfig,
    RetentionSettings,
    RollupSpec,
)

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
from .logger import print_debug, print_error, print_info, print_success, print_warning

__all__ = [
    "DownsamplingStatus",
    "RollupSpec",
    "apply_questdb_retention",
    "build_client",
    "ensure_questdb_table",
    "ensure_questdb_ttl",
    "ensure_questdb_version",
    "questdb_rollup_baseline",
    "send_to_questdb",
]


# Call-time lookups keep the print_* helpers patchable and the log format the exporter's own.
def _debug(message: str) -> None:
    print_debug(message)


def _info(message: str) -> None:
    print_info(message)


def _success(message: str) -> None:
    print_success(message)


def _warning(message: str) -> None:
    print_warning(message)


def _error(message: str) -> None:
    print_error(message)


_LOG = LogSink(debug=_debug, info=_info, success=_success, warning=_warning, error=_error)


def build_client(
    *,
    downsampling: str = QUESTDB_DOWNSAMPLING,
    ttl: str | None = QUESTDB_TTL,
    ttl_days: int | None = QUESTDB_TTL_DAYS,
    transport=None,
    sleep=time.sleep,
) -> QuestDBClient:
    """Build the client from the exporter's settings; the keyword arguments exist for tests."""
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


# One server per process: the client caches the version verdict and the table-gate results.
_CLIENT = build_client()


def send_to_questdb(line_protocol_data: str) -> bool:
    """Send line protocol data to QuestDB's `/write` endpoint; True on HTTP 200 or 204."""
    return _CLIENT.write(line_protocol_data)


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
