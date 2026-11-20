#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/main.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Main entrypoint: CrowdSec → Metrics Exporter
Exports CrowdSec security alerts to InfluxDB 2.x or QuestDB for monitoring
and analysis, selected via METRICS_BACKEND.

Runs are idempotent through backend-side deduplication rather than a local
watermark: every run sends the full current data set, and the backend collapses
rows it has already stored. See `ALERT_DEDUP_KEYS` and `app.events.DEDUP_KEYS`.
"""

import sys
from enum import Enum
from typing import Any

from app.banner import print_banner
from app.config import (
    EVENTS_ENABLED,
    EVENTS_SINCE,
    EVENTS_TABLE,
    INFLUXDB_USE_HTTPS,
    INFLUXDB_VALIDATE_CERTIFICATE,
    METRICS_BACKEND,
    QUESTDB_TABLE,
)
from app.crowdsec import (
    CrowdSecFetchError,
    CrowdSecIncompleteFetchError,
    get_abuse_contact,
    get_crowdsec_alerts,
    get_crowdsec_decisions,
    get_hostname,
    parse_record_id,
)
from app.events import DEDUP_KEYS as EVENT_DEDUP_KEYS
from app.events import ROLLUP as EVENT_ROLLUP
from app.events import build_event_lines
from app.influxdb import (
    format_influxdb_line_protocol,
    send_to_influxdb,
)
from app.kbinterrupt import register_handlers
from app.logger import (
    print_debug,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from app.questdb import (
    RollupSpec,
    apply_questdb_retention,
    ensure_questdb_table,
    ensure_questdb_version,
    questdb_rollup_baseline,
    send_to_questdb,
)

# Columns that identify an alert row in QuestDB, passed to
# `DEDUP ENABLE UPSERT KEYS`. These are exactly the tag columns written by
# `format_influxdb_line_protocol()` plus the designated timestamp, which must
# come first — i.e. the same identity InfluxDB derives from series + timestamp.
# `alert_id` is a field, not a tag, so it cannot serve as a key here.
ALERT_DEDUP_KEYS = (
    "timestamp",
    "host",
    "ip_address",
    "as_name",
    "as_number",
    "country",
    "scenario",
)

# Downsampling rollup for the alert table. `ip_address` is deliberately not a
# dimension: dropping the per-IP detail is what makes the long-term history
# small, while "how many decisions per country and scenario" survives.
# `latitude`/`longitude` are per-IP coordinates and meaningless once IPs are
# collapsed, so they are not aggregated either.
ALERT_ROLLUP = RollupSpec(
    dimensions=("host", "country", "scenario"),
    aggregates=(
        ("decisions_count", "count", ""),
        ("events_count_sum", "sum", "events_count"),
        ("events_count_max", "max", "events_count"),
    ),
)


def warn_insecure_transport() -> None:
    """Warn when the InfluxDB connection is unencrypted or unverified.

    The certificate and TLS version are verified by the real write connection
    (`send_to_influxdb`), which fails the run when the handshake is rejected.
    """
    if not INFLUXDB_USE_HTTPS:
        print_warning("Using HTTP connection - data transmission is not encrypted")
    elif not INFLUXDB_VALIDATE_CERTIFICATE:
        print_warning("INFLUXDB_VALIDATE_CERTIFICATE is off - the server certificate is not verified")


class SendStatus(Enum):
    """Outcome of one table export: stored data and database setup are separate facts."""

    OK = "ok"
    # Nothing was stored: the dedup gate failed or the write was rejected.
    NOT_WRITTEN = "not_written"
    # Stored, but configured QuestDB retention or rollup setup failed; never resent.
    WRITTEN_UNCONFIGURED = "written_unconfigured"


def _send(
    payload: str,
    table: str,
    dedup_keys: tuple[str, ...],
    rollup: RollupSpec | None = None,
) -> SendStatus:
    """Write line protocol to the configured backend.

    For QuestDB, `ensure_questdb_table()` verifies deduplication before the
    first write: ILP auto-creates tables without it, so an earlier write could
    store a batch that later runs duplicate. When the gate fails, nothing is
    written. After a successful write, `apply_questdb_retention()` verifies the
    rollup, applies the raw TTL and only then publishes the effective state. The
    raw TTL is shortened only once the view is valid and current; a pending
    refresh keeps full retention. Failed rollup or TTL setup keeps full raw
    retention where possible and reports `WRITTEN_UNCONFIGURED`; the payload is
    never posted again. For InfluxDB 2.x
    no DDL is needed: a point that repeats an existing series + timestamp
    overwrites it, and it has no equivalent of the rollup view.
    """
    if METRICS_BACKEND != "questdb":
        return SendStatus.OK if send_to_influxdb(payload) else SendStatus.NOT_WRITTEN
    if not ensure_questdb_table(table, dedup_keys):
        print_error(f"QuestDB table {table!r} is not safely configured for idempotent exports; nothing was written")
        return SendStatus.NOT_WRITTEN
    baseline_txn = questdb_rollup_baseline(table, rollup)
    if not send_to_questdb(payload):
        return SendStatus.NOT_WRITTEN
    return SendStatus.OK if apply_questdb_retention(table, rollup, baseline_txn) else SendStatus.WRITTEN_UNCONFIGURED


def _report_send(status: SendStatus, what: str) -> bool:
    """Log the outcome of `_send` and return True only for a fully successful export."""
    if status is SendStatus.NOT_WRITTEN:
        print_error(f"Failed to send {what} to {METRICS_BACKEND}: nothing was stored")
    elif status is SendStatus.WRITTEN_UNCONFIGURED:
        print_error(
            f"{what.capitalize()} were written to {METRICS_BACKEND}, but retention/downsampling setup failed; "
            "the data is kept and not resent, fix the QuestDB setup"
        )
    return status is SendStatus.OK


def export_events(hostname: str) -> bool:
    """Export per-event request details into the separate events table.

    Sends every event in the `EVENTS_SINCE` window on every run; duplicates
    from the overlap are collapsed by the backend. Returns False when the fetch
    or the write failed, or when the result is incomplete (ceiling reached,
    event details missing, events without a timestamp); the usable events are
    still written in that case.
    """
    complete = True
    try:
        alerts = get_crowdsec_alerts(EVENTS_SINCE)
    except CrowdSecIncompleteFetchError as e:
        print_error(f"Event fetch incomplete, exporting what was retrieved: {e}")
        alerts = e.alerts
        complete = False
    except CrowdSecFetchError as e:
        print_error(f"Event export skipped, LAPI fetch failed: {e}")
        if e.hint:
            print_info(f"Hint: {e.hint}")
        return False

    measurement = EVENTS_TABLE if METRICS_BACKEND == "questdb" else f"{hostname}_events"
    lines, skipped = build_event_lines(alerts, measurement, host=hostname)
    if skipped:
        print_error(f"{skipped} event(s) or alert(s) skipped for invalid data or lack of a usable timestamp")
        complete = False

    if not lines:
        print_info("💤 No events to export")
        return complete

    print_info(f"Exporting {len(lines)} events from {len(alerts)} alerts")
    sample = lines[0]
    suffix = "..." if len(sample) > 100 else ""
    print_debug(f"  Sample event: {sample[:100]}{suffix}")

    if not _report_send(_send("\n".join(lines), measurement, EVENT_DEDUP_KEYS, EVENT_ROLLUP), "events"):
        return False

    print_success(f"Exported {len(lines)} events")
    return complete


def main() -> int:
    """Fetch alerts from CrowdSec and export them to the configured backend.

    Returns the process exit code: 0 on success (including "nothing to send"),
    1 when the CrowdSec fetch or the backend write failed (including a TLS
    handshake rejection or, for QuestDB, a server that is not version 10.x, a
    dedup gate that could not be verified or a configured TTL that could not be
    set), or when the data is incomplete
    (fetch ceiling reached, records with a missing or invalid id, alerts or events
    without a usable timestamp). Usable records are still exported in that case,
    and the alert and event tables are attempted independently.
    """
    print_banner()
    print_info(f"Starting CrowdSec → {METRICS_BACKEND} export")

    register_handlers()

    if METRICS_BACKEND == "influxdb2":
        warn_insecure_transport()

    try:
        hostname = get_hostname()
    except (OSError, ValueError) as e:
        print_error(f"Failed to read host hostname: {e}")
        return 1
    print_info(f"Using hostname: {hostname}")

    if METRICS_BACKEND == "questdb" and not ensure_questdb_version():
        return 1

    complete = True
    try:
        decisions = get_crowdsec_decisions()
    except CrowdSecIncompleteFetchError as e:
        print_error(f"Alert fetch incomplete, exporting what was retrieved: {e}")
        decisions = e.alerts
        complete = False
    except CrowdSecFetchError as e:
        print_error(f"LAPI fetch failed: {e}")
        if e.hint:
            print_info(f"Hint: {e.hint}")
        return 1

    alerts: list[dict[str, Any]] = []
    skipped_count = 0

    for decision in decisions:
        if not isinstance(decision, dict):
            print_warning(f"Skipping malformed decision of type {type(decision).__name__}")
            skipped_count += 1
            continue
        alert_id = parse_record_id(decision.get("id"))
        if alert_id is None:
            print_warning(f"Skipping decision with a missing or invalid id: {decision.get('id')!r}")
            skipped_count += 1
            continue
        scenario = decision.get("scenario")
        if scenario is not None and not isinstance(scenario, str):
            print_warning(f"Skipping decision {alert_id} with a non-text scenario")
            skipped_count += 1
            continue
        source = decision.get("source")
        if not isinstance(source, dict):
            source = {}
        alerts.append(
            {
                "alert_id": alert_id,
                "ip_address": source.get("ip") or "",
                "as_name": source.get("as_name") or "",
                "as_number": source.get("as_number") or 0,
                "latitude": source.get("latitude"),
                "longitude": source.get("longitude"),
                "country": str(source.get("cn") or "").upper(),
                "abuse_email": get_abuse_contact(source.get("ip") or ""),
                "events_count": decision.get("events_count", 0),
                "scenario": (scenario or "").split("/")[-1],
                "message": decision.get("message", ""),
                "start_at": decision.get("start_at", ""),
            }
        )

    if skipped_count:
        print_error(
            f"Skipped {skipped_count} malformed decision(s) "
            "(not an object, missing or invalid id, or non-text scenario)"
        )
        complete = False

    # QuestDB and InfluxDB 2.x both accept the same line protocol wire format;
    # only the measurement/table name and the write target differ.
    measurement_name = QUESTDB_TABLE if METRICS_BACKEND == "questdb" else hostname
    lines = [
        line
        for alert in alerts
        if (
            line := format_influxdb_line_protocol(
                alert,
                measurement_name,
                host=hostname if METRICS_BACKEND == "questdb" else None,
            )
        )
        is not None
    ]
    if len(lines) < len(alerts):
        print_error(f"{len(alerts) - len(lines)} alert(s) skipped for lack of a usable timestamp")
        complete = False

    if lines:
        line_protocol_data = "\n".join(lines)
        print_info(f"Exporting {len(lines)} alerts to {METRICS_BACKEND}:")
        for i, line in enumerate(lines[:2]):
            suffix = "..." if len(line) > 100 else ""
            print_debug(f"  Sample {i + 1}: {line[:100]}{suffix}")

        # No early return: a failing alert table must not block the independent
        # events table; the run still exits 1 below.
        if _report_send(_send(line_protocol_data, measurement_name, ALERT_DEDUP_KEYS, ALERT_ROLLUP), "alerts"):
            print_success(f"Exported {len(lines)} alerts")
        else:
            complete = False
    else:
        print_info("💤 No decisions to export")

    if EVENTS_ENABLED and not export_events(hostname):
        complete = False

    return 0 if complete else 1


if __name__ == "__main__":
    sys.exit(main())
