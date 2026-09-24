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
from typing import Any

from app.config import (
    EVENTS_ENABLED,
    EVENTS_SINCE,
    EVENTS_TABLE,
    INFLUXDB_USE_HTTPS,
    METRICS_BACKEND,
    QUESTDB_TABLE,
)
from app.crowdsec import (
    CrowdSecFetchError,
    get_abuse_contact,
    get_crowdsec_alerts,
    get_crowdsec_decisions,
    get_hostname,
)
from app.events import DEDUP_KEYS as EVENT_DEDUP_KEYS
from app.events import build_event_lines
from app.influxdb import (
    format_influxdb_line_protocol,
    send_to_influxdb,
    verify_tls_configuration,
)
from app.kbinterrupt import register_handlers
from app.logger import (
    print_debug,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from app.questdb import ensure_questdb_dedup, ensure_questdb_ttl, send_to_questdb
from app.version import GIT_SHA, VERSION

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

banner = rf"""
   ______                       _______
  / ____/________ _      ______/ / ___/___  _____
 / /   / ___/ __ \ | /| / / __  /\__ \/ _ \/ ___/
 / /___/ /  / /_/ / |/ |/ / /_/ /___/ /  __/ /__
 \____/_/   \____/|__/|__/\__,_//____/\___/\___/
            → Metrics Export Tool for CrowdSec
                    v{VERSION} ({GIT_SHA[:7]})
       Independent project; not affiliated with CrowdSec
"""


def verify_secure_connection() -> bool:
    """
    Verify TLS configuration if HTTPS is enabled.

    Returns:
        True if secure connection is verified or not needed, False otherwise
    """
    if INFLUXDB_USE_HTTPS:
        print_info("Verifying TLS configuration for secure HTTPS connection...")
        if not verify_tls_configuration():
            print_error("TLS configuration does not meet security requirements")
            print_warning(
                "Continuing with insecure connection - data may be vulnerable!"
            )

            try:
                response = input("Continue anyway? (y/N): ")
                if response.lower() != "y":
                    print_error(
                        "Application terminated due to insecure TLS configuration"
                    )
                    return False
            except (KeyboardInterrupt, EOFError):
                print_error("Application terminated by user")
                return False
        else:
            print_success("TLS configuration meets security requirements")
    else:
        print_warning("Using HTTP connection - data transmission is not encrypted")

    return True


def _send(payload: str, table: str, dedup_keys: tuple[str, ...]) -> bool:
    """Write line protocol to the configured backend.

    For QuestDB, retention and deduplication are (re-)declared after a
    successful write, because ILP auto-creates the table without either. For
    InfluxDB 2.x no DDL is needed: a point that repeats an existing
    series + timestamp overwrites it.
    """
    if METRICS_BACKEND == "questdb":
        if not send_to_questdb(payload):
            return False
        ensure_questdb_ttl(table)
        ensure_questdb_dedup(table, dedup_keys)
        return True
    return send_to_influxdb(payload)


def export_events(hostname: str) -> bool:
    """Export per-event request details into the separate events table.

    Sends every event in the `EVENTS_SINCE` window on every run; duplicates
    from the overlap are collapsed by the backend. Returns False when the fetch
    or the write failed.
    """
    try:
        alerts = get_crowdsec_alerts(EVENTS_SINCE)
    except CrowdSecFetchError as e:
        print_error(f"Event export skipped, LAPI fetch failed: {e}")
        if e.hint:
            print_info(f"HINT: {e.hint}")
        return False

    measurement = EVENTS_TABLE if METRICS_BACKEND == "questdb" else f"{hostname}_events"
    lines = build_event_lines(alerts, measurement, host=hostname)

    if not lines:
        print_info("💤 No events to export")
        return True

    print_info(f"Exporting {len(lines)} events from {len(alerts)} alerts")
    sample = lines[0]
    suffix = "..." if len(sample) > 100 else ""
    print_debug(f"  Sample event: {sample[:100]}{suffix}")

    if not _send("\n".join(lines), measurement, EVENT_DEDUP_KEYS):
        print_error(f"Failed to send events to {METRICS_BACKEND}")
        return False

    print_success(f"Successfully exported {len(lines)} events")
    return True


def main() -> int:
    """Fetch alerts from CrowdSec and export them to the configured backend.

    Returns the process exit code: 0 on success (including "nothing to send"),
    1 when the TLS check, the CrowdSec fetch or the backend write failed.
    """
    print(banner)
    print_info(f"Starting CrowdSec → {METRICS_BACKEND} export...")

    # Register signal handlers for clean shutdown
    register_handlers()

    # Verify secure connection before proceeding. This check exercises the
    # process' general TLS environment (not the backend's certificate) and is
    # only meaningful for the InfluxDB backend, which is the only one it was
    # written against.
    if METRICS_BACKEND == "influxdb2" and not verify_secure_connection():
        return 1

    try:
        hostname = get_hostname()
    except (OSError, ValueError) as e:
        print_error(f"Failed to read host hostname: {e}")
        return 1
    print_info(f"Using hostname: {hostname}")

    # Fetch the alerts behind the currently active decisions
    try:
        decisions = get_crowdsec_decisions()
    except CrowdSecFetchError as e:
        print_error(f"LAPI fetch failed: {e}")
        if e.hint:
            print_info(f"HINT: {e.hint}")
        return 1

    alerts: list[dict[str, Any]] = []
    skipped_count = 0

    # Process each decision
    for decision in decisions:
        try:
            alert_id = int(decision.get("id", 0))
        except (ValueError, TypeError):
            print_warning(
                f"Skipping decision with non-numeric id: {decision.get('id')!r}"
            )
            skipped_count += 1
            continue
        source = decision.get("source", {})
        alerts.append(
            {
                "alert_id": alert_id,
                "ip_address": source.get("ip", ""),
                "as_name": source.get("as_name", ""),
                "as_number": source.get("as_number", 0),
                "latitude": source.get("latitude", 0.0),
                "longitude": source.get("longitude", 0.0),
                "country": (source.get("cn") or "").upper(),
                "abuse_email": get_abuse_contact(source.get("ip", "")),
                "events_count": decision.get("events_count", 0),
                "scenario": (decision.get("scenario") or "").split("/")[-1],
                "message": decision.get("message", ""),
                "start_at": decision.get("start_at", ""),
            }
        )

    if skipped_count:
        print_warning(
            f"Skipped {skipped_count} malformed decision(s) with non-numeric id"
        )

    if alerts:
        # QuestDB and InfluxDB 2.x both accept the same line protocol wire
        # format; only the measurement/table name and the write target differ.
        measurement_name = QUESTDB_TABLE if METRICS_BACKEND == "questdb" else hostname
        line_protocol_data = "\n".join(
            format_influxdb_line_protocol(
                alert,
                measurement_name,
                host=hostname if METRICS_BACKEND == "questdb" else None,
            )
            for alert in alerts
        )

        print_info(f"Exporting {len(alerts)} alerts to {METRICS_BACKEND}:")
        for i, line in enumerate(line_protocol_data.split("\n")[:2]):
            suffix = "..." if len(line) > 100 else ""
            print_debug(f"  Sample {i + 1}: {line[:100]}{suffix}")

        if not _send(line_protocol_data, measurement_name, ALERT_DEDUP_KEYS):
            print_error(f"Failed to send data to {METRICS_BACKEND}")
            return 1

        print_success(f"Successfully exported {len(alerts)} alerts")
    else:
        print_info("💤 No decisions to export")

    # The event export is additive: a failure here must not hide the successful
    # alert export above, but it still marks the run as failed for the health
    # check.
    if EVENTS_ENABLED and not export_events(hostname):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
