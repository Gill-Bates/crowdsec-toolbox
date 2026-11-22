#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/events.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Per-event export.

The decision export in `main.py` writes one point per alert and therefore only
carries aggregate information. CrowdSec attaches the interesting request
details to the individual *events* inside an alert, as a flat list of
key/value `meta` entries — `http_path`, `http_verb`, `http_status`,
`target_fqdn`, and for auth scenarios `target_user`.

This module turns those events into line protocol for a separate table
(`EVENTS_TABLE`), reusing the escaping helpers from `app.influxdb` because
QuestDB and InfluxDB share the wire format.

There is no export watermark: every run re-sends all events in the
`EVENTS_SINCE` window, and the backend deduplicates. That only works because
each line carries a deterministic identity — `alert_id` plus `event_seq`, the
event's position inside its alert. Both are tags, so they are part of the
series identity for InfluxDB and usable as QuestDB `DEDUP UPSERT KEYS`. The
host is part of that key as well because one QuestDB event table can receive
events from several CrowdSec instances.
"""

from datetime import UTC, datetime
from typing import Any

from .crowdsec import parse_record_id
from .influxdb import escape_influxdb_string_field, escape_influxdb_value
from .logger import print_warning

# Columns that identify an event row exactly. Passed to QuestDB's
# `DEDUP ENABLE UPSERT KEYS`; the designated timestamp must come first.
DEDUP_KEYS = ("timestamp", "host", "alert_id", "event_seq")

# This table gets no downsampling rollup (`ROLLUP = None`, see
# `app.questdb.RollupSpec`). QuestDB requires the non-aggregate columns of a
# materialized view to be a subset of the base table's DEDUP keys, and those
# keys are the per-event identity above — grouping a rollup by them would
# collapse nothing. The events table therefore keeps full resolution for the
# whole QUESTDB_TTL window; shorten QUESTDB_TTL or EVENTS_SINCE if that is too
# much data.
ROLLUP = None

# Meta keys promoted to tags (SYMBOL columns in QuestDB). Everything CrowdSec
# also puts into the alert row — ASNNumber, ASNOrg, IsoCode, SourceRange — is
# deliberately left out; join on alert_id instead of duplicating it per event.
_TAG_META_KEYS = (
    "http_verb",
    "http_status",
    "target_fqdn",
    "target_technology",
    "target_user",
    "service",
)

# `http_path` stays a string field rather than a tag: scan paths are
# effectively unbounded, and QuestDB SYMBOL columns are a poor fit for
# high-cardinality values.
_PATH_META_KEY = "http_path"


def _meta_to_dict(event: dict[str, Any]) -> dict[str, str]:
    """Flatten an event's [{key, value}, ...] meta list into a dict."""
    meta: dict[str, str] = {}
    for entry in event.get("meta") or []:
        if not isinstance(entry, dict):
            continue
        key = entry.get("key")
        if isinstance(key, str) and key:
            meta[key] = str(entry.get("value", ""))
    return meta


def _event_timestamp_ns(meta: dict[str, str], fallback: str) -> int | None:
    """Resolve an event's timestamp in nanoseconds.

    Prefers the ISO-8601 `timestamp` meta entry (e.g.
    "2026-09-23T15:56:28+02:00"). The event's own `timestamp` field uses a Go
    format that `fromisoformat` cannot read, so the alert's `start_at` is the
    fallback. Returns None when neither parses; the current time is never used
    because it cannot dedup against earlier runs.
    """
    for candidate in (meta.get("timestamp", ""), fallback):
        value = (candidate or "").strip().replace("Z", "+00:00")
        if not value:
            continue
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp() * 1e9)
    return None


def format_event_line_protocol(
    measurement: str,
    *,
    host: str,
    alert_id: int,
    event_seq: int,
    scenario: str,
    ip: str,
    meta: dict[str, str],
    timestamp_ns: int,
) -> str:
    """Build a single line protocol line for one CrowdSec event."""
    # alert_id and event_seq are tags, not fields: they form the dedup key, and
    # a field would neither join the InfluxDB series identity nor be usable in
    # QuestDB's UPSERT KEYS.
    tags = {
        "alert_id": escape_influxdb_value(str(alert_id)),
        "event_seq": escape_influxdb_value(str(event_seq)),
        "host": escape_influxdb_value(host),
        "ip_address": escape_influxdb_value(ip),
        "scenario": escape_influxdb_value(scenario),
    }
    for key in _TAG_META_KEYS:
        tags[key] = escape_influxdb_value(meta.get(key, ""))

    fields = {
        "http_path": escape_influxdb_string_field(meta.get(_PATH_META_KEY, "")),
    }

    # Empty tags are dropped: line protocol has no representation for an empty
    # tag value, and QuestDB would reject the line.
    tags_str = ",".join(f"{k}={v}" for k, v in tags.items() if v)
    fields_str = ",".join(f"{k}={v}" for k, v in fields.items())
    prefix = escape_influxdb_value(measurement)
    if tags_str:
        prefix = f"{prefix},{tags_str}"
    return f"{prefix} {fields_str} {timestamp_ns}"


def build_event_lines(
    alerts: list[dict[str, Any]],
    measurement: str,
    *,
    host: str,
) -> tuple[list[str], int]:
    """Turn every event of every alert into line protocol.

    All alerts in the fetched window are emitted on every run; repeated rows
    are collapsed by the backend (see `DEDUP_KEYS`). `event_seq` is the event's
    index inside its alert, which the LAPI returns in a stable order, so the
    same event produces the same key on every run.

    Args:
        alerts: Alert dicts from the LAPI
        measurement: Target table / measurement name
        host: Source host tag

    Returns:
        (lines, skipped): one line per event, and the number of records left
        out: events without a usable timestamp and alerts with a missing or
        invalid id (each logged). A non-zero count makes the run fail.
    """
    lines: list[str] = []
    skipped = 0

    for alert in alerts:
        alert_id = parse_record_id(alert.get("id")) if isinstance(alert, dict) else None
        if alert_id is None:
            raw = alert.get("id") if isinstance(alert, dict) else alert
            print_warning(f"Skipping alert with a missing or invalid id: {raw!r}")
            skipped += 1
            continue

        raw_scenario = alert.get("scenario")
        if raw_scenario is not None and not isinstance(raw_scenario, str):
            print_warning(f"Skipping alert {alert_id} with a non-text scenario")
            skipped += 1
            continue
        scenario = (raw_scenario or "").split("/")[-1]
        fallback_ts = str(alert.get("start_at") or "")
        source = alert.get("source")
        source_ip = str(source.get("ip") or "") if isinstance(source, dict) else ""
        alert_events = alert.get("events") or []
        if not isinstance(alert_events, list):
            print_warning(f"Skipping alert {alert_id} with malformed event details")
            skipped += 1
            continue

        for seq, event in enumerate(alert_events):
            if not isinstance(event, dict):
                print_warning(f"Skipping malformed event {seq} of alert {alert_id}")
                skipped += 1
                continue
            meta = _meta_to_dict(event)
            timestamp_ns = _event_timestamp_ns(meta, fallback_ts)
            if timestamp_ns is None:
                print_warning(f"Skipping event {seq} of alert {alert_id}: no parseable timestamp")
                skipped += 1
                continue
            try:
                lines.append(
                    format_event_line_protocol(
                        measurement,
                        host=host,
                        alert_id=alert_id,
                        event_seq=seq,
                        scenario=scenario,
                        ip=meta.get("source_ip", "") or source_ip,
                        meta=meta,
                        timestamp_ns=timestamp_ns,
                    )
                )
            except ValueError as e:
                # A backslash before a separator cannot be stored; one bad line must not poison the batch.
                print_warning(f"Skipping event {seq} of alert {alert_id}: {e}")
                skipped += 1
    return lines, skipped
