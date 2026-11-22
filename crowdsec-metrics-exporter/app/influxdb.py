#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/influxdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
InfluxDB integration: line protocol formatting and writes to InfluxDB 2.x.
"""

import math
import ssl
from datetime import UTC, datetime

from gillbates_influxdb_client import (
    NO_RETRY,
    InfluxDBClient,
    InfluxDBConfig,
    InfluxDBError,
    InfluxDBUnavailableError,
    escape_string_field,
    escape_tag,
    hardened_tls_context,
)

from .config import (
    INFLUXDB_BUCKET,
    INFLUXDB_CIPHERS,
    INFLUXDB_ORGANIZATION,
    INFLUXDB_PORT,
    INFLUXDB_TOKEN,
    INFLUXDB_URL,
    INFLUXDB_USE_HTTPS,
    INFLUXDB_VALIDATE_CERTIFICATE,
    REQUEST_TIMEOUT,
)
from .logger import print_error, print_info, print_success, print_warning


def escape_influxdb_value(value: str) -> str:
    """Escape a tag value or measurement; empty or missing values become an empty string.

    Raises ValueError for a backslash before a separator or at the end, which line protocol cannot store.
    """
    if not value:
        return ""
    return escape_tag(str(value))


def escape_influxdb_string_field(value: str) -> str:
    """Return value as a quoted line-protocol string field; empty or missing values become `""`."""
    if not value:
        return '""'
    return escape_string_field(str(value))


def _coordinate(value: object, limit: float) -> float | None:
    """Return a finite coordinate within +/-limit, or None when it is unknown or invalid.

    An unknown coordinate is omitted instead of replaced by 0.0, which would be a real
    point in the Gulf of Guinea; `nan`/`inf` are not valid line protocol numbers.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except TypeError, ValueError:
        return None
    return number if math.isfinite(number) and abs(number) <= limit else None


def format_influxdb_line_protocol(alert: dict, hostname: str, *, host: str | None = None) -> str | None:
    """Convert a CrowdSec alert into one InfluxDB line protocol line.

    Returns None (after a warning) when `start_at` is missing or unparsable:
    the current time would defeat deduplication, so the caller skips the alert
    and rates the run as failed. Missing or invalid coordinates are left out of
    the point; the other fields are still written.

    Args:
        alert: Alert dictionary from CrowdSec
        hostname: Used as the measurement name
        host: Optional source host tag, used to separate QuestDB instances
    """
    try:
        measurement = escape_influxdb_value(hostname)

        tags = {
            "ip_address": escape_influxdb_value(alert.get("ip_address", "")),
            "as_name": escape_influxdb_value(alert.get("as_name", "")) or "unknown",
            "as_number": escape_influxdb_value(str(alert.get("as_number") or 0)),
            "country": escape_influxdb_value(alert.get("country", "")),
            "scenario": escape_influxdb_value(alert.get("scenario", "")),
        }
        if host:
            tags["host"] = escape_influxdb_value(host)

        events_count = alert.get("events_count", 0)
        fields = {
            # A non-integer would make the whole batch invalid; omit the field instead.
            "events_count": events_count
            if isinstance(events_count, int) and not isinstance(events_count, bool)
            else None,
            "latitude": _coordinate(alert.get("latitude"), 90.0),
            "longitude": _coordinate(alert.get("longitude"), 180.0),
            "message": escape_influxdb_string_field(alert.get("message", "")),
            "abuse_email": escape_influxdb_string_field(alert.get("abuse_email", "")),
            "alert_id": int(alert.get("alert_id", 0)),
        }

    except ValueError as e:
        # A backslash before a separator cannot be stored; sending it would invalidate the batch.
        print_warning(f"Skipping alert {alert.get('alert_id')!r}: {e}")
        return None
    # Convert timestamp to nanoseconds. `start_at` can be `None` (key present,
    # value null) rather than missing, so `.get(..., "")` does not cover it;
    # coerce defensively before parsing.
    try:
        timestamp_str = str(alert.get("start_at") or "").replace("Z", "+00:00")
        parsed = datetime.fromisoformat(timestamp_str)
        if parsed.tzinfo is None:
            # Naive values are UTC, like in events.py; local time would skew the dedup key.
            parsed = parsed.replace(tzinfo=UTC)
        timestamp = int(parsed.timestamp() * 1e9)
    except ValueError, OverflowError:
        print_warning(f"Skipping alert {alert.get('alert_id')!r}: no parseable start_at")
        return None

    tags_str = ",".join([f"{k}={v}" for k, v in tags.items() if v])
    fields_str = ",".join([f"{k}={v}" for k, v in fields.items() if v is not None])

    # The comma before tags_str is only valid when there is at least one tag.
    # as_name always falls back to "unknown", so tags_str is never empty today,
    # but this must not silently emit invalid line protocol if that changes.
    prefix = f"{measurement},{tags_str}" if tags_str else measurement
    return f"{prefix} {fields_str} {timestamp}"


def _caused_by_tls(error: BaseException) -> bool:
    """Whether an ssl.SSLError sits anywhere in the cause chain of a transport failure."""
    seen = set()
    while error is not None and id(error) not in seen:
        if isinstance(error, ssl.SSLError):
            return True
        seen.add(id(error))
        error = error.__cause__ or error.__context__
    return False


def _build_config() -> InfluxDBConfig:
    """Build the client settings; HTTPS uses the hardened TLS context (TLS 1.2-1.3, configured ciphers)."""
    context = (
        hardened_tls_context(ciphers=INFLUXDB_CIPHERS, verify=INFLUXDB_VALIDATE_CERTIFICATE)
        if INFLUXDB_USE_HTTPS
        else None
    )
    return InfluxDBConfig(
        host=INFLUXDB_URL,
        port=INFLUXDB_PORT,
        https=INFLUXDB_USE_HTTPS,
        token=INFLUXDB_TOKEN,
        organization=INFLUXDB_ORGANIZATION,
        bucket=INFLUXDB_BUCKET,
        ssl_context=context,
        timeout=REQUEST_TIMEOUT,
        # Deliberate: plain HTTP or an unverified certificate only warns (main.warn_insecure_transport).
        allow_insecure=True,
    )


def send_to_influxdb(line_protocol_data: str) -> bool:
    """Send line protocol data to the InfluxDB 2.x write API (hardened TLS over HTTPS).

    Every line carries its timestamp, so a repeated write is idempotent. A single attempt per
    batch (no retries): the next scheduled run resends everything.
    Returns True when the server confirmed every batch with HTTP 204, False on any failure.
    """
    protocol = "https" if INFLUXDB_USE_HTTPS else "http"
    url = f"{protocol}://{INFLUXDB_URL}:{INFLUXDB_PORT}/api/v2/write"
    try:
        config = _build_config()
        print_info(f"Writing data to InfluxDB at {url}" + (" with hardened TLS" if INFLUXDB_USE_HTTPS else ""))
        with InfluxDBClient(config, retry=NO_RETRY) as client:
            client.write(line_protocol_data)
        print_success("Wrote data to InfluxDB")
        return True
    except ssl.SSLError as e:
        print_error(f"SSL/TLS error: {e}")
    except InfluxDBUnavailableError as e:
        if e.status_code is not None:
            print_error(f"InfluxDB API error: {e.status_code} - {e.body[:300]}")
        elif _caused_by_tls(e):
            print_error(f"SSL/TLS error: {e}")
        else:
            print_error(f"Connection error to InfluxDB: {e}")
    except InfluxDBError as e:
        print_error(f"InfluxDB API error: {e.status_code} - {e.body[:300]}")
    except ValueError as e:
        print_error(f"Invalid InfluxDB write configuration: {e}")
    except Exception as e:
        # Last resort: an unexpected error fails the write instead of crashing the run.
        print_error(f"Unexpected error sending to InfluxDB: {e}")
    return False
