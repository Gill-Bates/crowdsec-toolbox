#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/influxdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
InfluxDB integration: line protocol formatting and writes to InfluxDB 2.x.
"""

import math
import re
import ssl
from datetime import UTC, datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

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


class TLS12Adapter(HTTPAdapter):
    """HTTPAdapter that enforces TLS 1.2+ with the configured cipher list."""

    def init_poolmanager(self, *args, **kwargs):
        """Initialize the pool manager with a hardened TLS context."""
        context = create_urllib3_context(
            ssl_minimum_version=ssl.TLSVersion.TLSv1_2,
            ssl_maximum_version=ssl.TLSVersion.TLSv1_3,
            ciphers=INFLUXDB_CIPHERS,
        )
        kwargs["ssl_context"] = context
        return super().init_poolmanager(*args, **kwargs)


def create_secure_session() -> requests.Session:
    """Create a requests session whose http and https adapters enforce TLS 1.2+."""
    session = requests.Session()

    adapter = TLS12Adapter()
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return session


# Line breaks and other C0 controls (tab excepted) cannot be represented in a
# tag value, and InfluxDB rejects "\n" in field values too: one such value
# would split a line and invalidate the whole batch.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def _strip_control_chars(value: str) -> str:
    """Replace line breaks and other control characters with a single space each."""
    return _CONTROL_CHARS.sub(" ", value)


def escape_influxdb_value(value: str) -> str:
    """Escape comma, equals sign and space for tag values and measurements.

    Control characters are replaced by a space first (deterministic, so dedup keys stay stable).
    """
    if not value:
        return ""
    value_str = _strip_control_chars(str(value))
    return value_str.replace(",", "\\,").replace("=", "\\=").replace(" ", "\\ ")


def escape_influxdb_string_field(value: str) -> str:
    """Return value as a quoted line-protocol string field, escaping backslash and quote."""
    if not value:
        return '""'
    # Backslashes first: escaping quotes first would double the escape character.
    value_str = _strip_control_chars(str(value)).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{value_str}"'


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
        "events_count": events_count if isinstance(events_count, int) and not isinstance(events_count, bool) else None,
        "latitude": _coordinate(alert.get("latitude"), 90.0),
        "longitude": _coordinate(alert.get("longitude"), 180.0),
        "message": escape_influxdb_string_field(alert.get("message", "")),
        "abuse_email": escape_influxdb_string_field(alert.get("abuse_email", "")),
        "alert_id": int(alert.get("alert_id", 0)),
    }

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


def send_to_influxdb(line_protocol_data: str) -> bool:
    """Send line protocol data to the InfluxDB 2.x write API (hardened TLS over HTTPS).

    Returns True on HTTP 204, False on any failure.
    """
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

    session = None
    try:
        if INFLUXDB_USE_HTTPS:
            print_info(f"Writing data to InfluxDB at {url} with hardened TLS")
            session = create_secure_session()
        else:
            print_info(f"Writing data to InfluxDB at {url}")
            session = requests.Session()

        response = session.post(
            url,
            headers=headers,
            params=params,
            data=line_protocol_data,
            verify=INFLUXDB_VALIDATE_CERTIFICATE,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 204:
            print_success("Wrote data to InfluxDB")
            return True
        print_error(f"InfluxDB API error: {response.status_code} - {response.text[:300]}")
        return False

    except ssl.SSLError as e:
        print_error(f"SSL/TLS error: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print_error(f"Connection error to InfluxDB: {e}")
        return False
    except Exception as e:
        # Last resort: an unexpected error fails the write instead of crashing the run.
        print_error(f"Unexpected error sending to InfluxDB: {e}")
        return False
    finally:
        if session is not None:
            session.close()
