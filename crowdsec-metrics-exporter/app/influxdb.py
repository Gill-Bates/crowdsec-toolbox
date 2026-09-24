#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/influxdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
InfluxDB integration module.
Handles data formatting and communication with InfluxDB 2.x.
"""

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
from .logger import print_error, print_info, print_success


class TLS12Adapter(HTTPAdapter):
    """HTTPAdapter that enforces TLS 1.2+ with secure ciphers"""

    def init_poolmanager(self, *args, **kwargs):
        """
        Initialize pool manager with hardened TLS configuration.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
        """
        context = create_urllib3_context(
            ssl_minimum_version=ssl.TLSVersion.TLSv1_2,
            ssl_maximum_version=ssl.TLSVersion.TLSv1_3,
            ciphers=INFLUXDB_CIPHERS,
        )
        kwargs["ssl_context"] = context
        return super().init_poolmanager(*args, **kwargs)


def create_secure_session() -> requests.Session:
    """
    Create a requests session with hardened TLS configuration.

    Returns:
        Configured session with TLS 1.2+ enforcement
    """
    session = requests.Session()

    # Add TLS 1.2+ adapter
    adapter = TLS12Adapter()
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return session


def verify_tls_configuration() -> bool:
    """
    Verify that the TLS configuration meets security requirements.

    Returns:
        True if TLS configuration is secure, False otherwise
    """
    # Check available TLS versions
    test_session = None
    try:
        # Test cipher suite with a secure session
        test_session = create_secure_session()
        test_response = test_session.get(
            "https://www.howsmyssl.com/a/check", timeout=10
        )

        if test_response.status_code == 200:
            ssl_info = test_response.json()
            tls_version = ssl_info.get("tls_version")
            rating = ssl_info.get("rating")

            print_info(f"TLS version: {tls_version}")
            print_info(f"Security rating: {rating}")

            # Check if TLS 1.2 or higher is used
            if tls_version and any(
                version in tls_version for version in ["TLS 1.2", "TLS 1.3"]
            ):
                print_success("TLS 1.2 or higher is available")
                return True
            else:
                print_error("TLS 1.2 or higher is not available")
                return False
        else:
            print_error(f"TLS test failed with status: {test_response.status_code}")
            return False

    except ssl.SSLError as e:
        print_error(f"SSL/TLS error during verification: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print_error(f"Connection error during TLS verification: {e}")
        return False
    finally:
        if test_session is not None:
            test_session.close()


def escape_influxdb_value(value: str) -> str:
    """
    Escape special characters for InfluxDB tags and measurements.

    Args:
        value: String value to escape

    Returns:
        Escaped string safe for InfluxDB
    """
    if not value:
        return ""
    value_str = str(value)
    return value_str.replace(",", "\\,").replace("=", "\\=").replace(" ", "\\ ")


def escape_influxdb_string_field(value: str) -> str:
    """
    Escape string field values for InfluxDB line protocol.

    Args:
        value: String value to escape

    Returns:
        Properly quoted and escaped string
    """
    if not value:
        return '""'
    # Backslashes first: escaping quotes first would double the escape character.
    value_str = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{value_str}"'


def format_influxdb_line_protocol(
    alert: dict, hostname: str, *, host: str | None = None
) -> str:
    """
    Convert a CrowdSec alert into InfluxDB Line Protocol format.

    Args:
        alert: Alert dictionary from CrowdSec
        hostname: Hostname for measurement
        host: Optional source host tag, used to separate QuestDB instances

    Returns:
        Formatted line protocol string
    """
    measurement = escape_influxdb_value(hostname)

    # Build tags dictionary
    tags = {
        "ip_address": escape_influxdb_value(alert.get("ip_address", "")),
        "as_name": escape_influxdb_value(alert.get("as_name", "")) or "unknown",
        "as_number": escape_influxdb_value(str(alert.get("as_number", 0))),
        "country": escape_influxdb_value(alert.get("country", "")),
        "scenario": escape_influxdb_value(alert.get("scenario", "")),
    }
    if host:
        tags["host"] = escape_influxdb_value(host)

    # Build fields dictionary
    fields = {
        "events_count": alert.get("events_count", 0),
        "latitude": float(alert.get("latitude", 0.0)),
        "longitude": float(alert.get("longitude", 0.0)),
        "message": escape_influxdb_string_field(alert.get("message", "")),
        "abuse_email": escape_influxdb_string_field(alert.get("abuse_email", "")),
        "alert_id": int(alert.get("alert_id", 0)),
    }

    # Convert timestamp to nanoseconds. `start_at` can be `None` (key present,
    # value null) rather than missing, so `.get(..., "")` does not cover it;
    # coerce defensively before parsing.
    try:
        timestamp_str = str(alert.get("start_at") or "").replace("Z", "+00:00")
        timestamp = int(datetime.fromisoformat(timestamp_str).timestamp() * 1e9)
    except ValueError:
        # Fallback to current time if parsing fails.
        # utcnow() returned a naive datetime whose .timestamp() was interpreted as
        # local time, which skewed the InfluxDB timestamp on non-UTC hosts.
        timestamp = int(datetime.now(UTC).timestamp() * 1e9)

    # Build line protocol components
    tags_str = ",".join([f"{k}={v}" for k, v in tags.items() if v])
    fields_str = ",".join([f"{k}={v}" for k, v in fields.items() if v is not None])

    return f"{measurement},{tags_str} {fields_str} {timestamp}"


def send_to_influxdb(line_protocol_data: str) -> bool:
    """
    Send line protocol data to InfluxDB 2.x API with hardened TLS.

    Args:
        line_protocol_data: Data formatted in line protocol

    Returns:
        True if successful, False otherwise
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
        print_info(f"Sending data to InfluxDB at {url} with hardened TLS...")

        # Create secure session for HTTPS, normal for HTTP
        if INFLUXDB_USE_HTTPS:
            session = create_secure_session()
        else:
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
            print_success("Data successfully sent to InfluxDB")
            return True
        else:
            print_error(f"InfluxDB API error: {response.status_code} - {response.text}")
            return False

    except ssl.SSLError as e:
        print_error(f"SSL/TLS error: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print_error(f"Connection error to InfluxDB: {e}")
        return False
    except Exception as e:
        # Last-resort guard so an unexpected error is logged and turned into a
        # clean False instead of crashing the run; more specific excepts above
        # handle the expected cases.
        print_error(f"Unexpected error sending to InfluxDB: {e}")
        return False
    finally:
        if session is not None:
            session.close()
