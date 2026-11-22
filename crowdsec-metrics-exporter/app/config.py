#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Configuration for the CrowdSec metrics exporter.
Reads settings.env and the process environment into module-level constants, with defaults.
"""

import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from gillbates_questdb_client import parse_ttl, ttl_days

BASE_DIR = Path(__file__).resolve().parent.parent


def _exit(message: str) -> SystemExit:
    """Build the exit for a config error as a log-format line (the logger imports this module)."""
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    return SystemExit(f"{now} | ERROR    | crowdsec_metrics | {message}")


def _env_bool(name: str, default: bool) -> bool:
    """Read an explicit true/false setting, rejecting values that could weaken security silently."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    raise _exit(f"Config Error: {name} must be 'true' or 'false', got {raw!r}")


def _env_int(name: str, default: int, *, minimum: int, maximum: int | None = None) -> int:
    """Read an integer setting; a set but unusable value aborts startup instead of falling back."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        value = None
    if value is None or value < minimum or (maximum is not None and value > maximum):
        bound = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        raise _exit(f"Config Error: {name} must be an integer {bound}, got {raw!r}")
    return value


def _parse_env_line(line: str) -> tuple[str, str] | None:
    """Parse a single KEY=VALUE line, dotenv-style.

    Returns None for blank lines, comments, and lines without a valid KEY.
    Supports an optional leading 'export ' prefix and strips a single layer of
    matching single or double quotes from the value. Unquoted values have
    surrounding whitespace stripped.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()

    if "=" not in stripped:
        return None

    key, _, value = stripped.partition("=")
    key = key.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return None

    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    else:
        # Unquoted values: dotenv semantics treat whitespace followed by '#'
        # as the start of an inline comment. A '#' directly abutting the
        # preceding character is kept as part of the value.
        match = re.search(r"\s#", value)
        if match:
            value = value[: match.start()].strip()

    return key, value


def load_settings_env(path: Path, *, override: bool) -> None:
    """Load KEY=VALUE pairs from an env file into os.environ.

    A missing file is not an error. This exporter loads with override=True,
    so settings.env always wins over the ambient environment.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return

    for line in text.splitlines():
        parsed = _parse_env_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if override or key not in os.environ:
            os.environ[key] = value


load_settings_env(BASE_DIR / "settings.env", override=True)


def _positive_timeout[N: (int, float)](name: str, cast: type[N], default: N) -> N:
    """Read a timeout from the environment as a finite number greater than zero.

    An unset or empty variable uses the default. A value that is set but
    unusable (unparsable, zero, negative, nan, inf) aborts startup: silently
    falling back would hide a typo, and 0, nan and inf would disable or break
    the HTTP timeout.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = cast(raw)
    except ValueError:
        raise _exit(f"Config Error: {name} must be a finite number greater than 0, got {raw!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise _exit(f"Config Error: {name} must be a finite number greater than 0, got {raw!r}")
    return value


HOSTNAME_OVERRIDE = os.getenv("HOSTNAME_OVERRIDE", "")

# Console log level: DEBUG, INFO (default), WARNING or ERROR. DEBUG additionally
# surfaces the line-protocol sample lines.
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper()
if LOG_LEVEL not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
    raise _exit(f"Config Error: LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR, got {LOG_LEVEL!r}")

# Metrics backend selection: "influxdb2" (default) or "questdb"
METRICS_BACKEND = os.getenv("METRICS_BACKEND", "influxdb2").strip().lower()
if METRICS_BACKEND not in {"influxdb2", "questdb"}:
    raise _exit(f"Config Error: METRICS_BACKEND must be 'influxdb2' or 'questdb', got {METRICS_BACKEND!r}")

# CrowdSec Local API (LAPI) configuration
#
# The exporter talks to the LAPI over HTTP as a registered machine, the same way
# crowdsec-abuse-reporter does. It deliberately does *not* shell out to `cscli`
# through the Docker socket: socket access is equivalent to root on the
# host, while these credentials are only valid against the LAPI.
CROWDSEC_LAPI_URL = os.getenv("CROWDSEC_LAPI_URL", "").strip()
CROWDSEC_LAPI_MACHINE_ID = os.getenv("CROWDSEC_LAPI_MACHINE_ID", "").strip()
CROWDSEC_LAPI_PASSWORD = os.getenv("CROWDSEC_LAPI_PASSWORD", "")
if any(ch in CROWDSEC_LAPI_PASSWORD for ch in "\r\n\x00"):
    raise _exit("Config Error: CROWDSEC_LAPI_PASSWORD contains invalid control characters (CR/LF/NUL)")

# Fallback for direct host runs: CrowdSec's own watcher credentials file, used
# when the URL, machine ID or password is not supplied via the environment.
CROWDSEC_LAPI_CREDENTIALS_PATH = os.getenv("CROWDSEC_LAPI_CREDENTIALS_PATH", "/etc/crowdsec/local_api_credentials.yaml")
CROWDSEC_LAPI_VALIDATE_CERTIFICATE = _env_bool("CROWDSEC_LAPI_VALIDATE_CERTIFICATE", True)
CROWDSEC_LAPI_TIMEOUT = max(_positive_timeout("CROWDSEC_LAPI_TIMEOUT", float, 30.0), 1.0)

# Initial alert limit per LAPI call; a full response escalates it up to crowdsec.MAX_ALERT_FETCH_LIMIT.
CROWDSEC_ALERT_LIMIT = _env_int("CROWDSEC_ALERT_LIMIT", 10000, minimum=1)


def _require_bare_host(name: str, raw: str) -> str:
    """Return raw as a bare host name, aborting on scheme, port or path.

    `influxdb.py` and `questdb.py` assemble the endpoint
    themselves (`{protocol}://{host}:{port}/...`), so a value like
    "https://host" would produce "https://https://host:443/write" and fail as
    an opaque DNS error. Reject it at startup with a message that names the
    fix instead.
    """
    host = raw.strip().rstrip("/")
    if "://" in host:
        scheme, _, remainder = host.partition("://")
        raise _exit(
            f"Config Error: {name} must be a bare host name without a scheme. "
            f"Use {name}={remainder.split('/')[0]} and control the scheme via "
            f"{name.rsplit('_', 1)[0]}_USE_HTTPS (got {scheme}://...)"
        )
    if "/" in host:
        raise _exit(f"Config Error: {name} must be a host name without a path, got {raw!r}")
    # A bracketed IPv6 literal legitimately contains colons; anything else with
    # a colon is a host:port pair that would collide with the separate port
    # setting.
    if ":" in host and not host.startswith("["):
        raise _exit(
            f"Config Error: {name} must not include a port; set {name.rsplit('_', 1)[0]}_PORT instead (got {raw!r})"
        )
    return host


# InfluxDB configuration
INFLUXDB_URL = _require_bare_host("INFLUXDB_URL", os.getenv("INFLUXDB_URL", "localhost"))
INFLUXDB_PORT = _env_int("INFLUXDB_PORT", 443, minimum=1, maximum=65535)
INFLUXDB_USE_HTTPS = _env_bool("INFLUXDB_USE_HTTPS", True)
INFLUXDB_VALIDATE_CERTIFICATE = _env_bool("INFLUXDB_VALIDATE_CERTIFICATE", True)
INFLUXDB_ORGANIZATION = os.getenv("INFLUXDB_ORGANIZATION", "myOrg")
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "crowdsec")

# InfluxDB Security Settings. The TLS version bounds live in
# `gillbates_influxdb_client.hardened_tls_context` (TLS 1.2 to 1.3); only the
# cipher list is configured here.
INFLUXDB_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"

INFLUXDB_TOKEN = os.getenv("INFLUXDB_TOKEN", "")


# QuestDB configuration (used when METRICS_BACKEND=questdb)
QUESTDB_URL = _require_bare_host("QUESTDB_URL", os.getenv("QUESTDB_URL", "localhost"))
QUESTDB_PORT = _env_int("QUESTDB_PORT", 9000, minimum=1, maximum=65535)
QUESTDB_USE_HTTPS = _env_bool("QUESTDB_USE_HTTPS", False)
QUESTDB_VALIDATE_CERTIFICATE = _env_bool("QUESTDB_VALIDATE_CERTIFICATE", True)
QUESTDB_TABLE = os.getenv("QUESTDB_TABLE", "crowdsec")
QUESTDB_TOKEN = os.getenv("QUESTDB_TOKEN", "")
QUESTDB_USERNAME = os.getenv("QUESTDB_USERNAME", "")
QUESTDB_PASSWORD = os.getenv("QUESTDB_PASSWORD", "")

# Retention applied to the QuestDB table after each write (ALTER TABLE ... SET
# TTL). Default 365d; "0" disables.
_QUESTDB_TTL_RAW = os.getenv("QUESTDB_TTL", "365d")
try:
    QUESTDB_TTL = parse_ttl(_QUESTDB_TTL_RAW)
    QUESTDB_TTL_DAYS = ttl_days(_QUESTDB_TTL_RAW)
except ValueError as _e:
    raise _exit(f"Config Error: {_e}") from None


# QuestDB downsampling ------------------------------------------------------
# A profile keeps the full-resolution rows for a short window and moves the
# long-term history into a materialized rollup view, which then carries
# QUESTDB_TTL. The intervals suit ban data: one row per decision, not a
# per-second gauge.
@dataclass(frozen=True)
class QuestDBDownsamplingProfile:
    raw_retention_days: int
    rollup_interval: str


QUESTDB_DOWNSAMPLING_PROFILES: dict[str, QuestDBDownsamplingProfile] = {
    "low": QuestDBDownsamplingProfile(raw_retention_days=90, rollup_interval="1h"),
    "medium": QuestDBDownsamplingProfile(raw_retention_days=30, rollup_interval="1h"),
    "high": QuestDBDownsamplingProfile(raw_retention_days=7, rollup_interval="6h"),
}
# Bumping this changes the rollup view name, so a definition change is additive
# instead of conflicting with a view an older build created.
QUESTDB_DOWNSAMPLING_SCHEMA_VERSION = 1
QUESTDB_DOWNSAMPLING_STATE_TABLE = "_crowdsec_downsampling"
QUESTDB_DOWNSAMPLING_DISABLED_PROFILE = "disabled"

QUESTDB_DOWNSAMPLING = os.getenv("QUESTDB_DOWNSAMPLING", "").strip().lower()
if QUESTDB_DOWNSAMPLING and QUESTDB_DOWNSAMPLING not in QUESTDB_DOWNSAMPLING_PROFILES:
    raise _exit(
        "Config Error: QUESTDB_DOWNSAMPLING must be empty or one of "
        f"{', '.join(sorted(QUESTDB_DOWNSAMPLING_PROFILES))}, got {QUESTDB_DOWNSAMPLING!r}"
    )

# Per-event export (LAPI GET /v1/alerts) -----------------------------------
# The decision export above writes one point per alert. This second, optional
# export writes one point per *event* inside an alert, which is what carries
# the request details (http_path, http_verb, target_fqdn, target_user).
EVENTS_ENABLED = _env_bool("EVENTS_ENABLED", False)
EVENTS_TABLE = os.getenv("EVENTS_TABLE", f"{QUESTDB_TABLE}_events")


def _validate_questdb_event_table(backend: str, events_enabled: bool, alert_table: str, event_table: str) -> None:
    if backend == "questdb" and events_enabled and alert_table == event_table:
        raise _exit("Config Error: EVENTS_TABLE must differ from QUESTDB_TABLE")


_validate_questdb_event_table(METRICS_BACKEND, EVENTS_ENABLED, QUESTDB_TABLE, EVENTS_TABLE)

# Time window passed to the LAPI `since` parameter. Must stay comfortably
# larger than the export interval so nothing falls between two runs. The whole
# window is re-sent on every run and the backend deduplicates, so this value
# also sets the write amplification: window / run interval.
EVENTS_SINCE = os.getenv("EVENTS_SINCE", "30m").strip()
if not re.fullmatch(r"[0-9]+[smhd]", EVENTS_SINCE):
    raise _exit(f"Config Error: EVENTS_SINCE must look like 30m, 2h or 1d, got {EVENTS_SINCE!r}")

# Performance and behavior settings
REQUEST_TIMEOUT = _positive_timeout("REQUEST_TIMEOUT", int, 30)

__all__ = [
    "CROWDSEC_ALERT_LIMIT",
    "CROWDSEC_LAPI_CREDENTIALS_PATH",
    "CROWDSEC_LAPI_MACHINE_ID",
    "CROWDSEC_LAPI_PASSWORD",
    "CROWDSEC_LAPI_TIMEOUT",
    "CROWDSEC_LAPI_URL",
    "CROWDSEC_LAPI_VALIDATE_CERTIFICATE",
    "EVENTS_ENABLED",
    "EVENTS_SINCE",
    "EVENTS_TABLE",
    "HOSTNAME_OVERRIDE",
    "INFLUXDB_BUCKET",
    "INFLUXDB_CIPHERS",
    "INFLUXDB_ORGANIZATION",
    "INFLUXDB_PORT",
    "INFLUXDB_TOKEN",
    "INFLUXDB_URL",
    "INFLUXDB_USE_HTTPS",
    "INFLUXDB_VALIDATE_CERTIFICATE",
    "LOG_LEVEL",
    "METRICS_BACKEND",
    "QUESTDB_DOWNSAMPLING",
    "QUESTDB_DOWNSAMPLING_DISABLED_PROFILE",
    "QUESTDB_DOWNSAMPLING_PROFILES",
    "QUESTDB_DOWNSAMPLING_SCHEMA_VERSION",
    "QUESTDB_DOWNSAMPLING_STATE_TABLE",
    "QUESTDB_PASSWORD",
    "QUESTDB_PORT",
    "QUESTDB_TABLE",
    "QUESTDB_TOKEN",
    "QUESTDB_TTL",
    "QUESTDB_TTL_DAYS",
    "QUESTDB_URL",
    "QUESTDB_USERNAME",
    "QUESTDB_USE_HTTPS",
    "QUESTDB_VALIDATE_CERTIFICATE",
    "REQUEST_TIMEOUT",
]
