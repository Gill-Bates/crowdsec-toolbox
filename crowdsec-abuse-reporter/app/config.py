#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import math
import os
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SETTINGS_PATH = Path(os.getenv("SETTINGS_PATH", str(BASE_DIR / "settings.env")))


def _parse_env_line(line: str) -> tuple[str, str] | None:
    """Parse a single KEY=VALUE line, dotenv-style.

    Returns None for blank lines, comments, and lines without a valid KEY.
    Supports an optional leading 'export ' prefix and strips a single layer of
    matching single or double quotes from the value. Unquoted values have
    surrounding whitespace stripped (matching python-dotenv's prior
    behaviour); quoted values keep their contents byte-for-byte, so a
    password with leading/trailing spaces survives when quoted.
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
    if not key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
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

    A missing file is not an error. When override is False, existing
    environment variables win (this matters for Docker, which sets
    variables via env_file before this loader runs).
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


load_settings_env(SETTINGS_PATH, override=False)


def _log_config_warning(message: str) -> None:
    """Internal logger for config-related warnings without disrupting main logging."""
    print(f"⚠️  Config Warning: {message}")


def _fail_clean(message: str) -> None:
    """Print an actionable config error and exit without a Python traceback."""
    print(f"✗ Config Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _get_float_env(name: str, default: float, *, minimum: float = 0.0) -> float:
    """Read a float env var with validation and fallback logging."""
    try:
        value = float(os.getenv(name, str(default)).strip())
    except (ValueError, TypeError, AttributeError):
        _log_config_warning(f"Invalid {name}, using default {default}")
        return default

    # float() accepts 'nan'/'inf'/'-inf'. NaN and +inf slip past the minimum
    # check below (NaN compares False; +inf is never < minimum) and would yield
    # an unbounded/undefined timeout or delay, so reject non-finite values.
    if not math.isfinite(value):
        _log_config_warning(f"Invalid {name} (not finite), using default {default}")
        return default

    if value < minimum:
        _log_config_warning(f"{name} below {minimum}, using default {default}")
        return default

    return value


def _get_int_env(name: str, default: int, *, minimum: int = 0) -> int:
    """Read an int env var with validation and fallback logging."""
    try:
        value = int(os.getenv(name, str(default)).strip())
    except (ValueError, TypeError, AttributeError):
        _log_config_warning(f"Invalid {name}, using default {default}")
        return default

    if value < minimum:
        _log_config_warning(f"{name} below {minimum}, using default {default}")
        return default

    return value


def _get_bool_env(name: str, default: bool) -> bool:
    """Read a bool env var from common true/false spellings."""
    raw = os.getenv(name)
    if raw is None:
        return default

    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    _log_config_warning(f"Invalid {name}, using default {default}")
    return default


_ASN_RE = re.compile(r"(?:AS)?([0-9]+)", re.IGNORECASE)


def normalize_asn(value: object) -> str:
    """Reduce an ASN to its bare digits so 'AS8881', 'as8881', ' 8881 ' and the
    integer 8881 all compare equal. Returns '' when the value is not a plain
    ASN.

    Deliberately strict: WHITELISTED_ASN suppresses reporting outright, so a
    malformed entry must not silently resolve to a different ASN. Digit-scraping
    would turn 'AS12foo34' into '1234' and whitelist an unrelated network.
    """
    match = _ASN_RE.fullmatch(str(value).strip())
    return match.group(1) if match else ""


_raw_smtp_password = os.getenv("SMTP_PASSWORD", "")
# Do not normalize the secret: a password may legitimately contain leading or
# trailing spaces, and silently stripping them causes confusing auth failures.
# Only reject characters that cannot appear in a valid SMTP AUTH credential.
if any(ch in _raw_smtp_password for ch in "\r\n\x00"):
    _fail_clean("SMTP_PASSWORD contains invalid control characters (CR/LF/NUL)")
SMTP_PASSWORD = _raw_smtp_password


HOSTNAME_OVERRIDE = os.getenv("HOSTNAME_OVERRIDE", "")

# Reporting identity autodetection. When HOSTNAME_OVERRIDE is empty, the tool
# detects the host's routable public IP by querying an external service. This
# yields the correct WAN address even inside Docker/behind NAT, instead of a
# useless private bridge IP. Set PUBLIC_IP_DETECTION=false to fall back to
# local interface detection (which may report a private IP).
PUBLIC_IP_DETECTION = _get_bool_env("PUBLIC_IP_DETECTION", True)
PUBLIC_IP_TIMEOUT = _get_float_env("PUBLIC_IP_TIMEOUT", 5.0, minimum=0.5)

SENDER_NAME = os.getenv("SENDER_NAME", "")
BCC = [a.strip() for a in os.getenv("BCC", "").split(",") if a.strip()]


# ASNs that must NEVER receive an abuse mail. Normalized to bare digits so the
# comparison is robust against the "AS" prefix (CrowdSec reports as_number as
# plain digits, e.g. "8881", while operators write "AS8881" in settings.env).
WHITELISTED_ASN = frozenset(
    normalized
    for raw in os.getenv("WHITELISTED_ASN", "").split(",")
    if (normalized := normalize_asn(raw))
)

# Left empty when unset so the CrowdSec credentials file can supply the URL.
# A default here would always win over the file (see _resolve_lapi_credentials).
CROWDSEC_LAPI_URL = os.getenv("CROWDSEC_LAPI_URL", "").strip()
CROWDSEC_LAPI_MACHINE_ID = os.getenv("CROWDSEC_LAPI_MACHINE_ID", "").strip()
# Not stripped, for the same reason as SMTP_PASSWORD: a generated credential may
# legitimately carry edge whitespace, and silently trimming it causes permanent
# auth failures in unattended runs. Only reject what cannot appear in a header.
CROWDSEC_LAPI_PASSWORD = os.getenv("CROWDSEC_LAPI_PASSWORD", "")
if any(ch in CROWDSEC_LAPI_PASSWORD for ch in "\r\n\x00"):
    _fail_clean("CROWDSEC_LAPI_PASSWORD contains invalid control characters (CR/LF/NUL)")
CROWDSEC_LAPI_CREDENTIALS_PATH = os.getenv(
    "CROWDSEC_LAPI_CREDENTIALS_PATH", "/etc/crowdsec/local_api_credentials.yaml"
).strip()
CROWDSEC_LAPI_VERIFY_TLS = _get_bool_env("CROWDSEC_LAPI_VERIFY_TLS", True)
CROWDSEC_LAPI_TIMEOUT = _get_float_env("CROWDSEC_LAPI_TIMEOUT", 30.0, minimum=1.0)

# The LAPI alert *list* endpoint returns summary alerts without events/enrichment.
# Fetch each alert's full detail (GET /v1/alerts/{id}) so reports can include the
# usernames, attack patterns, AS/country and event counts CrowdSec captured.
CROWDSEC_FETCH_ALERT_DETAILS = _get_bool_env("CROWDSEC_FETCH_ALERT_DETAILS", True)
# Safety cap on per-run detail fetches (one HTTP request each).
CROWDSEC_DETAIL_LIMIT = _get_int_env("CROWDSEC_DETAIL_LIMIT", 500, minimum=0)

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")


def _get_port_env(name: str, default: int) -> int:
    value = _get_int_env(name, default, minimum=1)
    if value > 65_535:
        _log_config_warning(f"{name} above 65535, using default {default}")
        return default
    return value


SMTP_PORT = _get_port_env("SMTP_PORT", 587)
SMTP_USE_TLS = _get_bool_env("SMTP_USE_TLS", True)
SMTP_VERIFY_SSL = _get_bool_env("SMTP_VERIFY_SSL", True)
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_SENDER = os.getenv("SMTP_SENDER", "abuse-reporter@example.com")

SLEEP_BETWEEN_MAILS = _get_int_env("SLEEP_BETWEEN_MAILS", 0)

# Chunked sending: process at most MAIL_CHUNK_SIZE mails, then pause
# SLEEP_BETWEEN_CHUNKS seconds before the next chunk. MAIL_CHUNK_SIZE=0 disables
# chunking (single continuous pass).
MAIL_CHUNK_SIZE = _get_int_env("MAIL_CHUNK_SIZE", 0)
SLEEP_BETWEEN_CHUNKS = _get_int_env("SLEEP_BETWEEN_CHUNKS", 0)

ABUSIX_TIMEOUT = _get_float_env("ABUSIX_TIMEOUT", 3.0, minimum=0.1)

# Total DNS budget per abuse-contact lookup (across retries/nameservers). Keeps
# a slow or unreachable resolver from hanging the whole run.
ABUSIX_DNS_LIFETIME = _get_float_env(
    "ABUSIX_DNS_LIFETIME", max(ABUSIX_TIMEOUT, 5.0), minimum=0.1
)

DATA_DIR = BASE_DIR / "data"

# Working directory for the GeoLite2 databases. The container points this at a
# tmpfs and seeds it from the copy baked into the image at build time, so the
# databases never live on a persistent volume; the updater then overwrites them
# in place when a newer release exists. Direct host runs keep them under data/.
GEOIP_DIR = Path(os.getenv("GEOIP_DIR", "").strip() or (DATA_DIR / "geolite2"))

# Records in abuse_alerts older than this are deleted at startup. The
# abuse_contacts_cache uses 2× the same value. Set to 0 to disable cleanup.
DB_RETENTION_DAYS = _get_int_env("DB_RETENTION_DAYS", 365, minimum=0)

# Rows stuck in 'pending' (a send was claimed but never finalized — e.g. a crash
# or kill mid-send) have an unknown SMTP outcome. At each startup, any pending row
# older than this many minutes is moved to the terminal 'unknown_send_state' and
# never retried (at-most-once delivery). Must comfortably exceed a single
# alert's send time. Set to 0 to disable.
PENDING_REAP_MINUTES = _get_int_env("PENDING_REAP_MINUTES", 60, minimum=0)

# Logging verbosity for the stdlib logger (crowdsec.py, reportbody.py, …).
# DEBUG surfaces decision/alert key matching and IP detection traces.
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip() or "INFO"

# Cap on alerts handled per run. 0 disables the cap.
MAX_ALERTS_PER_RUN = _get_int_env("MAX_ALERTS_PER_RUN", 0)

# Optional time-series export of report outcomes, same variable names as
# crowdsec-metrics-exporter. "none" (default) keeps the full audit trail in
# SQLite. With "influxdb2" or "questdb" the report details (recipient,
# scenario, error text) go only to that backend and SQLite keeps control data
# alone (claim/status per (AlertId, IP), contact cache, run state), so the
# same data is never stored twice.
METRICS_BACKEND = os.getenv("METRICS_BACKEND", "none").strip().lower() or "none"
if METRICS_BACKEND not in {"none", "influxdb2", "questdb"}:
    _fail_clean(
        f"METRICS_BACKEND must be 'none', 'influxdb2' or 'questdb', got {METRICS_BACKEND!r}"
    )
METRICS_ENABLED = METRICS_BACKEND != "none"
METRICS_ONLY = _get_bool_env("METRICS_ONLY", False)

INFLUXDB_URL = os.getenv("INFLUXDB_URL", "localhost").strip()
INFLUXDB_PORT = _get_port_env("INFLUXDB_PORT", 443)
INFLUXDB_USE_HTTPS = _get_bool_env("INFLUXDB_USE_HTTPS", True)
INFLUXDB_VALIDATE_CERTIFICATE = _get_bool_env("INFLUXDB_VALIDATE_CERTIFICATE", True)
INFLUXDB_ORGANIZATION = os.getenv("INFLUXDB_ORGANIZATION", "myOrg").strip()
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "crowdsec").strip()
INFLUXDB_TOKEN = os.getenv("INFLUXDB_TOKEN", "")
if METRICS_BACKEND == "influxdb2" and not INFLUXDB_TOKEN:
    _fail_clean("METRICS_BACKEND=influxdb2 requires INFLUXDB_TOKEN")

QUESTDB_URL = os.getenv("QUESTDB_URL", "localhost").strip()
QUESTDB_PORT = _get_port_env("QUESTDB_PORT", 9000)
QUESTDB_USE_HTTPS = _get_bool_env("QUESTDB_USE_HTTPS", False)
QUESTDB_VALIDATE_CERTIFICATE = _get_bool_env("QUESTDB_VALIDATE_CERTIFICATE", True)
QUESTDB_TABLE = os.getenv("QUESTDB_TABLE", "crowdsec-abuse").strip() or "crowdsec-abuse"
QUESTDB_TOKEN = os.getenv("QUESTDB_TOKEN", "")
QUESTDB_USERNAME = os.getenv("QUESTDB_USERNAME", "")
QUESTDB_PASSWORD = os.getenv("QUESTDB_PASSWORD", "")

_TTL_UNITS = {"h": "HOURS", "d": "DAYS", "w": "WEEKS", "M": "MONTHS", "y": "YEARS"}


def parse_questdb_ttl(raw: str) -> str | None:
    """Turn '365d' / '12w' / '1y' / '48h' / '6M' into QuestDB's 'TTL' clause
    value (e.g. '365 DAYS'). '', '0' or '0d' disable the TTL (None).
    Raises ValueError on anything else."""
    value = raw.strip()
    if value in {"", "0"}:
        return None
    match = re.fullmatch(r"([0-9]+)\s*([hdwMy])", value)
    if not match:
        raise ValueError(
            f"QUESTDB_TTL must look like 365d, 12w, 6M, 1y or 48h, got {raw!r}"
        )
    amount = int(match.group(1))
    if amount == 0:
        return None
    return f"{amount} {_TTL_UNITS[match.group(2)]}"


# Retention applied to the QuestDB table after each write (ALTER TABLE ... SET
# TTL). Default 365d; "0" disables.
try:
    QUESTDB_TTL = parse_questdb_ttl(os.getenv("QUESTDB_TTL", "365d"))
except ValueError as _e:
    _fail_clean(str(_e))

for _name, _secret in (
    ("INFLUXDB_TOKEN", INFLUXDB_TOKEN),
    ("QUESTDB_TOKEN", QUESTDB_TOKEN),
    ("QUESTDB_PASSWORD", QUESTDB_PASSWORD),
):
    if any(ch in _secret for ch in "\r\n\x00"):
        _fail_clean(f"{_name} contains invalid control characters (CR/LF/NUL)")

REQUEST_TIMEOUT = _get_float_env("REQUEST_TIMEOUT", 30.0, minimum=1.0)

# Retries for a single metrics write, on top of the durable outbox below. Cheap
# insurance against a DNS blip or a one-off connection reset: a transient
# failure is resolved inside the run instead of deferring the points to the next
# one. Attempts are spaced by METRICS_RETRY_BACKOFF * 2**n seconds.
METRICS_WRITE_RETRIES = _get_int_env("METRICS_WRITE_RETRIES", 2, minimum=0)
METRICS_RETRY_BACKOFF = _get_float_env("METRICS_RETRY_BACKOFF", 1.0, minimum=0.0)

# Durable spool for report points that the backend has not accepted yet. A point
# is written here before any network call and removed only once the backend
# acknowledged it, so a backend outage defers the points to the next run instead
# of losing them. Replay is safe because it is exactly idempotent: the timestamp
# is baked into the line, and DEDUP_KEYS / InfluxDB's own series+timestamp rule
# collapse a repeated point onto the same row.
#
# The bounds exist so a long outage cannot grow the database without limit.
# Oldest rows are dropped first — they are the least useful, and dropping them is
# the same outcome the code had before the outbox existed.
METRICS_OUTBOX_MAX_ROWS = _get_int_env("METRICS_OUTBOX_MAX_ROWS", 50000, minimum=0)
METRICS_OUTBOX_MAX_AGE_DAYS = _get_int_env(
    "METRICS_OUTBOX_MAX_AGE_DAYS", 30, minimum=0
)
