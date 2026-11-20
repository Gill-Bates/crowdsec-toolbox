#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/crowdsec.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
CrowdSec integration module.

Fetches alerts from the CrowdSec Local API (LAPI) over HTTP as a registered
machine: POST /v1/watchers/login yields a bearer token, GET /v1/alerts returns
the data. No Docker socket is needed, which would be equivalent to root on the host.

The module mirrors `crowdsec-abuse-reporter/app/crowdsec.py` (credentials
resolution, retry policy, error type) but stays a separate copy on purpose — the
tools share no application code so each can be deployed independently.
"""

import logging
import socket
import time
from pathlib import Path
from typing import Any

import httpx

from .config import (
    CROWDSEC_ALERT_LIMIT,
    CROWDSEC_LAPI_CREDENTIALS_PATH,
    CROWDSEC_LAPI_MACHINE_ID,
    CROWDSEC_LAPI_PASSWORD,
    CROWDSEC_LAPI_TIMEOUT,
    CROWDSEC_LAPI_URL,
    CROWDSEC_LAPI_VALIDATE_CERTIFICATE,
    HOSTNAME_OVERRIDE,
)
from .logger import print_info, print_success, print_warning

logger = logging.getLogger(__name__)

HOST_HOSTNAME_PATH = Path("/run/host/hostname")

_RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_LAPI_MAX_ATTEMPTS = 3

# Hard ceiling for the escalating alert fetch; bounds memory and response size.
# A larger CROWDSEC_ALERT_LIMIT raises it, so the configured start is never cut.
MAX_ALERT_FETCH_LIMIT = 100_000
_ALERT_FETCH_LIMIT_FACTOR = 10

LAPI_CREDENTIALS_HINT = (
    "Use `docker exec -it <your crowdsec container name> "
    "cat /etc/crowdsec/local_api_credentials.yaml` to inspect the generated "
    "credentials, then copy `login` to `CROWDSEC_LAPI_MACHINE_ID` and "
    "`password` to `CROWDSEC_LAPI_PASSWORD`."
)


class CrowdSecFetchError(Exception):
    """Raised when alerts cannot be fetched or parsed from the LAPI.

    Distinguishes a real failure (auth, transport, invalid JSON) from the valid
    case of CrowdSec simply having nothing to report, so a broken fetch is never
    mistaken for "nothing new".
    """

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.hint = hint


class CrowdSecIncompleteFetchError(CrowdSecFetchError):
    """Raised when the alerts were fetched but the result is provably or possibly partial.

    Causes: the fetch ceiling was reached with a full response, or some event
    details are missing. `alerts` holds everything that was retrieved (summary
    alerts stand in for failed detail requests), so a caller can still export
    it and then rate the run as failed.
    """

    def __init__(self, message: str, alerts: list[dict[str, Any]]):
        super().__init__(message)
        self.alerts = alerts


def parse_record_id(value: Any) -> int | None:
    """Return a LAPI record id as a non-negative int, or None when it is missing or invalid.

    The id is part of the dedup identity, so a substitute such as 0 would merge
    unrelated records: callers skip the record instead. Floats and booleans are
    rejected rather than truncated.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    return None


def get_hostname() -> str:
    """Return the configured or mounted host name, falling back for direct runs."""
    if HOSTNAME_OVERRIDE.strip():
        return HOSTNAME_OVERRIDE.strip()
    try:
        hostname = HOST_HOSTNAME_PATH.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return socket.gethostname()
    if not hostname or any(char in hostname for char in "\r\n\x00"):
        raise ValueError(f"Host hostname file is invalid: {HOST_HOSTNAME_PATH}")
    return hostname


def _read_lapi_credentials_file() -> dict[str, str]:
    """Read url/login/password from CrowdSec's default credentials file."""
    path = Path(CROWDSEC_LAPI_CREDENTIALS_PATH)
    if not path.exists():
        return {}

    credentials: dict[str, str] = {}
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            if key not in {"url", "login", "password"}:
                continue
            credentials[key] = value.strip().strip('"').strip("'")
    except OSError as e:
        raise CrowdSecFetchError(f"Failed to read LAPI credentials file {path}: {e}") from e

    return credentials


def _resolve_lapi_credentials() -> dict[str, str]:
    """Resolve effective LAPI credentials from env vars or CrowdSec defaults."""
    file_credentials = _read_lapi_credentials_file()
    return {
        # An explicit env var wins; otherwise CrowdSec's own credentials file
        # decides. The built-in default is last so it can never mask a file that
        # points the watcher at a different LAPI host.
        "url": (CROWDSEC_LAPI_URL or file_credentials.get("url") or "http://127.0.0.1:8080"),
        "machine_id": CROWDSEC_LAPI_MACHINE_ID or file_credentials.get("login", ""),
        "password": CROWDSEC_LAPI_PASSWORD or file_credentials.get("password", ""),
    }


def _get_lapi_base_url() -> str:
    """Return the normalized Local API base URL including /v1."""
    base_url = _resolve_lapi_credentials()["url"].rstrip("/")
    if not base_url:
        raise CrowdSecFetchError("CROWDSEC_LAPI_URL is empty")
    if base_url.endswith("/v1"):
        return base_url
    return f"{base_url}/v1"


def _build_lapi_client() -> httpx.Client:
    """Create a configured LAPI HTTP client."""
    return httpx.Client(
        base_url=_get_lapi_base_url(),
        timeout=CROWDSEC_LAPI_TIMEOUT,
        verify=CROWDSEC_LAPI_VALIDATE_CERTIFICATE,
        headers={"Accept": "application/json"},
    )


def _format_lapi_auth_hint() -> str:
    """Return a short operator hint for broken or missing LAPI credentials."""
    return (
        "Verify that `CROWDSEC_LAPI_MACHINE_ID` and `CROWDSEC_LAPI_PASSWORD` "
        "match the CrowdSec watcher credentials. " + LAPI_CREDENTIALS_HINT
    )


def _auth_rejected(prefix: str, status_code: int) -> CrowdSecFetchError:
    """Build the error for a 401/403 answer, with the credentials hint."""
    label = "Unauthorized" if status_code == 401 else "Forbidden"
    return CrowdSecFetchError(f"{prefix} with HTTP {status_code} ({label}).", hint=_format_lapi_auth_hint())


def _request_with_retry(  # noqa: RET503 the loop always returns or raises
    client: httpx.Client, method: str, url: str, **kwargs: Any
) -> httpx.Response:
    """Issue a LAPI request, retrying transient transport/5xx failures.

    A single short LAPI hiccup must not discard the whole unattended run. Only
    transport errors and retryable status codes are repeated; 4xx (except 429)
    is a permanent answer and is raised immediately.
    """
    delay = 1.0
    for attempt in range(1, _LAPI_MAX_ATTEMPTS + 1):
        started = time.monotonic()
        try:
            response = client.request(method, url, **kwargs)
            response.raise_for_status()
            logger.debug(
                "LAPI %s %s -> %d in %.2fs, %d bytes",
                method,
                url,
                response.status_code,
                time.monotonic() - started,
                len(response.content),
            )
            return response
        except httpx.HTTPStatusError as e:
            if e.response.status_code not in _RETRY_STATUS_CODES:
                raise
            error: httpx.HTTPError = e
        except httpx.TransportError as e:
            error = e

        if attempt == _LAPI_MAX_ATTEMPTS:
            raise error

        logger.warning(
            "LAPI request %s %s failed (attempt %d/%d), retrying in %.1fs: %s",
            method,
            url,
            attempt,
            _LAPI_MAX_ATTEMPTS,
            delay,
            error,
        )
        time.sleep(delay)
        delay *= 2


def _get_lapi_token(client: httpx.Client) -> str:
    """Authenticate against the LAPI watchers endpoint and return a JWT."""
    credentials = _resolve_lapi_credentials()
    machine_id = credentials["machine_id"]
    password = credentials["password"]
    if not machine_id or not password:
        raise CrowdSecFetchError(
            "CrowdSec LAPI credentials are missing or incomplete. Set "
            "CROWDSEC_LAPI_MACHINE_ID/CROWDSEC_LAPI_PASSWORD or provide "
            f"{CROWDSEC_LAPI_CREDENTIALS_PATH}.",
            hint=_format_lapi_auth_hint(),
        )
    try:
        response = _request_with_retry(
            client,
            "POST",
            "/watchers/login",
            json={"machine_id": machine_id, "password": password, "scenarios": []},
        )
    except httpx.HTTPStatusError as e:
        # Log the status only — the login response body of this sensitive
        # endpoint can echo back credential-related diagnostics.
        status_code = e.response.status_code
        if status_code in (401, 403):
            raise _auth_rejected("LAPI authentication failed", status_code) from e
        raise CrowdSecFetchError(f"LAPI authentication failed with HTTP {status_code}") from e
    except httpx.HTTPError as e:
        raise CrowdSecFetchError(f"LAPI authentication failed: {e}") from e

    try:
        payload = response.json()
    except ValueError as e:
        raise CrowdSecFetchError("LAPI authentication returned invalid JSON") from e
    if not isinstance(payload, dict):
        raise CrowdSecFetchError("Unexpected LAPI authentication format (expected an object)")
    token = payload.get("token")
    if not token:
        raise CrowdSecFetchError("LAPI authentication response did not contain a token")
    return token


def _fetch_alerts(client: httpx.Client, token: str, params: dict[str, str]) -> list[dict[str, Any]]:
    """GET /v1/alerts and validate the payload shape."""
    try:
        response = _request_with_retry(
            client,
            "GET",
            "/alerts",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code
        if status_code in (401, 403):
            raise _auth_rejected("LAPI alerts fetch failed", status_code) from e
        raise CrowdSecFetchError(f"LAPI alerts fetch failed with HTTP {status_code}: {e.response.text[:300]}") from e
    except httpx.HTTPError as e:
        raise CrowdSecFetchError(f"LAPI alerts fetch failed: {e}") from e

    try:
        alerts = response.json()
    except ValueError as e:
        raise CrowdSecFetchError("LAPI alerts response was not valid JSON") from e
    # An empty result set is returned as null, not [].
    if alerts is None:
        return []
    if not isinstance(alerts, list):
        raise CrowdSecFetchError("Unexpected LAPI alerts format (expected a list)")
    # Every consumer calls alert.get(...); a non-object entry would raise
    # AttributeError instead of the handled CrowdSecFetchError.
    if not all(isinstance(alert, dict) for alert in alerts):
        raise CrowdSecFetchError("Unexpected LAPI alerts format (list contains non-object entries)")
    return alerts


def _fetch_all_alerts(client: httpx.Client, token: str, params: dict[str, str]) -> list[dict[str, Any]]:
    """GET /v1/alerts, raising the limit until the result set is provably complete.

    The LAPI has no client-side offset and returns at most `limit` alerts, so a
    response shorter than the limit proves completeness. A full response is
    re-requested with a tenfold limit up to the ceiling. A response that still
    fills the limit there cannot be proven complete.

    Raises:
        CrowdSecIncompleteFetchError: the ceiling response is full; carries it.
    """
    limit = CROWDSEC_ALERT_LIMIT
    ceiling = max(MAX_ALERT_FETCH_LIMIT, limit)
    while True:
        alerts = _fetch_alerts(client, token, {**params, "limit": str(limit)})
        if len(alerts) < limit:
            return alerts
        if limit >= ceiling:
            message = (
                f"LAPI returned {len(alerts)} alerts, the maximum fetch limit; "
                "further alerts may be missing from this run"
            )
            print_warning(message)
            raise CrowdSecIncompleteFetchError(message, alerts)
        limit = min(limit * _ALERT_FETCH_LIMIT_FACTOR, ceiling)
        print_info(f"LAPI response filled the fetch limit; retrying with limit {limit}")


def get_crowdsec_decisions() -> list[dict[str, Any]]:
    """Return alerts that currently carry an active decision.

    These are the alert objects behind the active decisions, carrying `id`,
    `source`, `events_count`, `scenario`, `message` and `start_at`, which
    `main.py` maps to points.

    Raises:
        CrowdSecIncompleteFetchError: the fetch ceiling was reached; carries the
            alerts retrieved so far.
        CrowdSecFetchError: authentication, transport or payload failure. An
            empty list is a successful run with nothing to export.
    """
    print_info("Retrieving alerts with active decisions from CrowdSec LAPI")
    started = time.monotonic()
    params = {"has_active_decision": "true"}
    with _build_lapi_client() as client:
        token = _get_lapi_token(client)
        alerts = _fetch_all_alerts(client, token, params)
    print_success(f"Retrieved {len(alerts)} alerts from CrowdSec LAPI in {time.monotonic() - started:.1f}s")
    return alerts


def _alert_has_events(alert: dict[str, Any]) -> bool:
    """True when an alert already carries complete event detail."""
    events = alert.get("events")
    expected = alert.get("events_count")
    if isinstance(expected, int) and not isinstance(expected, bool) and expected == 0:
        return events is None or _has_complete_event_details(alert, expected)
    return isinstance(events, list) and bool(events) and _has_complete_event_details(alert, expected)


def _has_complete_event_details(alert: dict[str, Any], expected: Any) -> bool:
    events = alert.get("events")
    if not isinstance(events, list) or any(not isinstance(event, dict) for event in events):
        return False
    if expected is None:
        return True
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
        return False
    # CrowdSec caps the stored events per alert (scenario cache_size), so fewer
    # events than events_count is normal; only a missing list is incomplete.
    return len(events) >= 1 or expected == 0


def _fetch_alert_detail(client: httpx.Client, token: str, alert_id: Any, expected_events: Any) -> dict[str, Any] | None:
    """Fetch one alert's full detail (events with their meta blocks).

    Returns None on any error so the caller can keep the summary alert and
    report the run as incomplete instead of losing it.
    """
    try:
        response = _request_with_retry(
            client, "GET", f"/alerts/{alert_id}", headers={"Authorization": f"Bearer {token}"}
        )
        detail = response.json()
    except (httpx.HTTPError, ValueError) as e:
        print_warning(f"Failed to fetch detail for alert {alert_id}: {e}")
        return None
    if isinstance(detail, list) and detail and isinstance(detail[0], dict):
        detail = detail[0]
    if isinstance(detail, dict) and _has_complete_event_details(detail, expected_events):
        return detail
    print_warning(f"Event detail for alert {alert_id} was missing or incomplete")
    return None


def get_crowdsec_alerts(since: str) -> list[dict[str, Any]]:
    """Return alerts from the given window, including their events.

    Whether GET /v1/alerts already embeds `events[]` depends on the CrowdSec
    version, so alerts that arrive without events are enriched individually via
    GET /v1/alerts/{id}. That fallback is what the per-event export needs: the
    request details (`http_path`, `target_user`, ...) live in the event meta.

    Args:
        since: Duration understood by the LAPI, e.g. "30m"

    Raises:
        CrowdSecIncompleteFetchError: the fetch ceiling was reached or some event
            details could not be fetched; carries all alerts retrieved so far.
        CrowdSecFetchError: authentication, transport or payload failure.
    """
    print_info(f"Retrieving alerts with events from CrowdSec LAPI (since {since})")
    started = time.monotonic()
    params = {"since": since}
    with _build_lapi_client() as client:
        token = _get_lapi_token(client)
        problems: list[str] = []
        try:
            alerts = _fetch_all_alerts(client, token, params)
        except CrowdSecIncompleteFetchError as e:
            alerts = e.alerts
            problems.append(str(e))

        enriched: list[dict[str, Any]] = []
        fetched = 0
        failed = 0
        for alert in alerts:
            # A malformed id is kept as is; build_event_lines skips it with a warning.
            alert_id = parse_record_id(alert.get("id"))
            if alert_id is not None and not _alert_has_events(alert):
                detail = _fetch_alert_detail(client, token, alert_id, alert.get("events_count"))
                fetched += 1
                if detail is None:
                    failed += 1
                enriched.append(detail if detail is not None else alert)
            else:
                enriched.append(alert)

    if fetched:
        print_info(f"Fetched event detail for {fetched} of {len(alerts)} alerts")
    if failed:
        problems.append(f"Event detail missing for {failed} of {len(alerts)} alerts")
    if problems:
        raise CrowdSecIncompleteFetchError("; ".join(problems), enriched)
    print_success(f"Retrieved {len(enriched)} alerts from CrowdSec LAPI in {time.monotonic() - started:.1f}s")
    return enriched


def get_abuse_contact(ip_address: str) -> str:  # noqa: ARG001 placeholder lookup, signature kept for the real one
    """Return a placeholder abuse contact; to be replaced by a real RDAP/WHOIS lookup."""
    return "abuse@example.com"
