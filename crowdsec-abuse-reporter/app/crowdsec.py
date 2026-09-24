#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/crowdsec.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
CrowdSec integration module for fetching alerts and decisions.

This module handles:
- Local API (LAPI) authentication and fetches
- Decision derivation from active alerts
- Context extraction and merging
- Node IP detection

Note on logging: This module uses Python's logging framework internally
for detailed debug/error traces. User-facing output uses print_* functions
from app.logger. This separation is intentional - API/debug traces vs.
user-facing logs.
"""

import ipaddress
import json
import logging
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import httpx

from .config import (
    CROWDSEC_DETAIL_LIMIT,
    CROWDSEC_FETCH_ALERT_DETAILS,
    CROWDSEC_LAPI_CREDENTIALS_PATH,
    CROWDSEC_LAPI_MACHINE_ID,
    CROWDSEC_LAPI_PASSWORD,
    CROWDSEC_LAPI_TIMEOUT,
    CROWDSEC_LAPI_URL,
    CROWDSEC_LAPI_VERIFY_TLS,
    PUBLIC_IP_DETECTION,
    PUBLIC_IP_TIMEOUT,
)

logger = logging.getLogger(__name__)


class CrowdSecFetchError(Exception):
    """Raised when decisions cannot be fetched or parsed from CrowdSec.

    Distinguishes a real failure (command error, invalid JSON) from the valid
    case of CrowdSec simply having no decisions, so callers do not mistake a
    broken fetch for "nothing to report".
    """

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.hint = hint

GOOGLE_DNS_IP = "8.8.8.8"
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30
IP_DETECTION_TIMEOUT = 5
DEFAULT_ALERT_FETCH_LIMIT = 10_000

# External services that echo back the caller's routable public IP as plain
# text. Tried in order; the first valid public IP wins. Multiple providers add
# resilience if one is down or rate-limited.
PUBLIC_IP_SERVICES = (
    "https://checkip.amazonaws.com/",
    "https://api.ipify.org",
    "https://icanhazip.com",
)

LAPI_CREDENTIALS_HINT = (
    "Use `docker exec -it <your crowdsec container name> "
    "cat /etc/crowdsec/local_api_credentials.yaml` to inspect the generated "
    "credentials, then copy `login` to `CROWDSEC_LAPI_MACHINE_ID` and "
    "`password` to `CROWDSEC_LAPI_PASSWORD`."
)


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
        raise CrowdSecFetchError(
            f"Failed to read LAPI credentials file {path}: {e}"
        ) from e

    return credentials


def _resolve_lapi_credentials() -> dict[str, str]:
    """Resolve effective LAPI credentials from env vars or CrowdSec defaults."""
    file_credentials = _read_lapi_credentials_file()
    return {
        # An explicit env var wins; otherwise CrowdSec's own credentials file
        # decides. The built-in default is last so it can never mask a file that
        # points the watcher at a different LAPI host.
        "url": (
            CROWDSEC_LAPI_URL
            or file_credentials.get("url")
            or "http://127.0.0.1:8080"
        ),
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
        verify=CROWDSEC_LAPI_VERIFY_TLS,
        headers={"Accept": "application/json"},
    )


def _format_lapi_auth_hint() -> str:
    """Return a short operator hint for broken or missing LAPI credentials."""
    return (
        "Verify that `CROWDSEC_LAPI_MACHINE_ID` and `CROWDSEC_LAPI_PASSWORD` "
        "match the CrowdSec watcher credentials. "
        + LAPI_CREDENTIALS_HINT
    )


_RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_LAPI_MAX_ATTEMPTS = 3


def _request_with_retry(
    client: httpx.Client, method: str, url: str, **kwargs: Any
) -> httpx.Response:
    """Issue a LAPI request, retrying transient transport/5xx failures.

    A single short LAPI hiccup must not discard the whole unattended run. Only
    transport errors and retryable status codes are repeated; 4xx (except 429)
    is a permanent answer and is raised immediately.
    """
    delay = 1.0
    for attempt in range(1, _LAPI_MAX_ATTEMPTS + 1):
        try:
            response = client.request(method, url, **kwargs)
            response.raise_for_status()
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
            json={
                "machine_id": machine_id,
                "password": password,
                "scenarios": [],
            },
        )
    except httpx.HTTPStatusError as e:
        # Log the status only — the login response body can echo back
        # credential-related or diagnostic data from this sensitive endpoint.
        status_code = e.response.status_code
        if status_code in (401, 403):
            status_label = "Unauthorized" if status_code == 401 else "Forbidden"
            raise CrowdSecFetchError(
                f"LAPI authentication failed with HTTP {status_code} "
                f"({status_label}).",
                hint=_format_lapi_auth_hint(),
            ) from e
        raise CrowdSecFetchError(
            f"LAPI authentication failed with HTTP {status_code}"
        ) from e
    except httpx.HTTPError as e:
        raise CrowdSecFetchError(f"LAPI authentication failed: {e}") from e

    try:
        payload = response.json()
    except ValueError as e:
        raise CrowdSecFetchError("LAPI authentication returned invalid JSON") from e

    # A syntactically valid but unexpected payload (e.g. a JSON array) would
    # otherwise raise AttributeError and abort the unattended run outside the
    # CrowdSecFetchError path the caller handles.
    if not isinstance(payload, dict):
        raise CrowdSecFetchError(
            "Unexpected LAPI authentication format (expected an object)"
        )

    token = payload.get("token")
    if not token:
        raise CrowdSecFetchError("LAPI authentication response did not contain a token")
    return token


def _alert_has_events(alert: dict[str, Any]) -> bool:
    """True when an alert already carries event detail (no need to re-fetch)."""
    events = alert.get("events")
    return isinstance(events, list) and len(events) > 0


def _fetch_lapi_alert_detail(
    client: httpx.Client, token: str, alert_id: Any
) -> dict[str, Any] | None:
    """Fetch a single alert's full detail (events + enriched source).

    Returns None on any error so the caller can fall back to the summary alert
    without aborting the whole run.
    """
    try:
        response = client.get(
            f"/alerts/{alert_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        detail = response.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.warning(f"Failed to fetch detail for alert {alert_id}: {e}")
        return None

    # The detail endpoint returns a single alert object.
    if isinstance(detail, dict):
        return detail
    if isinstance(detail, list) and detail and isinstance(detail[0], dict):
        return detail[0]
    return None


def _fetch_lapi_alerts() -> list[dict[str, Any]]:
    """Fetch active alerts from CrowdSec Local API.

    The list endpoint returns summary alerts only; when enabled, each alert is
    enriched with its full detail (events, usernames, attack patterns, AS/country)
    via GET /v1/alerts/{id}.
    """
    params = {
        "has_active_decision": "true",
        "limit": str(DEFAULT_ALERT_FETCH_LIMIT),
    }

    with _build_lapi_client() as client:
        token = _get_lapi_token(client)
        try:
            response = _request_with_retry(
                client,
                "GET",
                "/alerts",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                status_code = e.response.status_code
                status_label = "Unauthorized" if status_code == 401 else "Forbidden"
                raise CrowdSecFetchError(
                    f"LAPI alerts fetch failed with HTTP {status_code} "
                    f"({status_label}).",
                    hint=_format_lapi_auth_hint(),
                ) from e
            raise CrowdSecFetchError(
                f"LAPI alerts fetch failed with HTTP {e.response.status_code}: "
                f"{e.response.text[:300]}"
            ) from e
        except httpx.HTTPError as e:
            raise CrowdSecFetchError(f"LAPI alerts fetch failed: {e}") from e

        try:
            alerts = response.json()
        except ValueError as e:
            raise CrowdSecFetchError("LAPI alerts response was not valid JSON") from e

        if alerts is None:
            return []
        if not isinstance(alerts, list):
            raise CrowdSecFetchError("Unexpected LAPI alerts format (expected a list)")
        # Every consumer below calls alert.get(...); a non-object entry would
        # raise AttributeError instead of the handled CrowdSecFetchError.
        if not all(isinstance(alert, dict) for alert in alerts):
            raise CrowdSecFetchError(
                "Unexpected LAPI alerts format (list contains non-object entries)"
            )

        if not CROWDSEC_FETCH_ALERT_DETAILS:
            return alerts

        # Enrich summary alerts with full detail (bounded by CROWDSEC_DETAIL_LIMIT)
        enriched: list[dict[str, Any]] = []
        fetched = 0
        for alert in alerts:
            alert_id = alert.get("id")
            needs_detail = (
                alert_id is not None
                and fetched < CROWDSEC_DETAIL_LIMIT
                and not _alert_has_events(alert)
            )
            if needs_detail:
                detail = _fetch_lapi_alert_detail(client, token, alert_id)
                fetched += 1
                enriched.append(detail if detail is not None else alert)
            else:
                enriched.append(alert)

        if fetched:
            logger.debug(f"Fetched full detail for {fetched} alert(s)")
        return enriched


def _is_public_ip(value: str) -> bool:
    """True if value parses as a globally routable IP (IPv4 or IPv6)."""
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


def _normalize_ip(value: Any) -> str | None:
    """Return a canonical single-host IP from a decision value, else None.

    Decision values are untrusted external input and may be a bare IP, a CIDR
    range ("1.2.3.0/24"), or malformed. Only a single host is a valid report
    subject: collapsing a range to its network address would attribute the whole
    range's activity to one address, which is usually a different party than the
    one actually banned. Ranges therefore yield None and are skipped upstream.
    Single-host prefixes (/32, /128) are accepted — they denote one address.
    """
    if not value:
        return None
    try:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    if network.num_addresses != 1:
        return None
    return str(network.network_address)


def _get_public_ip_from_http() -> str:
    """Detect the host's routable public IP via external echo services.

    Tries each service in PUBLIC_IP_SERVICES with a short per-request timeout
    so a slow or unreachable provider cannot stall startup. Returns the first
    response that is a valid public IP, or 'unknown' if all fail. This works
    correctly inside Docker/behind NAT, where local interface detection only
    sees a private bridge IP.
    """
    headers = {"User-Agent": "crowdsec-abuse-reporter/1.0"}
    for url in PUBLIC_IP_SERVICES:
        try:
            resp = httpx.get(
                url,
                timeout=PUBLIC_IP_TIMEOUT,
                headers=headers,
                follow_redirects=True,
            )
            resp.raise_for_status()
            candidate = resp.text.strip()
            if _is_public_ip(candidate):
                logger.info(f"Detected public IP via {url}: {candidate}")
                return candidate
            logger.debug(f"{url} returned non-public value: {candidate!r}")
        except Exception as e:
            logger.debug(f"Public IP service {url} failed: {e}")

    return "unknown"


def get_node_ip() -> str:
    """
    Detect the reporting identity, preferring the host's routable public IP.

    Strategy:
      1. Query external HTTP services for the real public IP. This is the
         address that belongs in an abuse report and works behind NAT/Docker.
      2. Fall back to local interface detection only if public detection is
         disabled (PUBLIC_IP_DETECTION=false) or every service is unreachable.
         Note: the fallback may return a private container/bridge IP.

    Returns:
        Detected IP address or 'unknown' if all methods fail
    """
    if PUBLIC_IP_DETECTION:
        public_ip = _get_public_ip_from_http()
        if public_ip != "unknown":
            return public_ip
        logger.warning(
            "Public IP detection failed; falling back to local interface IP "
            "(may be a private address)"
        )

    detection_methods = [
        _get_ip_from_ipv4_global,
        _get_ip_from_ipv6_global,
        _get_ip_from_hostname,
        _get_ip_from_route,
    ]

    # Execute all detection methods in parallel
    with ThreadPoolExecutor(max_workers=len(detection_methods)) as executor:
        future_to_method = {
            executor.submit(method): method.__name__ for method in detection_methods
        }

        for future in as_completed(future_to_method):
            try:
                ip_address = future.result()
                if ip_address and ip_address != "unknown":
                    method_name = future_to_method[future]
                    logger.info(f"Detected node IP via {method_name}: {ip_address}")

                    # Cancel remaining futures since we found a valid IP.
                    # Note: This cancels pending futures but cannot abort
                    # already-running subprocess commands. The timeouts in
                    # each detection method protect against hanging.
                    executor.shutdown(wait=False, cancel_futures=True)
                    return ip_address

            except Exception as e:
                method_name = future_to_method[future]
                logger.debug(f"IP detection method {method_name} failed: {e}")

    logger.warning("All IP detection methods failed, using 'unknown'")
    return "unknown"


def _get_ip_from_ipv4_global() -> str:
    """Extract IPv4 address from global scope interfaces."""
    success, output = _run_command(
        ["ip", "-o", "-4", "addr", "show", "scope", "global"],
        max_retries=1,
        timeout=IP_DETECTION_TIMEOUT,
    )

    if success and output:
        ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
        return ip_match.group(1) if ip_match else "unknown"
    return "unknown"


def _get_ip_from_ipv6_global() -> str:
    """
    Extract IPv6 address from global scope interfaces.

    Note: This is a best-effort detection. The regex pattern captures
    the main address portion but may not handle all edge cases like
    zone identifiers (%eth0 suffixes). For production use with complex
    IPv6 setups, consider more robust parsing.
    """
    success, output = _run_command(
        ["ip", "-o", "-6", "addr", "show", "scope", "global"],
        max_retries=1,
        timeout=IP_DETECTION_TIMEOUT,
    )

    if success and output:
        # Best effort: captures hex:colon format, ignores zone IDs
        ip_match = re.search(r"inet6 ([0-9a-f:]+)", output)
        return ip_match.group(1) if ip_match else "unknown"
    return "unknown"


def _get_ip_from_hostname() -> str:
    """Extract IP address from hostname command output."""
    success, output = _run_command(
        ["hostname", "-I"], max_retries=1, timeout=IP_DETECTION_TIMEOUT
    )

    if success and output:
        ips = output.strip().split()
        return ips[0] if ips else "unknown"
    return "unknown"


def _get_ip_from_route() -> str:
    """Extract source IP from route to external destination."""
    success, output = _run_command(
        ["ip", "route", "get", GOOGLE_DNS_IP],
        max_retries=1,
        timeout=IP_DETECTION_TIMEOUT,
    )

    if success and output:
        ip_match = re.search(r"src (\d+\.\d+\.\d+\.\d+)", output)
        return ip_match.group(1) if ip_match else "unknown"
    return "unknown"


def _run_command(
    cmd: list[str], max_retries: int = MAX_RETRIES, timeout: int = DEFAULT_TIMEOUT
) -> tuple[bool, str | None]:
    """
    Execute system command with comprehensive error handling and retry logic.

    Args:
        cmd: Command and arguments as list
        max_retries: Maximum number of retry attempts
        timeout: Command execution timeout in seconds

    Returns:
        Tuple of (success_status, command_output)
    """
    last_error = None

    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout,
                encoding="utf-8",
                errors="ignore",  # Handle encoding issues gracefully
            )
            return True, result.stdout

        except FileNotFoundError:
            error_msg = f"Command not found: {cmd[0]}"
            logger.error(error_msg)
            return False, error_msg

        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {timeout}s: {' '.join(cmd)}"
            if attempt < max_retries - 1:
                logger.warning(f"{error_msg} (attempt {attempt + 1}/{max_retries})")
            else:
                logger.error(
                    f"Command failed after {max_retries} attempts due to timeout"
                )
            last_error = error_msg

            if attempt < max_retries - 1:
                retry_delay = 2 ** (attempt + 1)
                logger.debug(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                return False, last_error

        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed with exit code {e.returncode}: {' '.join(cmd)}"

            # Use warning level for retryable errors, error for final failure
            if attempt < max_retries - 1:
                logger.warning(f"{error_msg} (attempt {attempt + 1}/{max_retries})")
            else:
                logger.error(error_msg)

            if e.stderr:
                error_level = (
                    logger.warning if attempt < max_retries - 1 else logger.error
                )
                error_level(f"stderr: {e.stderr.strip()}")

            if e.stdout:
                logger.debug(f"stdout: {e.stdout.strip()}")

            last_error = error_msg

            # Don't retry for command not found or permission errors
            if e.returncode in [127, 126]:
                return False, error_msg

            if attempt < max_retries - 1:
                retry_delay = 2 ** (attempt + 1)
                logger.debug(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                return False, last_error

        except UnicodeDecodeError as e:
            error_msg = f"Command output encoding error: {e}"
            logger.error(error_msg)
            return False, error_msg

    return False, last_error or f"All {max_retries} attempts failed"


def check_lapi_health() -> bool:
    """Lightweight LAPI connectivity check (login only, no data fetch).

    Returns True when the LAPI is reachable and credentials are accepted.
    Used by the heartbeat loop between main processing runs.

    The cause is logged so an outage, bad credentials, TLS misconfig, or a code
    defect can be told apart in production instead of all collapsing to False.
    """
    try:
        with _build_lapi_client() as client:
            _get_lapi_token(client)
        return True
    except CrowdSecFetchError as e:
        logger.warning("LAPI health check failed: %s", e)
        return False
    except Exception:
        logger.exception("Unexpected LAPI health check failure")
        return False


def get_crowdsec_alerts() -> list[dict[str, Any]]:
    """
    Fetch active CrowdSec alerts through the Local API.

    Returns:
        List of alert dictionaries
    """
    alerts = _fetch_lapi_alerts()
    logger.info(f"Successfully retrieved {len(alerts)} active alerts from CrowdSec LAPI")
    return alerts


def _parse_meta_data(meta_list: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Parse metadata from key-value pairs to structured dictionary.

    Args:
        meta_list: List of metadata dictionaries

    Returns:
        Parsed metadata dictionary
    """
    result = {}
    if not isinstance(meta_list, list):
        return result

    for meta_item in meta_list:
        if isinstance(meta_item, dict) and "key" in meta_item and "value" in meta_item:
            key = meta_item["key"]
            value = meta_item["value"]

            # Attempt JSON parsing for structured data
            if isinstance(value, str):
                value = value.strip()
                if value.startswith(("[", "{")) and value.endswith(("]", "}")):
                    try:
                        parsed_value = json.loads(value)
                        result[key] = parsed_value
                        continue
                    except json.JSONDecodeError:
                        pass

            result[key] = value

    return result


def _extract_context_from_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Extract contextual information from alert events.

    Args:
        alert: Alert dictionary

    Returns:
        Context data dictionary
    """
    context_data = {}

    if "events" in alert and isinstance(alert["events"], list):
        for event in alert["events"]:
            # Parse metadata
            if "meta" in event and isinstance(event["meta"], list):
                meta_dict = _parse_meta_data(event["meta"])
                if meta_dict:
                    context_data.update(meta_dict)

            # Include extra data
            if "extra" in event and isinstance(event["extra"], dict) and event["extra"]:
                context_data.update(event["extra"])

    return context_data


def _source_ip_from_meta(alert: dict[str, Any]) -> str | None:
    """Look up a "source_ip" key in top-level meta, then in each event's meta.

    Shared by `_extract_source_ip_from_alert_payload` here and `get_alert_ip`
    in `main.py`, which both fall back to this same walk after their own
    (differing) top-level checks.
    """
    meta = alert.get("meta", [])
    if isinstance(meta, list):
        for item in meta:
            if isinstance(item, dict) and item.get("key") == "source_ip" and item.get("value"):
                return str(item["value"])

    events = alert.get("events", [])
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            event_meta = event.get("meta", [])
            if not isinstance(event_meta, list):
                continue
            for item in event_meta:
                if isinstance(item, dict) and item.get("key") == "source_ip" and item.get("value"):
                    return str(item["value"])

    return None


def _extract_source_ip_from_alert_payload(alert: dict[str, Any]) -> str | None:
    """Extract the best-effort source IP from a raw alert payload."""
    source = alert.get("source", {})
    if isinstance(source, dict):
        ip = source.get("ip")
        if ip:
            return str(ip)

        value = source.get("value")
        scope = str(source.get("scope", "")).lower()
        if value and scope == "ip":
            return str(value)

    context = alert.get("context", {})
    if isinstance(context, dict):
        context_ip = context.get("source_ip")
        if context_ip:
            return str(context_ip)

    return _source_ip_from_meta(alert)


def get_crowdsec_decisions() -> list[dict[str, Any]]:
    """
    Fetch reportable CrowdSec decisions by reading alerts with active decisions
    from the Local API and deriving one enriched decision per alert.

    Returns:
        List of decision dictionaries (one per alert with an active decision)
    """
    alerts = get_crowdsec_alerts()
    if not alerts:
        logger.info("CrowdSec returned no alerts with active decisions")
        return []

    decisions: list[dict[str, Any]] = []
    capi_skipped = 0
    for alert in alerts:
        active_decisions = [
            decision
            for decision in alert.get("decisions", [])
            if isinstance(decision, dict)
        ]
        if not active_decisions:
            continue

        source = alert.get("source", {})
        context = _extract_context_from_alert(alert)
        source_ip = _extract_source_ip_from_alert_payload(alert)
        alert_id = alert.get("id")

        # One report per abusive IP: a single alert can bundle several bans
        # (e.g. CAPI community-blocklist syncs carry hundreds of IPs), so we
        # emit a separate reportable decision per ban instead of grouping the
        # whole list into one mail. Bans pulled from the community (origin CAPI)
        # are not our own observations, so we never report them upstream.
        for ban in active_decisions:
            if str(ban.get("origin", "")).strip().upper() == "CAPI":
                capi_skipped += 1
                continue

            decision = ban.copy()
            # The report body shows only this ban / this IP.
            decision["decisions"] = [ban]
            decision.setdefault("scenario", alert.get("scenario", "unknown"))
            decision.setdefault("origin", "crowdsec")

            # Anchor the source on THIS ban's IP. Using the alert-level source
            # for every ban would mislabel each report with the alert's
            # representative IP in a multi-IP alert.
            ban_source = source.copy() if isinstance(source, dict) else {}
            ban_value = ban.get("value")
            ban_ip = _normalize_ip(ban_value)
            if ban_ip:
                decision.setdefault("value", ban_value)
                decision.setdefault("scope", ban.get("scope") or "Ip")
                ban_source["value"] = ban_value
                ban_source["ip"] = ban_ip
                ban_source.setdefault("scope", ban.get("scope") or "Ip")
            else:
                # No single-host ban value (malformed, or a Range like
                # 1.2.3.0/24) — fall back to the alert-level source IP, which is
                # the address actually observed, but only if it validates. The
                # ban's own CIDR must not stay on the decision: downstream
                # consumers would collapse it back to a single address.
                decision.pop("value", None)
                decision.pop("scope", None)
                ban_source.pop("value", None)
                normalized_source_ip = _normalize_ip(source_ip)
                if normalized_source_ip:
                    if not ban_source.get("ip"):
                        ban_source["ip"] = normalized_source_ip
                    if not ban_source.get("value"):
                        ban_source["value"] = normalized_source_ip
                    if not ban_source.get("scope"):
                        ban_source["scope"] = "Ip"
            decision["source"] = ban_source

            # Keep the originating alert id for display/reference. Idempotency
            # is per (alert id, IP) in the DB, so exploded reports from the same
            # alert no longer collide despite sharing this id.
            if alert_id is not None:
                decision["alert_id"] = alert_id
                decision["alert_ids"] = [alert_id]

            if context:
                decision["context"] = context

            decision["message"] = alert.get("message", "")
            decision["events_count"] = alert.get("events_count", 0)
            decision["created_at"] = alert.get("created_at")
            decision["start_at"] = alert.get("start_at")
            decision["stop_at"] = alert.get("stop_at")
            decision["meta"] = alert.get("meta", [])
            decision["events"] = alert.get("events", [])

            decisions.append(decision)

    if capi_skipped:
        logger.info(f"Skipped {capi_skipped} CAPI (community) bans — not reported")

    logger.info(
        f"Derived {len(decisions)} reportable decisions from {len(alerts)} active alerts"
    )
    return decisions
