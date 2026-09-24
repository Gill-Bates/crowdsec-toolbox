#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/reportbody.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# reportbody.py - Enhanced email body and X-ARF report generation with context
import ipaddress
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

if TYPE_CHECKING:
    from app.geoip import GeoInfo

# Module-level logger
logger = logging.getLogger(__name__)

# Exact normalized keys (hyphens → underscores, lowercased).
_SENSITIVE_CONTEXT_EXACT: frozenset[str] = frozenset({
    "authorization",
    "cookie",
    "set_cookie",
    "x_api_key",
    "x_auth_token",
    "proxy_authorization",
    "password",
    "passwd",
    "secret",
    "token",
    "session",
    "csrf",
    "api_key",
})


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SENSITIVE_CONTEXT_EXACT:
        return True
    return (
        "password" in normalized
        or normalized.endswith(("_token", "_secret", "_key"))
    )


# Context keys whose value is a URL or request path. Their own name is harmless,
# so key-based redaction never fires, but the query string they carry routinely
# holds reset tokens, session ids and api keys from the logged request. The
# report goes to an external abuse desk, so those values are redacted in place.
_URI_CONTEXT_KEYS: frozenset[str] = frozenset({
    "uri",
    "url",
    "target_uri",
    "request_uri",
    "path",
    "http_path",
    "http_referer",
    "referer",
    "referrer",
})

_QUERY_CONTEXT_KEYS: frozenset[str] = frozenset({
    "args",
    "http_args",
    "query",
    "query_string",
})


def _redact_query(query: str) -> str:
    """Redact sensitive parameters inside a urlencoded query string."""
    if not query:
        return query
    pairs = parse_qsl(query, keep_blank_values=True)
    # Rebuild only when something is actually redacted: urlencode re-quotes
    # every value, which would needlessly rewrite benign paths in the evidence.
    if not any(_is_sensitive_key(key) for key, _ in pairs):
        return query
    return urlencode(
        [
            (key, "[REDACTED]" if _is_sensitive_key(key) else value)
            for key, value in pairs
        ]
    )


def _redact_uri(value: str) -> str:
    """Redact sensitive query parameters while keeping the URI readable."""
    parts = urlsplit(value)
    redacted_query = _redact_query(parts.query)
    if redacted_query == parts.query:
        return value
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, redacted_query, parts.fragment)
    )
MAX_FIELD_LENGTH = 2_000
MAX_LIST_ITEMS = 20
MAX_DICT_ITEMS = 50

# Width to which labels are padded so values line up in monospace clients,
# while staying readable in proportional-font clients (no dot-leaders).
_LABEL_WIDTH = 18


def _field(label: str, value: Any) -> str:
    """Render a 'Label: value' line with a padded label for tidy alignment."""
    field_name = f"{label}:"
    padding = " " * max(_LABEL_WIDTH - len(field_name), 1)
    return f"  {field_name}{padding}{value}"


def _section(title: str) -> str:
    """Render a section heading underlined with dashes."""
    return f"{title}\n{'-' * len(title)}"


def _is_present(value: Any) -> bool:
    """True when a value is worth showing (not empty / None / 'N/A')."""
    return value not in (None, "", "N/A") and str(value).strip().lower() not in (
        "n/a",
        "none",
    )


def _extract_report_ip(alert: dict[str, Any]) -> str:
    """Resolve the offending IP across the alert/decision shapes CrowdSec emits.

    The LAPI alert *list* often omits source.ip; the address then lives in the
    decision's top-level ``value`` (scope Ip) or in the decisions array.
    """
    source = alert.get("source", {})
    if isinstance(source, dict):
        ip = source.get("ip")
        if _is_present(ip):
            return str(ip)
        value = source.get("value")
        if _is_present(value) and str(source.get("scope", "")).lower() == "ip":
            return str(value)

    top_value = _single_host(alert.get("value"))
    if top_value:
        return top_value

    for decision in alert.get("decisions") or []:
        if not isinstance(decision, dict):
            continue
        decision_value = _single_host(decision.get("value"))
        if decision_value:
            return decision_value

    return "unknown"


def _single_host(value: Any) -> str | None:
    """Return the address when value denotes exactly one host, else None.

    A range (e.g. "1.2.3.0/24") must never be reduced to its network address
    here: this IP is what the outgoing report names as the offender, and the
    network address usually belongs to a different party than the banned host.
    """
    if not _is_present(value):
        return None
    try:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    return str(network.network_address) if network.num_addresses == 1 else None


def _dict_or_empty(value: Any) -> dict[str, Any]:
    """Return value if it is a dict, else an empty dict.

    CrowdSec can emit unexpected shapes for source/context fields; using this
    guard prevents AttributeError/TypeError downstream and keeps processing
    intact even when the alert data is malformed.
    """
    return value if isinstance(value, dict) else {}


def _decisions_for(alert: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the alert's decisions, falling back to the object itself when it
    is a single derived decision (carries type/scope/value at top level)."""
    decisions = alert.get("decisions")
    if isinstance(decisions, list):
        # Consumers treat every entry as a mapping. A single malformed element
        # from upstream would otherwise abort the whole report build, so drop
        # non-dict entries instead of propagating them.
        valid = [decision for decision in decisions if isinstance(decision, dict)]
        if valid:
            return valid
    if alert.get("type") or alert.get("scope") or alert.get("value"):
        return [alert]
    return []


def build_mail_body(alert: dict[str, Any], hostname: str) -> str:
    """
    Build comprehensive abuse report email body with proper formatting.

    Includes all relevant CrowdSec alert details, blocking reasons and context.

    Args:
        alert: CrowdSec alert dictionary
        hostname: Reporting host identifier

    Returns:
        Formatted email body as string
    """
    # Extract alert identification with fallback
    alert_id = _extract_alert_id(alert)
    source = _dict_or_empty(alert.get("source"))
    ip = _extract_report_ip(alert)
    scenario = _limit_value(alert.get("scenario", "unknown"))

    # Format timestamps for readability
    created_at = format_timestamp(alert.get("created_at"))
    start_at = format_timestamp(alert.get("start_at"))
    stop_at = format_timestamp(alert.get("stop_at"))

    # GeoIP enrichment (non-fatal: lookup returns None-filled dict on any error)
    try:
        from app.geoip import lookup as _geoip_lookup
        geo = _geoip_lookup(ip) if ip != "unknown" else None
    except Exception:
        geo = None

    # Extract detailed information sections
    blocking_reasons = extract_blocking_reasons(_decisions_for(alert))
    context_details = extract_context_details(_dict_or_empty(alert.get("context")), alert)
    network_info = extract_network_info(source, geo)

    message = str(_limit_value(alert.get("message", ""))).strip()
    events_count = alert.get("events_count", "N/A")

    lines: list[str] = []
    lines.append(f"ABUSE REPORT — {scenario} from {ip}")
    lines.append("")
    lines.append("Dear Abuse Team,")
    lines.append("")
    lines.append(
        "we detected abusive activity originating from an IP address in your "
        "network and kindly ask you to investigate. A machine-readable X-ARF "
        "report is attached for automated processing."
    )
    lines.append("")

    lines.append(_section("INCIDENT"))
    lines.append(_field("IP address", ip))
    lines.append(_field("Activity", scenario))
    if _is_present(events_count):
        lines.append(_field("Events", events_count))
    lines.append(_field("First seen", start_at))
    lines.append(_field("Last seen", stop_at))
    lines.append(_field("Reported at", created_at))
    lines.append(_field("Reported by", hostname))
    lines.append(_field("Alert ID", alert_id))
    lines.append("")

    lines.append(_section("BLOCKING DECISION"))
    lines.append(blocking_reasons)
    lines.append("")

    if network_info.strip():
        lines.append(_section("NETWORK"))
        lines.append(network_info)
        lines.append("")

    if context_details and context_details != "No specific context information available.":
        lines.append(_section("REQUEST CONTEXT"))
        lines.append(context_details)
        lines.append("")

    if message:
        lines.append(_section("NOTES"))
        lines.append(f"  {message}")
        lines.append("")

    lines.append(_section("WHAT WE ASK"))
    lines.append("  1. Investigate the originating system for compromise")
    lines.append("  2. Check for malware, botnet activity or misconfiguration")
    lines.append("  3. Review firewall and security logs for related activity")
    lines.append("  4. If compromised, clean and secure the system")
    lines.append("")

    lines.append(
        "This report was generated automatically by our abuse reporting system "
        "based on CrowdSec metrics (https://www.crowdsec.net/). Please include "
        "the IP address and timestamps above when replying."
    )

    return "\n".join(lines).strip()


def _extract_alert_id(alert: dict[str, Any]) -> str:
    """
    Extract alert identifier with comprehensive fallback strategy.

    Args:
        alert: Alert dictionary

    Returns:
        Alert ID as normalized string. Always returns a string type for
        consistency, even when the source ID is numeric. Returns 'unknown'
        if no valid identifier is found.
    """
    # Priority order for alert identification
    if alert.get("alert_id"):
        return str(alert["alert_id"])
    elif alert.get("alert_ids"):
        return str(alert["alert_ids"][0])
    elif alert.get("id"):
        return str(alert["id"])
    elif alert.get("uuid"):
        return str(alert["uuid"])
    else:
        return "unknown"


def normalize_timestamp(timestamp: object) -> str:
    """Normalize timestamp to ISO 8601 with UTC timezone, or return empty string."""
    if not isinstance(timestamp, str) or not timestamp.strip():
        return ""
    try:
        dt = datetime.fromisoformat(timestamp)
    except ValueError:
        return ""
    if dt.tzinfo is None:
        # CrowdSec emits RFC3339 with an offset; a naive value means an unusual
        # producer. UTC stays the best available reading — dropping the stamp
        # would push _xarf_timestamp() onto "now", which is further from the
        # truth than the event time itself — but it must not be silent.
        logger.warning(
            "Timestamp %r has no timezone; assuming UTC for the report", timestamp
        )
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


def _xarf_timestamp(alert: dict[str, Any]) -> str:
    """Return a valid UTC timestamp for the X-ARF report, falling back to now."""
    return (
        normalize_timestamp(alert.get("created_at"))
        or normalize_timestamp(alert.get("start_at"))
        or datetime.now(UTC).isoformat()
    )


# ---------------------------------------------------------------------------
# XARF v4 helpers
# ---------------------------------------------------------------------------

# Maps keyword fragments found in CrowdSec scenario names to
# (category, type) pairs defined by the XARF v4 specification.
# Evaluated in order; first match wins.
_XARF_SCENARIO_RULES: list[tuple] = [
    # keywords                                               category          type
    (["bruteforce", "brute-force", "brute_force", "-bf", "_bf", "login"],
                                                             "connection",     "login_attack"),
    (["scan", "crawl", "probe", "spider", "fingerprint"],   "connection",     "port_scan"),
    (["exploit", "injection", "sqli", "xss", "lfi", "rfi", "rce"],
                                                             "vulnerability",  "exploit_attempt"),
    (["ddos", "flood", "amplif"],                           "connection",     "ddos_attack"),
    (["spam", "phish"],                                     "messaging",      "spam"),
    (["malware", "botnet", "c2", "backdoor", "rootkit"],    "infrastructure", "malware"),
]

_XARF_PROTO_KEYWORDS: list[tuple] = [
    ("ssh",   "ssh"),
    ("rdp",   "rdp"),
    ("ftp",   "ftp"),
    ("smtp",  "smtp"),
    ("http",  "http"),
    ("imap",  "imap"),
    ("pop3",  "pop3"),
]


def _scenario_to_xarf(scenario: str) -> tuple:
    """Return (category, type, protocol | None) for a CrowdSec scenario name."""
    s = scenario.lower()

    protocol: str | None = None
    for keyword, proto in _XARF_PROTO_KEYWORDS:
        if keyword in s:
            protocol = proto
            break

    for keywords, category, xarf_type in _XARF_SCENARIO_RULES:
        if any(k in s for k in keywords):
            return category, xarf_type, protocol

    return "connection", "abusive_content", protocol


def _xarf_reporter(sender_email: str, sender_name: str) -> dict[str, str]:
    """Build an XARF v4 reporter/sender object."""
    org = sender_name.strip()
    if not org:
        # Derive display name from email domain when no explicit name is set.
        org = sender_email.split("@")[-1] if "@" in sender_email else sender_email
    return {"org": org, "contact": sender_email}


def build_xarf_report(alert: dict[str, Any], hostname: str) -> str:
    """Build an XARF v4-compliant abuse report from a CrowdSec alert.

    Schema: https://xarf.org/docs/specification/
    Mandatory fields: xarf_version, report_id (UUID v4), timestamp,
    reporter, sender, source_identifier, category, type.
    CrowdSec-specific data is carried in the evidence object.
    """
    from app.config import SENDER_NAME, SMTP_SENDER

    alert_id = _extract_alert_id(alert)
    source = _dict_or_empty(alert.get("source"))
    ip = _extract_report_ip(alert)
    scenario = _limit_value(alert.get("scenario", "unknown"))

    start_at = normalize_timestamp(alert.get("start_at") or "")
    stop_at = normalize_timestamp(alert.get("stop_at") or "")

    # GeoIP enrichment
    try:
        from app.geoip import lookup as _geoip_lookup
        _geo = _geoip_lookup(ip) if ip != "unknown" else None
    except Exception:
        _geo = None

    decisions = ensure_decisions_format(_decisions_for(alert))
    context_data = extract_context_for_json(_dict_or_empty(alert.get("context")), alert)

    category, xarf_type, protocol = _scenario_to_xarf(str(scenario))
    reporter = _xarf_reporter(SMTP_SENDER, SENDER_NAME)

    # GeoIP-enriched geo fields (fall back to CrowdSec source metadata)
    country   = (_geo or {}).get("country") or _limit_value(source.get("cn"))
    city      = (_geo or {}).get("city")
    asn_num   = (_geo or {}).get("asn") or _limit_value(source.get("as_number"))
    asn_name  = (_geo or {}).get("provider") or _limit_value(source.get("as_name"))

    xarf_payload: dict[str, Any] = {
        # --- XARF v4 mandatory fields ---
        "xarf_version":      "4.0.0",
        "report_id":         str(uuid.uuid4()),       # UUID v4
        "timestamp":         _xarf_timestamp(alert),
        "reporter":          reporter,
        "sender":            reporter,
        "source_identifier": ip,
        "category":          category,
        "type":              xarf_type,

        # --- XARF v4 recommended fields ---
        "description": f"Automated security alert: {scenario}",
        **({"protocol": protocol} if protocol else {}),

        # --- CrowdSec-specific evidence ---
        "evidence": {
            "crowdsec": {
                "alert_id":   alert_id,
                "scenario":   scenario,
                "events_count": alert.get("events_count", 0),
                "start_at":   start_at,
                "stop_at":    stop_at,
                "message":    _limit_value(alert.get("message", "")),
                "decisions":  decisions,
                "source": {
                    "ip":        ip,
                    "country":   country,
                    "city":      city,
                    "as_number": asn_num,
                    "as_name":   asn_name,
                    "range":     _limit_value(source.get("range")),
                },
                "context":    context_data,
                "simulated":  alert.get("simulated", False),
            }
        },

        "remarks": (
            "This report was generated automatically by our abuse reporting "
            "system based on CrowdSec metrics (https://www.crowdsec.net/) "
            "and formatted according to XARF v4 (https://xarf.org/)."
        ),
    }

    return json.dumps(xarf_payload, ensure_ascii=False, indent=2)


def ensure_decisions_format(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Normalize decisions list to ensure consistent format.

    The single caller (`build_xarf_report()`) always passes `_decisions_for()`'s
    output, which already contains only dicts. This function has no other
    caller and does not filter defensively; a non-dict entry would raise here.

    Args:
        decisions: List of decision dictionaries

    Returns:
        Normalized list of decision dictionaries
    """
    formatted_decisions = []
    for decision in decisions:
        formatted_decision = {
            "type": _limit_value(decision.get("type", "unknown")),
            "scope": _limit_value(decision.get("scope", "unknown")),
            "value": _limit_value(decision.get("value", "unknown")),
            "origin": _limit_value(decision.get("origin", "unknown")),
            "duration": _limit_value(decision.get("duration", "unknown")),
            "scenario": _limit_value(decision.get("scenario", "unknown")),
        }
        formatted_decisions.append(formatted_decision)

    return formatted_decisions


def extract_network_info(
    source: dict[str, Any],
    geo: "GeoInfo | None" = None,
) -> str:
    """Format network information for the email body.

    GeoIP data (from the local MaxMind DB) takes priority over CrowdSec
    metadata, which can be stale or absent. Falls back to source fields when
    GeoIP is unavailable.
    """
    network_lines: list[str] = []

    # Country — prefer GeoIP ISO code; fall back to CrowdSec cn field
    country = (geo or {}).get("country") or source.get("cn")
    if _is_present(country):
        network_lines.append(_field("Country", country))

    # City — only available via GeoIP (CrowdSec does not provide it)
    city = (geo or {}).get("city")
    if _is_present(city):
        network_lines.append(_field("City", city))

    # Provider / ASN — prefer GeoIP ASN DB; fall back to CrowdSec as_* fields
    geo_asn      = (geo or {}).get("asn")
    geo_provider = (geo or {}).get("provider")
    cs_asn       = source.get("as_number")
    cs_name      = source.get("as_name")

    if _is_present(geo_asn) or _is_present(geo_provider):
        asn_str = f"AS{geo_asn}" if _is_present(geo_asn) else ""
        if _is_present(geo_provider):
            asn_str = f"{asn_str} — {geo_provider}".removeprefix(" — ")
        network_lines.append(_field("Provider", asn_str))
    elif _is_present(cs_asn) or _is_present(cs_name):
        asn_str = f"AS{cs_asn}" if _is_present(cs_asn) else ""
        if _is_present(cs_name):
            asn_str = f"{asn_str} ({cs_name})".strip()
        network_lines.append(_field("Provider", asn_str))

    if _is_present(source.get("range")):
        network_lines.append(_field("Range", source.get("range")))

    return "\n".join(network_lines)


def extract_context_details(context_data: dict[str, Any], alert: dict[str, Any]) -> str:
    """
    Extract and format context information for human-readable display.

    Args:
        context_data: Context information dictionary
        alert: Alert dictionary to extract meta information

    Returns:
        Formatted context details string
    """
    context_lines = []

    # Process both context data and meta information
    combined_context = _combine_context_sources(context_data, alert)

    for key, value in combined_context.items():
        formatted_line = _format_context_line(key, value)
        if formatted_line:
            if "\n" in formatted_line:
                # Handle multi-line entries (like headers)
                context_lines.extend(formatted_line.split("\n"))
            else:
                context_lines.append(formatted_line)

    if not context_lines:
        return "No specific context information available."

    return "\n".join(context_lines)


# Preferred display order for context keys (most relevant first)
_CONTEXT_KEY_ORDER = [
    "username",
    "user",
    "service",
    "user_agent",
    "method",
    "status",
    "path",
    "target_uri",
    "headers",
    "http_path",
    "http_args",
    "source_ip",
]

# Keys suppressed from REQUEST CONTEXT because they are either:
# - raw duplicates of labeled fields already rendered above
#   (http_verb → HTTP Method, http_status → HTTP Status, http_user_agent → User-Agent)
# - CrowdSec geo-enrichment that belongs in NETWORK, not here
# - zero-value noise or internal-only fields
_CONTEXT_SUPPRESSED_KEYS: frozenset[str] = frozenset({
    # raw duplicates of labeled context keys
    "http_verb",
    "http_status",
    "http_user_agent",
    # CrowdSec geo enrichment — shown in NETWORK via GeoIP
    "ASNNumber",
    "ASNOrg",
    "IsInEU",
    "IsoCode",
    "SourceRange",
    # noise / redundant
    "log_type",
    "timestamp",     # redundant with First/Last seen in INCIDENT
    "source_ip",     # redundant with IP address in INCIDENT
    "http_args_len", # zero-value has no value for the recipient
})


def _limit_value(value: Any) -> Any:
    """Bound large values before including them in reports."""
    if isinstance(value, str):
        return value[:MAX_FIELD_LENGTH]
    if isinstance(value, list):
        return [_limit_value(item) for item in value[:MAX_LIST_ITEMS]]
    if isinstance(value, dict):
        limited_items = list(value.items())[:MAX_DICT_ITEMS]
        return {key: _limit_value(item) for key, item in limited_items}
    return value


def _redact_context_value(key: str, value: Any) -> Any:
    """Redact sensitive context keys recursively."""
    if _is_sensitive_key(key):
        return "[REDACTED]"
    normalized_key = key.strip().lower().replace("-", "_")
    if isinstance(value, str):
        if normalized_key in _URI_CONTEXT_KEYS:
            return _limit_value(_redact_uri(value))
        if normalized_key in _QUERY_CONTEXT_KEYS:
            return _limit_value(_redact_query(value))
    if isinstance(value, dict):
        return {
            sub_key: _redact_context_value(str(sub_key), sub_value)
            for sub_key, sub_value in list(value.items())[:MAX_DICT_ITEMS]
        }
    if isinstance(value, list):
        return [_redact_context_value(key, item) for item in value[:MAX_LIST_ITEMS]]
    return _limit_value(value)


def _combine_context_sources(
    context_data: dict[str, Any], alert: dict[str, Any]
) -> dict[str, Any]:
    """
    Combine context data and meta information from alert with explicit ordering.

    Keys are ordered according to _CONTEXT_KEY_ORDER for consistent,
    readable output. Unknown keys are appended alphabetically.

    Args:
        context_data: Context information dictionary
        alert: Alert dictionary containing meta information

    Returns:
        Combined context dictionary with consistent key ordering
    """
    raw_combined = context_data.copy() if context_data else {}

    # Extract and add meta information from alert
    if alert and "meta" in alert and isinstance(alert["meta"], list):
        meta_context = _extract_meta_context(alert["meta"])
        raw_combined.update(meta_context)

    # Apply explicit key ordering
    ordered_result = {}
    for key in _CONTEXT_KEY_ORDER:
        if key in raw_combined:
            ordered_result[key] = raw_combined.pop(key)

    # Append remaining keys alphabetically
    for key in sorted(raw_combined.keys()):
        ordered_result[key] = raw_combined[key]

    return {
        key: _redact_context_value(key, value)
        for key, value in ordered_result.items()
    }


def _json_safe_parse(value: str, *, key: str = "") -> Any:
    """Safely parse JSON strings with fallback to original value.

    The key is logged on failure instead of the raw value to prevent
    sensitive meta fields from appearing in debug logs.
    """
    if not isinstance(value, str):
        return value

    stripped = value.strip()
    if stripped.startswith(("[", "{")) and stripped.endswith(("]", "}")):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as e:
            logger.debug("JSON parsing failed for context key %r: %s", key, e)
            return value
    return value


def _extract_meta_context(meta_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract and parse meta information from alert meta list."""
    context = {}

    for meta_item in meta_list:
        if not isinstance(meta_item, dict):
            continue

        key = meta_item.get("key")
        value = meta_item.get("value")

        if not key or value is None:
            continue

        context[str(key)] = _json_safe_parse(value, key=str(key))

    return context


def _format_context_line(key: str, value: Any) -> str | None:
    """
    Format individual context key-value pair for display.

    Args:
        key: Context key
        value: Context value

    Returns:
        Formatted line string or None if should be skipped
    """
    if key in _CONTEXT_SUPPRESSED_KEYS:
        return None

    # Handle specific context keys with custom formatting
    if key in ("username", "user", "usernames"):
        text = ", ".join(str(v) for v in value) if isinstance(value, list) else value
        return _field("Username(s)", text)

    elif key == "service":
        text = ", ".join(str(v) for v in value) if isinstance(value, list) else value
        return _field("Service", text)

    elif key == "user_agent":
        if isinstance(value, list):
            # Deduplicate while preserving order; show at most 3 distinct UAs.
            seen: list[str] = []
            for ua in value:
                ua_s = str(ua)
                if ua_s not in seen:
                    seen.append(ua_s)
                if len(seen) == 3:
                    break
            text = seen[0] if len(seen) == 1 else "; ".join(seen)
        else:
            text = str(value)
        return _field("User-Agent", text)

    elif key == "method":
        text = ", ".join(value) if isinstance(value, list) else value
        return _field("HTTP Method", text)

    elif key == "status":
        text = ", ".join(str(v) for v in value) if isinstance(value, list) else value
        return _field("HTTP Status", text)

    elif key == "target_uri":
        if isinstance(value, list):
            uri_text = ", ".join(value[:3])
            if len(value) > 3:
                uri_text += f" … and {len(value) - 3} more"
            return _field("Target URIs", uri_text)
        return _field("Target URI", value)

    elif key in ("path", "http_path"):
        text = ", ".join(value[:5]) if isinstance(value, list) else value
        return _field("Request Path", text)

    elif key == "http_args":
        text = ", ".join(value[:5]) if isinstance(value, list) else value
        return _field("Query Args", text)

    elif key == "headers":
        if isinstance(value, dict):
            return "\n".join(
                _field(f"Header {header_key}", header_value)
                for header_key, header_value in value.items()
            )
        return _field("Headers", json.dumps(value, ensure_ascii=False))

    elif isinstance(value, list):
        # Join simple scalar lists for readability; JSON-encode nested ones.
        if all(not isinstance(item, (dict, list)) for item in value):
            return _field(key, ", ".join(str(item) for item in value))
        return _field(key, json.dumps(value, ensure_ascii=False))

    elif isinstance(value, dict):
        return _field(key, json.dumps(value, ensure_ascii=False))

    else:
        return _field(key, value)


def extract_context_for_json(
    context_data: dict[str, Any], alert: dict[str, Any]
) -> dict[str, Any]:
    """
    Extract context data for JSON serialization in X-ARF reports.

    Args:
        context_data: Context information dictionary
        alert: Alert dictionary to extract meta information

    Returns:
        Context dictionary ready for JSON serialization
    """
    return _combine_context_sources(context_data, alert)


def format_timestamp(timestamp: str) -> str:
    """
    Format ISO timestamp to human-readable format.

    Args:
        timestamp: ISO format timestamp string

    Returns:
        Formatted timestamp string or 'N/A' if invalid
    """
    if not timestamp:
        return "N/A"

    try:
        dt = datetime.fromisoformat(timestamp)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError) as e:
        logger.debug("Timestamp parsing failed for %r: %s", timestamp, e)
        return timestamp


def extract_blocking_reasons(decisions: list[dict[str, Any]]) -> str:
    """
    Extract and format blocking reasons from decisions.

    Args:
        decisions: List of decision dictionaries

    Returns:
        Formatted blocking reasons string
    """
    if not decisions:
        return "No specific blocking reasons available."

    reasons = []
    for decision in decisions[:MAX_LIST_ITEMS]:
        decision_type = str(_limit_value(decision.get("type", "unknown"))).upper()
        scope = _limit_value(decision.get("scope", "unknown"))
        value = _limit_value(decision.get("value", "unknown"))
        duration = _limit_value(decision.get("duration"))
        origin = _limit_value(decision.get("origin"))
        scenario = _limit_value(decision.get("scenario", "unknown"))

        # Normalise CrowdSec title-case scope values ("Ip" → "IP", "Range" → "Range")
        scope_display = "IP" if str(scope).lower() == "ip" else scope

        headline = f"  {decision_type}: {value} (scope {scope_display}"
        if duration:
            headline += f", for {duration}"
        headline += ")"
        reasons.append(headline)

        # Detail line indented 4 spaces (one level below the 2-space headline)
        detail = f"    scenario {scenario}"
        if origin:
            detail += f", origin {origin}"
        reasons.append(detail)

    return "\n".join(reasons)
