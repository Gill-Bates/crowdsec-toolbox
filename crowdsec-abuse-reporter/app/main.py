#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/main.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
CrowdSec → Abuse Mail Export Tool
=================================
- Fetches alerts from CrowdSec
- Deduplicates by subnet before processing
- Extracts abuse contacts via DNS-based Abuse Contact DB
- Sends abuse reports via SMTP with X-ARF attachment
- Logs processed alerts in SQLite database
"""

import atexit
import ipaddress
import math
import re
import signal
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parseaddr

from app.abuse import send_abuse_mail
from app.abuse import split_recipients as _split_abuse_contacts
from app.abusix import extract_abuse_contact, get_active_nameservers
from app.banner import print_banner
from app.config import (
    BCC,
    DB_RETENTION_DAYS,
    HOSTNAME_OVERRIDE,
    LOG_LEVEL,
    MAIL_CHUNK_SIZE,
    MAX_ALERTS_PER_RUN,
    METRICS_BACKEND,
    METRICS_ENABLED,
    METRICS_ONLY,
    METRICS_OUTBOX_MAX_ROWS,
    PENDING_REAP_MINUTES,
    SLEEP_BETWEEN_CHUNKS,
    SLEEP_BETWEEN_MAILS,
    WHITELISTED_ASN,
    normalize_asn,
)
from app.crowdsec import (
    CrowdSecFetchError,
    _source_ip_from_meta,
    get_crowdsec_decisions,
    get_node_ip,
)
from app.database import (
    batch_check_processed_alerts,
    claim_alert_for_send,
    cleanup_old_records,
    close_connection,
    count_metric_points,
    finalize_alert,
    get_alert_stats,
    init_db,
    reap_stale_pending,
    run_db_maintenance,
    set_run_state,
)
from app.geoip import GeoIPUnavailableError
from app.logger import (
    TAGS,
    print_config_info,
    print_database_error,
    print_debug,
    print_dns_error,
    print_internal_ip_skipped,
    print_log,
    print_mail_error,
    print_mail_sent,
    print_no_contact_found,
    print_processing,
    print_stat_item,
    print_summary_header,
    setup_logging,
)
from app.metrics import (
    flush_points,
    format_report_line,
    get_source_host,
    measurement_name,
    write_points,
)
from app.reportbody import build_mail_body, build_xarf_report

IPV4_PREFIX_LENGTH = 24
IPV6_PREFIX_LENGTH = 48

_EMAIL_LOCAL_RE = re.compile(r"[^@\s]{1,64}")
_EMAIL_DOMAIN_RE = re.compile(r"[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}")


def _validate_email(value: str | None) -> str | None:
    """Return the normalised address or None when it fails basic validation.

    DNS-sourced abuse contacts are untrusted input. We check for control
    characters that could cause SMTP header injection and verify the address
    has the minimum shape of a routable mailbox.
    """
    if not value:
        return None
    candidate = value.strip()
    if not candidate or any(ch in candidate for ch in "\r\n\x00"):
        return None
    _, parsed = parseaddr(candidate)
    if not parsed or parsed != candidate or "@" not in parsed:
        return None
    local, domain = parsed.rsplit("@", 1)
    if not _EMAIL_LOCAL_RE.fullmatch(local) or not _EMAIL_DOMAIN_RE.fullmatch(domain):
        return None
    return parsed


@dataclass
class ProcessResult:
    """Result container for alert processing with enhanced metadata."""

    success: bool
    alert_id: int | None = None
    ip: str = ""
    scenario: str = ""
    recipient: str | None = None
    error_type: str | None = None
    error_details: str | None = None
    processing_time: float = 0.0
    db_error: bool = False
    # True once a claimed send was attempted (sent or send_error): these are
    # the outcomes exported to the metrics backend.
    finalized: bool = False


@dataclass
class ProcessingStats:
    """Enhanced statistics container with performance metrics."""

    mails_sent: int = 0
    no_contact: int = 0
    dns_errors: int = 0
    send_errors: int = 0
    database_errors: int = 0
    invalid_ips: int = 0
    invalid_alert_ids: int = 0
    whitelisted_asns: int = 0
    already_processed: int = 0
    skipped_due_to_limit: int = 0
    metrics_errors: int = 0
    total_processing_time: float = 0.0
    start_time: float = 0.0

    def handled_alerts(self) -> int:
        """Count of alerts that were actually handled (sent, no contact, or errored).

        Note: already_processed, invalid_ips, invalid_alert_ids, and skipped_due_to_limit are excluded
        as they represent alerts that were filtered before handling.
        """
        return (
            self.mails_sent
            + self.no_contact
            + self.dns_errors
            + self.send_errors
        )

    def total_errors(self) -> int:
        return (
            self.dns_errors
            + self.send_errors
            + self.database_errors
            + self.metrics_errors
        )

    def average_processing_time(self) -> float:
        total = self.handled_alerts()
        return self.total_processing_time / total if total > 0 else 0.0

    def elapsed_time(self) -> float:
        return time.monotonic() - self.start_time


class GracefulInterruptHandler:
    """Handle graceful shutdown on interrupt signals."""

    def __init__(self):
        self.interrupted = False
        self.original_handlers = {}

    def __enter__(self):
        self.original_handlers[signal.SIGINT] = signal.signal(
            signal.SIGINT, self.handler
        )
        self.original_handlers[signal.SIGTERM] = signal.signal(
            signal.SIGTERM, self.handler
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for sig, handler in self.original_handlers.items():
            signal.signal(sig, handler)

    def handler(self, signum, frame):
        self.interrupted = True
        print_config_info(
            f"Received interrupt signal {signum}, finishing current operation..."
        )


def get_alert_id(alert: dict) -> int | None:
    """Extract the stable identifier used for DB idempotency.

    Decisions derived from alerts carry the alert id in ``alert_id`` /
    ``alert_ids`` — that is the intended persistence key. We fall back to the
    decision's own ``id`` only when no alert id is present, so enrichment
    availability never changes the key for the same ban between runs.
    """
    raw_id = alert.get("alert_id")

    if raw_id is None:
        alert_ids = alert.get("alert_ids")
        if isinstance(alert_ids, list) and alert_ids:
            raw_id = alert_ids[0]

    if raw_id is None:
        raw_id = alert.get("id")

    try:
        alert_id = int(raw_id)
    except (ValueError, TypeError):
        return None

    return alert_id if alert_id > 0 else None


def _alert_source(alert: dict) -> dict:
    """Return the alert's source mapping, tolerating a malformed/missing one."""
    source = alert.get("source", {})
    return source if isinstance(source, dict) else {}


def get_alert_ip(alert: dict) -> str:
    """Enhanced IP extraction with layered fallbacks.

    CrowdSec data can surface the source IP in multiple places depending on the
    producer and API shape: `source.ip`, `source.value` (when `scope=Ip`), or
    as `source_ip` in alert metadata/context.
    """
    source = _alert_source(alert)
    ip = source.get("ip")
    if ip and ip != "unknown":
        return str(ip)

    source_value = source.get("value")
    if source_value and str(source.get("scope", "")).lower() == "ip":
        return str(source_value)

    # Flat CrowdSec decision object: the IP is in the top-level "value" (with
    # top-level "scope" Ip/Range). This is the field cscli emits for
    # `decisions list`, so it must be checked or every decision looks "unknown".
    # A Range (e.g. "1.2.3.0/24") is deliberately NOT collapsed to its network
    # address: that address is usually a different party than the one banned,
    # and reporting it would send factually wrong data to an abuse desk.
    top_value = alert.get("value")
    top_scope = str(alert.get("scope", "")).lower()
    if top_value and top_scope in ("ip", "range", ""):
        candidate = str(top_value).strip()
        if "/" not in candidate:
            return candidate
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            network = None
        # A /32 or /128 still denotes exactly one address and stays reportable.
        if network is not None and network.num_addresses == 1:
            return str(network.network_address)

    context = alert.get("context", {})
    if isinstance(context, dict):
        context_ip = context.get("source_ip")
        if context_ip and context_ip != "unknown":
            return str(context_ip)

    return _source_ip_from_meta(alert) or "unknown"


def get_alert_scenario(alert: dict) -> str:
    """Enhanced scenario extraction with fallback."""
    return alert.get("scenario", "unknown") or "unknown"


def get_alert_asn(alert: dict) -> str:
    """Extract ASN from alert source, tolerating a malformed/missing source."""
    return str(_alert_source(alert).get("as_number", "") or "")


def get_alert_as_name(alert: dict) -> str:
    """Extract the provider/org name for an alert ASN when available."""
    return str(_alert_source(alert).get("as_name", "") or "").strip()


def get_alert_country(alert: dict) -> str:
    """Extract a country code/name from alert source metadata when available."""
    source = _alert_source(alert)
    for key in ("cn", "country"):
        value = str(source.get(key, "") or "").strip()
        if value:
            return value
    return "unknown"


def _truncate_display(value: str, max_length: int) -> str:
    """Truncate long table values without breaking alignment."""
    if len(value) <= max_length:
        return value
    return value[: max_length - 3] + "..."


def _rank_top_items(values: list[str], limit: int = 10) -> list[tuple[str, int]]:
    """Count and rank values for compact startup overview tables."""
    counts = Counter(value or "unknown" for value in values)
    return counts.most_common(limit)


def build_alert_overview_rows(
    decisions: list[dict], limit: int = 10
) -> list[tuple[int, str, int | None, str, int | None]]:
    """Return aligned rows for the startup overview table."""
    top_countries = _rank_top_items(
        [get_alert_country(alert) for alert in decisions], limit=limit
    )
    top_patterns = _rank_top_items(
        [get_alert_scenario(alert) for alert in decisions], limit=limit
    )

    row_count = max(len(top_countries), len(top_patterns))
    rows: list[tuple[int, str, int | None, str, int | None]] = []
    for index in range(row_count):
        country, country_count = (
            top_countries[index] if index < len(top_countries) else ("", None)
        )
        pattern, pattern_count = (
            top_patterns[index] if index < len(top_patterns) else ("", None)
        )
        rows.append((index + 1, country, country_count, pattern, pattern_count))
    return rows


def print_alert_overview_table(decisions: list[dict], limit: int = 10) -> None:
    """Print top source countries and attack patterns for active alerts."""
    rows = build_alert_overview_rows(decisions, limit=limit)
    if not rows:
        return

    country_width = max(
        len("Country"),
        *(len(_truncate_display(country or "", 18)) for _, country, _, _, _ in rows),
    )
    pattern_width = max(
        len("Attack pattern"),
        *(len(_truncate_display(pattern or "", 36)) for _, _, _, pattern, _ in rows),
    )

    print()
    print_summary_header("CURRENT ACTIVE REPORTABLE SIGNALS")
    print_config_info(
        f"  {'#':>2}  {'Country':<{country_width}}  {'Count':>5}  "
        f"{'Attack pattern':<{pattern_width}}  {'Count':>5}"
    )
    print_config_info(
        f"  {'-' * 2}  {'-' * country_width}  {'-' * 5}  "
        f"{'-' * pattern_width}  {'-' * 5}"
    )

    for rank, country, country_count, pattern, pattern_count in rows:
        country_display = _truncate_display(country or "", 18)
        pattern_display = _truncate_display(pattern or "", 36)
        print_config_info(
            f"  {rank:>2}  {country_display:<{country_width}}  "
            f"{'' if country_count is None else country_count:>5}  "
            f"{pattern_display:<{pattern_width}}  "
            f"{'' if pattern_count is None else pattern_count:>5}"
        )


def build_whitelisted_asn_rows(
    decisions: list[dict] | None = None,
) -> list[tuple[str, str]]:
    """Return whitelisted ASNs with best-effort provider names for display."""
    if not WHITELISTED_ASN:
        return []

    providers_by_asn = dict.fromkeys(sorted(WHITELISTED_ASN, key=int), "unknown")
    try:
        from app.geoip import lookup_asn_providers

        providers_by_asn.update(lookup_asn_providers(WHITELISTED_ASN))
    except Exception as exc:
        print_debug(f"ASN provider lookup failed: {exc}")

    if not decisions:
        return [(f"AS{asn}", provider) for asn, provider in providers_by_asn.items()]

    for alert in decisions:
        asn = normalize_asn(get_alert_asn(alert))
        if not asn or asn not in providers_by_asn:
            continue
        if providers_by_asn[asn] != "unknown":
            continue

        provider = get_alert_as_name(alert)
        if not provider:
            ip = get_alert_ip(alert)
            try:
                from app.geoip import lookup as geoip_lookup

                geo = geoip_lookup(ip)
                provider = str((geo or {}).get("provider", "") or "").strip()
            except Exception as exc:
                print_debug(f"GeoIP lookup failed for {ip}: {exc}")
                provider = ""

        if provider:
            providers_by_asn[asn] = provider

    return [(f"AS{asn}", provider) for asn, provider in providers_by_asn.items()]


def print_whitelisted_asn_table(decisions: list[dict] | None = None) -> None:
    """Print a whitelist table, using local ASN DB names when available."""
    rows = build_whitelisted_asn_rows(decisions)
    if not rows:
        return
    rows = sorted(rows, key=lambda item: (item[1].casefold(), item[0]))

    asn_width = max(len("ASN"), *(len(asn) for asn, _provider in rows))
    print_config_info("Configured whitelisted ASNs:")
    print_config_info(f"  {'ASN':<{asn_width}}  Provider")
    print_config_info(f"  {'-' * asn_width}  {'-' * 32}")
    for asn, provider in rows:
        print_config_info(f"  {asn:<{asn_width}}  {provider}")


def get_alert_confidence(alert: dict) -> float:
    """Extract a confidence/score for dedup tie-breaking, defaulting to 1.0.

    CrowdSec surfaces this (when present) as a top-level field, not inside
    ``source.scope`` (which is a string like "Ip"). We read the real field and
    fall back to 1.0, in which case dedup tie-breaks on the higher alert id.
    """
    for key in ("confidence", "score"):
        value = alert.get(key)
        if value is None:
            continue
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            continue
        # float() accepts 'nan'/'inf'. NaN loses every comparison and +inf wins
        # all of them, so a non-finite upstream value would silently distort
        # both the subnet dedup tie-break and the MAX_ALERTS_PER_RUN ranking.
        if math.isfinite(confidence):
            return confidence
    return 1.0


def get_subnet_prefix_length(ip: str) -> int:
    """Enhanced subnet prefix determination with validation."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return IPV4_PREFIX_LENGTH
        return IPV6_PREFIX_LENGTH
    except (ValueError, TypeError):
        return 0


def is_valid_public_ip(ip: str, alert_id: int = 0) -> bool:
    """Check if IP is valid and public (not internal/private)."""
    if ip == "unknown":
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_global or ip_obj.is_multicast:
            print_internal_ip_skipped(ip, alert_id)
            return False
        return True
    except (ValueError, TypeError):
        return False


def deduplicate_and_filter_alerts(
    decisions: list[dict], processed_alert_ids: set[tuple[int, str]]
) -> tuple[list[dict], int, int, int, int]:
    """
    Combined deduplication and filtering in one pass for better performance.
    Uses separate policies for IPv4 and IPv6 subnets.

    Returns:
        Tuple of (
            alerts_to_process,
            invalid_ip_count,
            invalid_alert_id_count,
            skipped_limit_count,
            whitelisted_count,
        )
    """
    ipv4_subnet_to_alert: dict[str, dict] = {}
    ipv6_subnet_to_alert: dict[str, dict] = {}
    invalid_ip_count = 0
    invalid_alert_id_count = 0
    whitelisted_count = 0
    alerts_to_process: list[dict] = []

    for alert in decisions:
        alert_id = get_alert_id(alert)
        ip = get_alert_ip(alert)

        if alert_id is None:
            invalid_alert_id_count += 1
            print_config_info(f"Skipping alert with invalid ID for IP {ip}")
            continue

        # Skip already processed reports (keyed per alert + IP)
        if (alert_id, ip) in processed_alert_ids:
            continue

        # Skip whitelisted ASNs (normalized to bare digits for a robust match)
        asn = normalize_asn(get_alert_asn(alert))
        if asn and asn in WHITELISTED_ASN:
            print_config_info(f"Skipping whitelisted ASN AS{asn} (Alert {alert_id})")
            whitelisted_count += 1
            continue

        # Skip invalid/internal IPs
        if not is_valid_public_ip(ip, alert_id):
            invalid_ip_count += 1
            continue

        # Deduplicate by subnet with IP version-specific policies
        prefix_length = get_subnet_prefix_length(ip)
        if prefix_length > 0:
            try:
                network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
                prefix = str(network.network_address)

                # Separate handling for IPv4 and IPv6
                if network.version == 4:
                    subnet_dict = ipv4_subnet_to_alert
                else:
                    subnet_dict = ipv6_subnet_to_alert

                existing_alert = subnet_dict.get(prefix)

                if not existing_alert:
                    subnet_dict[prefix] = alert
                else:
                    # Prefer higher confidence, then more recent
                    current_conf = get_alert_confidence(alert)
                    existing_conf = get_alert_confidence(existing_alert)
                    existing_alert_id = get_alert_id(existing_alert) or 0

                    if current_conf > existing_conf or (
                        current_conf == existing_conf
                        and alert_id > existing_alert_id
                    ):
                        subnet_dict[prefix] = alert
            except (ValueError, TypeError):
                alerts_to_process.append(alert)
        else:
            alerts_to_process.append(alert)

    # Add deduplicated alerts to final list
    alerts_to_process.extend(ipv4_subnet_to_alert.values())
    alerts_to_process.extend(ipv6_subnet_to_alert.values())

    # Apply alert limit if configured. Sort by priority first (higher
    # confidence, then newer alert id) so the cap keeps the most relevant
    # alerts instead of an arbitrary dict-insertion order.
    if MAX_ALERTS_PER_RUN and len(alerts_to_process) > MAX_ALERTS_PER_RUN:
        alerts_to_process.sort(
            key=lambda a: (get_alert_confidence(a), get_alert_id(a) or 0),
            reverse=True,
        )
        skipped = len(alerts_to_process) - MAX_ALERTS_PER_RUN
        alerts_to_process = alerts_to_process[:MAX_ALERTS_PER_RUN]
    else:
        skipped = 0

    total_dedup_count = len(ipv4_subnet_to_alert) + len(ipv6_subnet_to_alert)

    if total_dedup_count > 0:
        print_config_info(
            f"Deduplicated to {total_dedup_count} unique subnets "
            f"({len(ipv4_subnet_to_alert)} IPv4, {len(ipv6_subnet_to_alert)} IPv6)"
        )

    return (
        alerts_to_process,
        invalid_ip_count,
        invalid_alert_id_count,
        skipped,
        whitelisted_count,
    )


def sanitize_header_value(value: object) -> str:
    """Normalize header components to a single safe line."""
    sanitized = " ".join(str(value).splitlines()).strip()
    return sanitized or "unknown"


def send_abuse_report(
    alert: dict, recipient: str, hostname: str
) -> tuple[bool, str | None]:
    """Send abuse report email and return success status with error message."""
    ip = sanitize_header_value(get_alert_ip(alert))
    scenario = sanitize_header_value(get_alert_scenario(alert))

    subject = f"Abuse Report - {ip} - {scenario}"

    # Build + send in one try-block so an unexpected shape in alert data
    # (e.g. non-dict source/context) is caught here rather than after the
    # DB claim, which would leave the row permanently in 'pending'.
    try:
        body = build_mail_body(alert, hostname)
        xarf_attachment = build_xarf_report(alert, hostname)
        return send_abuse_mail(
            recipient=recipient,
            subject=subject,
            body=body,
            bcc=BCC,
            xarf_attachment=xarf_attachment,
        )
    except Exception as e:
        return False, f"Failed to build or send report: {e}"


def handle_processing_error(
    alert: dict, error_type: str, error_details: str, processing_time: float
) -> ProcessResult:
    """Handle and log processing errors consistently with proper alert reference."""
    alert_id = get_alert_id(alert)
    ip = get_alert_ip(alert)
    scenario = get_alert_scenario(alert)

    if error_type == "dns_error":
        print_dns_error(ip, error_details, alert_id)
    elif error_type == "no_contact":
        print_no_contact_found(ip, alert_id)

    return ProcessResult(
        success=False,
        alert_id=alert_id,
        ip=ip,
        scenario=scenario,
        error_type=error_type,
        error_details=error_details,
        processing_time=processing_time,
    )


def _sqlite_payload(value: str | None) -> str | None:
    """Report details stored in SQLite: kept by default, dropped in metrics mode.

    With a metrics backend the SQLite row carries control data only (AlertId,
    IPAddress, Status, timestamps) so the claim/finalize at-most-once protocol
    keeps working, while recipient, scenario and error text live solely in the
    time-series backend. Returns '' (or None for optional columns) there.
    """
    if not METRICS_ENABLED:
        return value
    return None if value is None else ""


def build_report_point(
    alert: dict, result: "ProcessResult", hostname: str, timestamp: datetime | None = None
) -> str:
    """Line-protocol point for one finalized report."""
    return format_report_line(
        measurement_name(hostname),
        host=get_source_host(),
        alert_id=result.alert_id or 0,
        ip=result.ip,
        scenario=result.scenario,
        status="sent" if result.success else "failed",
        recipient=result.recipient or "",
        error=result.error_details,
        country=get_alert_country(alert),
        as_number=normalize_asn(get_alert_asn(alert)),
        as_name=get_alert_as_name(alert),
        processing_time=result.processing_time,
        timestamp=timestamp,
    )


def process_single_alert(
    alert: dict, alert_index: int, total_alerts: int, hostname: str
) -> ProcessResult:
    """Process a single alert with improved structure."""
    alert_id = get_alert_id(alert)
    ip = get_alert_ip(alert)
    scenario = get_alert_scenario(alert)

    # Hard safety net: a whitelisted ASN must NEVER trigger a mail, even if it
    # somehow slipped past the upstream filter (e.g. enrichment changed the ASN).
    asn = normalize_asn(get_alert_asn(alert))
    if asn and asn in WHITELISTED_ASN:
        print_config_info(
            f"Blocked whitelisted ASN AS{asn} before send (Alert {alert_id})"
        )
        return ProcessResult(
            success=False,
            alert_id=alert_id,
            ip=ip,
            scenario=scenario,
            error_type="whitelisted",
        )

    print_processing(alert_index, total_alerts, ip, scenario)
    start_time = time.monotonic()

    # Step 1: Get abuse contact
    try:
        recipient = extract_abuse_contact(ip)
    except (OSError, RuntimeError, TimeoutError, ValueError) as e:
        processing_time = time.monotonic() - start_time
        return handle_processing_error(alert, "dns_error", str(e), processing_time)

    # DNS may return comma-separated multi-address contacts; validate each
    # individually and reassemble, falling back to single-address validation.
    valid_addrs = _split_abuse_contacts(recipient or "")
    if valid_addrs:
        recipient = ",".join(valid_addrs)
    else:
        recipient = _validate_email(recipient)
    if not recipient:
        processing_time = time.monotonic() - start_time
        return handle_processing_error(
            alert, "no_contact", f"No valid abuse contact for {ip}", processing_time
        )

    # Step 2: Claim the alert atomically right before sending. This is the
    # idempotency guard: only the claim owner sends, so a crash mid-send or two
    # overlapping runs can never deliver the same report twice.
    if alert_id is None:
        return ProcessResult(
            success=False,
            ip=ip,
            scenario=scenario,
            error_type="invalid_alert_id",
            processing_time=time.monotonic() - start_time,
        )

    try:
        claimed = claim_alert_for_send(alert_id, ip, _sqlite_payload(scenario))
    except Exception as e:
        # A failed claim is a persistence failure, not an idempotent skip.
        # Counting it as db_error keeps the run's exit code honest; swallowing
        # it here would let the container look healthy while nothing was sent.
        # Caught per alert so one bad row does not abort the remaining work.
        return ProcessResult(
            success=False,
            alert_id=alert_id,
            ip=ip,
            scenario=scenario,
            recipient=recipient,
            error_type="database_error",
            error_details=str(e),
            processing_time=time.monotonic() - start_time,
            db_error=True,
        )

    if not claimed:
        processing_time = time.monotonic() - start_time
        print_config_info(
            f"Skipping Alert {alert_id} for {ip}: already sent or in-flight"
        )
        return ProcessResult(
            success=False,
            alert_id=alert_id,
            ip=ip,
            scenario=scenario,
            recipient=recipient,
            error_type="already_handled",
            processing_time=processing_time,
        )

    # Step 3: Send abuse report
    success, error_msg = send_abuse_report(alert, recipient, hostname)
    processing_time = time.monotonic() - start_time

    # Step 4: Persist the outcome (transition out of 'pending')
    db_error = False
    try:
        finalize_alert(
            alert_id,
            _sqlite_payload(recipient),
            ip,
            _sqlite_payload(scenario),
            success,
            None if success or METRICS_ENABLED else error_msg,
        )
    except Exception as e:
        # The send outcome is already decided; a failed finalize leaves the row
        # 'pending', which is never auto-resent (at-most-once preserved).
        db_error = True
        print_database_error(
            alert_id, f"Failed to finalize alert after send: {e}"
        )

    # Step 5: Build result
    if success:
        print_mail_sent(recipient, alert_id, processing_time)
        return ProcessResult(
            success=True,
            alert_id=alert_id,
            ip=ip,
            scenario=scenario,
            recipient=recipient,
            processing_time=processing_time,
            db_error=db_error,
            finalized=True,
        )
    else:
        print_mail_error(recipient, error_msg, alert_id)
        return ProcessResult(
            success=False,
            alert_id=alert_id,
            ip=ip,
            scenario=scenario,
            recipient=recipient,
            error_type="send_error",
            error_details=error_msg,
            processing_time=processing_time,
            db_error=db_error,
            finalized=True,
        )


def sleep_between_mails(
    has_more_alerts: bool,
    last_result_success: bool,
    interrupt_handler: "GracefulInterruptHandler",
) -> None:
    """
    Sleep between mails based on configuration and last result.

    Args:
        has_more_alerts: Whether another alert will be processed afterwards
        last_result_success: Whether the last email was sent successfully
        interrupt_handler: Handler whose flag aborts the sleep on a stop signal
    """
    if SLEEP_BETWEEN_MAILS <= 0:
        return

    if last_result_success and has_more_alerts:
        print_config_info(f"Rate limiting: Sleeping {SLEEP_BETWEEN_MAILS} seconds...")
        # Use the interruptible variant so a container stop during the rate-limit
        # pause is honored promptly instead of blocking until Docker SIGKILLs us.
        interruptible_sleep(SLEEP_BETWEEN_MAILS, interrupt_handler)


def chunk_alerts(alerts: list[dict], chunk_size: int) -> list[list[dict]]:
    """Split alerts into chunks of chunk_size. A size <= 0 disables chunking
    (returns a single chunk with all alerts)."""
    if chunk_size <= 0 or len(alerts) <= chunk_size:
        return [alerts] if alerts else []
    return [alerts[i : i + chunk_size] for i in range(0, len(alerts), chunk_size)]


def interruptible_sleep(seconds: int, interrupt_handler: "GracefulInterruptHandler") -> None:
    """Sleep in 1-second steps so a shutdown signal is honored promptly."""
    for _ in range(max(0, seconds)):
        if interrupt_handler.interrupted:
            return
        time.sleep(1)


def _print_summary_section(title: str, rows: list[tuple[str, str]]) -> None:
    """Render a compact, readable summary section without log timestamps."""
    print(f"\n{title}")
    print("-" * len(title))

    label_width = max((len(label) for label, _ in rows), default=0)
    for label, value in rows:
        print(f"  {label:<{label_width}} : {value}")


def _print_sent_email_summary(
    mails_sent_details: list[tuple[int, str, str, str]], limit: int = 5
) -> None:
    """Render the sent-mail list in a terminal-friendly summary format."""
    if not mails_sent_details:
        return

    print(f"\nSent emails ({len(mails_sent_details)})")
    print("-" * len(f"Sent emails ({len(mails_sent_details)})"))

    for index, (alert_id, ip, scenario, recipient) in enumerate(
        mails_sent_details[:limit], start=1
    ):
        print(f"  {index}. Alert #{alert_id} | {ip} | {scenario}")
        print(f"     Recipients: {recipient}")

    remaining = len(mails_sent_details) - limit
    if remaining > 0:
        print(f"  ... {remaining} more entr{'y' if remaining == 1 else 'ies'} not shown")


def print_detailed_summary(
    stats: ProcessingStats,
    total_alerts: int,
    unique_alerts: int,
    mails_sent_details: list[tuple[int, str, str, str]],
) -> None:
    """Enhanced summary with performance metrics."""
    print("\n" + "=" * 60)
    print("RUN SUMMARY")
    print("=" * 60)

    overview_rows = [
        ("Total alerts from CrowdSec", str(total_alerts)),
        ("Eligible after filtering", str(unique_alerts)),
        ("Already processed", str(stats.already_processed)),
        ("Invalid/internal IPs", str(stats.invalid_ips)),
    ]
    if stats.invalid_alert_ids:
        overview_rows.append(("Invalid alert IDs", str(stats.invalid_alert_ids)))
    if stats.whitelisted_asns:
        overview_rows.append(("Whitelisted ASNs", str(stats.whitelisted_asns)))
    if stats.skipped_due_to_limit:
        overview_rows.append(("Skipped due to limit", str(stats.skipped_due_to_limit)))
    overview_rows.append(("Handled in this run", str(stats.handled_alerts())))
    _print_summary_section("Overview", overview_rows)

    result_rows = [
        ("Emails sent", str(stats.mails_sent)),
        ("No contact found", str(stats.no_contact)),
    ]
    if stats.dns_errors:
        result_rows.append(("DNS errors", str(stats.dns_errors)))
    if stats.send_errors:
        result_rows.append(("Send errors", str(stats.send_errors)))
    if stats.database_errors:
        result_rows.append(("Database errors", str(stats.database_errors)))
    if stats.metrics_errors:
        result_rows.append(("Metrics write errors", str(stats.metrics_errors)))
    _print_summary_section("Results", result_rows)

    performance_rows = [
        ("Total processing time", f"{stats.elapsed_time():.2f}s"),
        ("Average time per alert", f"{stats.average_processing_time():.2f}s"),
    ]
    _print_summary_section("Performance", performance_rows)

    _print_sent_email_summary(mails_sent_details)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _run_metrics_snapshot(hostname: str) -> int:
    """Export the current CrowdSec decisions without sending abuse mail."""
    if not METRICS_ENABLED:
        return 0
    try:
        decisions = get_crowdsec_decisions()
    except Exception as exc:
        print_database_error(0, f"Failed to fetch decisions for metrics: {exc}")
        return 1

    lines: list[str] = []
    for alert in decisions:
        alert_id = get_alert_id(alert)
        if alert_id is None:
            continue
        lines.append(
            format_report_line(
                measurement_name(hostname),
                host=get_source_host(),
                alert_id=alert_id,
                ip=get_alert_ip(alert),
                scenario=get_alert_scenario(alert),
                status="observed",
                recipient="",
                error=None,
                country=get_alert_country(alert),
                as_number=normalize_asn(get_alert_asn(alert)),
                as_name=get_alert_as_name(alert),
                processing_time=0.0,
            )
        )
    return 0 if write_points(lines) else 1


def _metrics_outbox_is_saturated() -> bool:
    """True when the outbox is within 10% of METRICS_OUTBOX_MAX_ROWS.

    The threshold is what turns a deferred batch into a failed run. Below it the
    points are merely waiting and the run is healthy; at it the next prune starts
    dropping the oldest points, which is real data loss and has to be visible.
    With the bound disabled (0) the spool is unbounded, so it can never saturate.
    """
    if METRICS_OUTBOX_MAX_ROWS <= 0:
        return False
    return count_metric_points() >= int(METRICS_OUTBOX_MAX_ROWS * 0.9)


def main() -> int:
    """Run once and record the outcome as control data in SQLite run_state."""
    started_at = _utc_now_iso()
    exit_code = 1
    try:
        exit_code = _run(started_at)
        return exit_code
    finally:
        if _run_state_ready:
            set_run_state(
                {
                    "last_run_finished_at": _utc_now_iso(),
                    "last_run_exit_code": str(exit_code),
                }
            )


# Set once init_db() succeeded so main() never creates a database just to
# record the state of a run that failed before the DB was usable.
_run_state_ready = False


def _run(started_at: str) -> int:
    """Enhanced main function with graceful interruption handling and immediate persistence."""
    global _run_state_ready
    _run_state_ready = False
    # Configure logging first so module-level logger.* traces are visible
    # (e.g. in `docker logs`) — otherwise INFO/DEBUG are silently dropped.
    setup_logging(LOG_LEVEL)
    print_banner()

    # Ensure the DB connection is closed cleanly on every exit path —
    # normal return, early error return, unhandled exception, or SIGTERM.
    atexit.register(close_connection)

    with GracefulInterruptHandler() as interrupt_handler:
        if METRICS_ONLY:
            # The metrics-only snapshot never sends mail, so it does not need
            # the reporting identity for QuestDB: measurement_name() ignores
            # `hostname` there and uses QUESTDB_TABLE instead (metrics.py), so
            # calling get_node_ip() would just be a redundant public-IP lookup
            # on every METRICS_INTERVAL tick, alongside the one the main
            # run_once loop already performs in entrypoint.sh. InfluxDB 2.x
            # does use `hostname` as the measurement name, so it still needs
            # the real lookup.
            if METRICS_BACKEND == "questdb":
                return _run_metrics_snapshot(HOSTNAME_OVERRIDE.strip())
            return _run_metrics_snapshot(HOSTNAME_OVERRIDE.strip() or get_node_ip())

        # Reporting identity: an explicit HOSTNAME_OVERRIDE wins; otherwise
        # get_node_ip() detects the routable public IP via external services
        # (correct even in Docker/behind NAT, where local detection would only
        # see a private bridge IP like 10.30.0.5).
        hostname = HOSTNAME_OVERRIDE.strip() or get_node_ip()

        # Initialize statistics with start time
        stats = ProcessingStats()
        stats.start_time = time.monotonic()

        print_config_info("Starting CrowdSec Abuse Mail export...")
        print_summary_header("DNS-BASED PROCESSING")
        print_config_info(f"✓ Reporting from: {hostname}")
        print_config_info("✓ Smart subnet deduplication")
        print_config_info(f"✓ IPv4 prefix length: /{IPV4_PREFIX_LENGTH}")
        print_config_info(f"✓ IPv6 prefix length: /{IPV6_PREFIX_LENGTH}")
        print_config_info("✓ DNS-based Abuse Contact DB queries")
        print_config_info(
            f"✓ DNS resolvers: {', '.join(get_active_nameservers()) or 'system'}"
        )
        print_config_info("✓ Full IPv4/IPv6 Dual-Stack support")
        print_config_info("✓ Immediate database persistence")
        print_config_info("✓ Internal networks are automatically skipped")
        print_config_info("✓ X-ARF attachment included")

        if MAX_ALERTS_PER_RUN:
            print_config_info(f"✓ Alert limit: {MAX_ALERTS_PER_RUN} per run")
        if SLEEP_BETWEEN_MAILS > 0:
            print_config_info(f"✓ Rate limiting: {SLEEP_BETWEEN_MAILS}s between emails")
        if MAIL_CHUNK_SIZE > 0:
            chunk_msg = f"✓ Chunked sending: {MAIL_CHUNK_SIZE} mails per chunk"
            if SLEEP_BETWEEN_CHUNKS > 0:
                chunk_msg += f", {SLEEP_BETWEEN_CHUNKS}s between chunks"
            print_config_info(chunk_msg)
        print_config_info("✓ Idempotent delivery (no duplicate reports in normal operation)")
        if METRICS_ENABLED:
            print_config_info(
                f"✓ Metrics backend: {METRICS_BACKEND} (SQLite keeps control data only)"
            )

        print_config_info("============================")

        # GeoIP: ensure both DBs are present and fresh before processing.
        # A refresh failure with an already-cached DB is non-fatal (reports
        # still go out, using the stale copy). A first-ever download failure
        # (no cached DB at all) is fatal — the container must not silently
        # run forever without GeoIP enrichment.
        try:
            from app.geoip import ensure_geoip_databases
            _geo_result = ensure_geoip_databases()
            if _geo_result.get("city") and _geo_result.get("asn"):
                print_config_info("✓ GeoIP databases ready (City + ASN)")
            else:
                missing = [k for k, v in _geo_result.items() if not v]
                print_config_info(f"⚠ GeoIP databases unavailable: {', '.join(missing)} — enrichment skipped")
        except GeoIPUnavailableError as e:
            print_config_info(f"ERROR: {e}")
            return 1
        except Exception as e:
            # Also fatal. A refresh failure that still has a usable cached DB is
            # handled inside the GeoIP module and never reaches here, so
            # anything arriving at this point (permission denied on the data
            # dir, a stale lock) means enrichment is genuinely broken. Warning
            # and continuing would bypass the fail-closed contract above.
            print_config_info(f"ERROR: GeoIP initialization failed: {e}")
            return 1

        # Deliberately after the GeoIP step: the provider names come from the
        # local ASN MMDB, so printing this with the rest of the configuration
        # above resolved every entry to "unknown" whenever the database was not
        # on disk yet — a cold start without an image baseline, or a run whose
        # first action is to download it.
        print_whitelisted_asn_table()

        # Initialize database
        try:
            init_db()
        except Exception as e:
            print_database_error(0, f"Failed to initialize database: {e}")
            return 1
        _run_state_ready = True
        set_run_state(
            {"last_run_started_at": started_at, "metrics_backend": METRICS_BACKEND}
        )

        # Prune records older than DB_RETENTION_DAYS (non-fatal).
        if DB_RETENTION_DAYS > 0:
            try:
                cleanup_old_records(DB_RETENTION_DAYS)
            except Exception as e:
                print_database_error(0, f"DB cleanup failed (non-fatal): {e}")

        # Mark reports left 'pending' by a crashed/killed earlier run as
        # 'unknown_send_state' (non-fatal). They are never retried: SMTP may
        # already have accepted the mail, and at-most-once beats a duplicate.
        if PENDING_REAP_MINUTES > 0:
            try:
                reap_stale_pending(PENDING_REAP_MINUTES)
            except Exception as e:
                print_database_error(0, f"Pending reaper failed (non-fatal): {e}")

        # Lightweight maintenance: ANALYZE calibration + WAL trim.
        run_db_maintenance()

        # Push whatever an earlier run could not deliver, before this run adds to
        # it. Doing it here rather than only at the end means a backend that came
        # back is drained even if this run finds no new alerts to report.
        if METRICS_ENABLED:
            outstanding = count_metric_points()
            if outstanding:
                print_config_info(
                    f"Retrying {outstanding} spooled metrics point(s) from an "
                    f"earlier run"
                )
                flush_points()

        # Lifetime statistics — shown once per run so trends are visible in logs.
        try:
            db_stats = get_alert_stats()
            if db_stats.get("total", 0) > 0:
                sent = db_stats["successful"]
                total = db_stats["total"]
                failed = db_stats.get("failed", 0)
                failed_suffix = f" ({failed} failed)" if failed else ""
                print()
                print_config_info(
                    f"Historical totals: {sent} mails sent / {total} total reports{failed_suffix}"
                )
        except Exception as e:
            print_database_error(0, f"Failed to display historical totals: {e}")

        # Fetch decisions from CrowdSec.
        # Distinguish a real fetch/parse failure from CrowdSec genuinely having
        # no decisions, so a broken LAPI call is never silently treated as
        # "nothing to report".
        print()
        print_config_info("Connecting to CrowdSec LAPI and fetching active decisions...")
        try:
            decisions = get_crowdsec_decisions()
        except CrowdSecFetchError as e:
            print_config_info(f"ERROR: Could not fetch CrowdSec decisions: {e}")
            if e.hint:
                print_config_info(f"HINT: {e.hint}")
            return 1
        except Exception as e:
            print_config_info(
                f"ERROR: Unexpected error while fetching CrowdSec decisions: {e}"
            )
            return 1

        if not decisions:
            print_config_info("CrowdSec returned no decisions — nothing to report")
            return 0
        print_debug(f"Retrieved {len(decisions)} alerts from CrowdSec")
        print_alert_overview_table(decisions)

        # Batch check processed reports. Idempotency is per (alert, IP) because
        # one alert can carry several bans (different IPs).
        alert_keys = [
            (alert_id, get_alert_ip(alert))
            for alert in decisions
            if (alert_id := get_alert_id(alert)) is not None
        ]
        processed_alert_ids = batch_check_processed_alerts(alert_keys)
        stats.already_processed = len(processed_alert_ids)

        # Combined deduplication and filtering
        (
            alerts_to_process,
            invalid_ip_count,
            invalid_alert_id_count,
            skipped_count,
            whitelisted_count,
        ) = deduplicate_and_filter_alerts(decisions, processed_alert_ids)
        stats.invalid_ips = invalid_ip_count
        stats.invalid_alert_ids = invalid_alert_id_count
        stats.skipped_due_to_limit = skipped_count
        stats.whitelisted_asns = whitelisted_count

        # Early exit if no alerts to process
        if not alerts_to_process:
            print()
            print_config_info("No alerts require processing after filtering")
            print_stat_item("Total alerts", str(len(decisions)))
            print_stat_item("Already processed", str(stats.already_processed))
            print_stat_item("Invalid/internal IPs", str(stats.invalid_ips))
            if stats.invalid_alert_ids:
                print_stat_item("Invalid alert IDs", str(stats.invalid_alert_ids))
            if stats.whitelisted_asns:
                print_stat_item("Whitelisted ASNs", str(stats.whitelisted_asns))
            if stats.skipped_due_to_limit:
                print_stat_item("Skipped due to limit", str(stats.skipped_due_to_limit))
            print_config_info("Processing completed successfully!")
            return 0

        print_config_info(
            f"After filtering: {len(alerts_to_process)} alerts require processing"
        )

        # Process alerts in chunks with optional throttling between chunks
        mails_sent_details: list[tuple[int, str, str, str]] = []
        metric_lines: list[str] = []
        total_to_process = len(alerts_to_process)
        chunks = chunk_alerts(alerts_to_process, MAIL_CHUNK_SIZE)
        processed = 0

        for chunk_index, chunk in enumerate(chunks):
            if interrupt_handler.interrupted:
                print_config_info("Interrupt received, stopping processing...")
                break

            if len(chunks) > 1:
                print_config_info(
                    f"Processing chunk {chunk_index + 1}/{len(chunks)} "
                    f"({len(chunk)} alerts)"
                )

            for alert in chunk:
                if interrupt_handler.interrupted:
                    print_config_info("Interrupt received, stopping processing...")
                    break

                processed += 1
                result = process_single_alert(
                    alert, processed, total_to_process, hostname
                )

                stats.total_processing_time += result.processing_time

                if METRICS_ENABLED and result.finalized:
                    try:
                        metric_lines.append(build_report_point(alert, result, hostname))
                    except (TypeError, ValueError) as e:
                        stats.metrics_errors += 1
                        print_database_error(
                            result.alert_id or 0, f"Failed to build metrics point: {e}"
                        )

                # Update statistics for real-time display
                if result.success and result.recipient:
                    mails_sent_details.append(
                        (result.alert_id, result.ip, result.scenario, result.recipient)
                    )
                    stats.mails_sent += 1
                elif result.error_type == "no_contact":
                    stats.no_contact += 1
                elif result.error_type == "dns_error":
                    stats.dns_errors += 1
                elif result.error_type == "send_error":
                    stats.send_errors += 1
                elif result.error_type == "whitelisted":
                    stats.whitelisted_asns += 1
                elif result.error_type == "already_handled":
                    stats.already_processed += 1

                if result.db_error:
                    stats.database_errors += 1

                # Sleep between successful emails for rate limiting
                has_more_alerts = processed < total_to_process
                sleep_between_mails(has_more_alerts, result.success, interrupt_handler)

            # Throttle between chunks (skip after the final chunk)
            is_last_chunk = chunk_index == len(chunks) - 1
            if (
                SLEEP_BETWEEN_CHUNKS > 0
                and not is_last_chunk
                and not interrupt_handler.interrupted
            ):
                print_config_info(
                    f"Chunk {chunk_index + 1}/{len(chunks)} complete — "
                    f"throttling {SLEEP_BETWEEN_CHUNKS}s before next chunk..."
                )
                interruptible_sleep(SLEEP_BETWEEN_CHUNKS, interrupt_handler)

        # One batch write per run, also after an interrupt so already-sent
        # reports are not held back. The points are spooled to SQLite first, so a
        # failed write defers them to the next run instead of losing them — which
        # matters because in metrics mode the report details are stored nowhere
        # else. A deferred batch is therefore a warning, not a run failure; the
        # outbox bounds in config.py decide when a prolonged outage becomes one
        # (see _check_metrics_outbox_health).
        if METRICS_ENABLED and not flush_points(metric_lines):
            print_log(
                "WARNING",
                TAGS["WARNING"],
                f"Metrics points are queued for the next run "
                f"({METRICS_BACKEND} unreachable); mails were sent",
            )
            # Escalate only once the spool is close to its bound, i.e. when the
            # next prune would start discarding points for real. A single
            # unreachable-backend run is recoverable and must not flip the
            # container unhealthy; an outage long enough to overflow the spool is
            # the failure worth surfacing.
            if _metrics_outbox_is_saturated():
                stats.metrics_errors += 1

        # Final summary
        print_detailed_summary(
            stats, len(decisions), len(alerts_to_process), mails_sent_details
        )

        error_count = stats.total_errors()
        status = "with warnings" if error_count > 0 else "successfully"
        if interrupt_handler.interrupted:
            status = "interrupted"

        print_config_info(f"Processing completed {status}!")

        # Exit code reflects run-level outcome so the orchestrator and the
        # entrypoint heartbeat can distinguish a healthy run from a failed one.
        # Per-report send/DNS errors are expected, transient, and retried next
        # run (greylisting, temporary DNS) — they must NOT fail the run or they
        # would wrongly flip the container unhealthy. Database errors indicate a
        # real persistence problem (disk full, locked DB) and are surfaced.
        if interrupt_handler.interrupted:
            return 130
        if stats.database_errors or stats.metrics_errors:
            return 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
