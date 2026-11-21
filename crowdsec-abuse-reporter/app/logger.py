#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/logger.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import re

from gillbates_logging import LineLog

# Tool-specific level colours and level-column values on top of the package defaults.
_EXTRA_COLORS = {
    "PROCESSING": "\033[95m",  # Magenta
    "DNS_QUERY": "\033[96m",  # Bright Cyan
    "MAIL_SENT": "\033[92m",  # Green
}
_EXTRA_TAGS = {
    "PROCESSING": "PROCESS",
    "DNS_QUERY": "DNS",
    "MAIL": "MAIL",
    "MAIL_SENT": "MAIL",
}

LOG_SOURCE = "crowdsec_abuse"
LOG = LineLog(LOG_SOURCE, tags=_EXTRA_TAGS, colors=_EXTRA_COLORS)
# Merged tables, including the package defaults.
COLORS = LOG.colors
TAGS = LOG.tags


def print_log(level: str, tag: str, message: str) -> None:
    """Print one log line: `<UTC time> | LEVEL | crowdsec_abuse | message`.

    ``level`` selects colour and stream (WARNING and above go to stderr);
    ``tag`` is the level-column value, usually TAGS[level] (mail errors log as
    MAIL on stderr). Colour only on a TTY with NO_COLOR unset.
    """
    LOG.print_log(level, tag, message)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logging once so module-level ``logger.*`` calls are emitted. Idempotent."""
    LOG.setup(level)


def split_recipients(recipient_string: str) -> list[str]:
    """Split a recipient string into validated addresses.

    Imported lazily: ``app.abuse`` imports this module, so a module-level
    import here would be circular.
    """
    from app.abuse import split_recipients as abuse_split

    return abuse_split(recipient_string)


def format_recipients_display(recipients: list[str], max_length: int = 40) -> str:
    """Format recipients for display with truncation if needed."""
    if not recipients:
        return "no recipients"

    if len(recipients) == 1:
        recipient_str = recipients[0]
    else:
        recipient_str = f"{recipients[0]} +{len(recipients) - 1} more"

    if len(recipient_str) > max_length:
        return recipient_str[: max_length - 3] + "..."

    return recipient_str


def print_processing(alert_index: int, total_alerts: int, ip: str, scenario: str) -> None:
    """Print the progress line for one alert."""
    progress = f"{alert_index}/{total_alerts}"
    message = f"Processing {progress} - {ip} ({scenario})"
    print_log("PROCESSING", TAGS["PROCESSING"], message)


def print_dns_query(ip: str, ip_version: str) -> None:
    """Print DNS query information."""
    message = f"Querying Abuse Contact DB for {ip_version} {ip}"
    print_log("DNS_QUERY", TAGS["DNS_QUERY"], message)


def print_abuse_contact_found(ip: str, contact: str) -> None:
    """Print found abuse contact."""
    recipients = split_recipients(contact)
    if len(recipients) > 1:
        contact_display = f"{recipients[0]}+{len(recipients) - 1} more"
    else:
        contact_display = contact

    if len(contact_display) > 50:
        contact_display = contact_display[:47] + "..."

    message = f"Found abuse contact for {ip}: {contact_display}"
    print_log("INFO", TAGS["INFO"], message)


def print_mail_sent(recipient: str, alert_id: int | None = None, processing_time: float | None = None) -> None:
    message = f"Mail sent to {recipient}"
    if alert_id is not None:
        message += f" (Alert ID: {alert_id})"
    if processing_time is not None:
        message += f" in {processing_time:.2f}s"
    print_log("MAIL_SENT", TAGS["MAIL_SENT"], message)


def print_mail_error(recipient: str, error_msg: str, alert_id: int | None = None) -> None:
    """Print mail sending error."""
    if "SMTP error:" in error_msg:
        error_msg = error_msg.replace("SMTP error:", "").strip()

    # Extract individual errors for multiple recipients
    if "Invalid RCPT TO address" in error_msg:
        error_msg = "Invalid recipient address"
    elif "{" in error_msg and "}" in error_msg:
        # Handle SMTP error dictionary format
        error_match = re.search(r"\{[^}]+\}", error_msg)
        if error_match:
            failed_count = error_match.group(0).count("Invalid RCPT TO")
            if failed_count > 0:
                error_msg = f"{failed_count} invalid recipient(s)"

    recipients = split_recipients(recipient)
    recipient_display = format_recipients_display(recipients, 30)

    if alert_id:
        message = f"Alert {alert_id}: Failed to {recipient_display} - {error_msg}"
    else:
        message = f"Failed to {recipient_display} - {error_msg}"
    print_log("ERROR", TAGS["MAIL"], message)


def print_no_contact_found(ip: str, alert_id: int | None = None) -> None:
    """Print no abuse contact found."""
    if alert_id:
        message = f"Alert {alert_id}: No abuse contact for {ip}"
    else:
        message = f"No abuse contact for {ip}"
    print_log("WARNING", TAGS["WARNING"], message)


def print_dns_error(ip: str, error_details: str, alert_id: int | None = None) -> None:
    """Print DNS error information."""
    if alert_id:
        message = f"Alert {alert_id}: DNS error for {ip} - {error_details}"
    else:
        message = f"DNS error for {ip} - {error_details}"
    print_log("ERROR", TAGS["ERROR"], message)


def print_database_error(alert_id: int, error_details: str) -> None:
    """Print database error."""
    message = f"Alert {alert_id}: Database error - {error_details}"
    print_log("ERROR", TAGS["ERROR"], message)


def print_internal_ip_skipped(ip: str, alert_id: int | None = None) -> None:
    """Print internal IP skip message."""
    if alert_id:
        message = f"Alert {alert_id}: Skipping internal IP {ip}"
    else:
        message = f"Skipping internal IP {ip}"
    print_log("INFO", TAGS["INFO"], message)


def print_config_info(message: str) -> None:
    """Print configuration information."""
    print_log("INFO", TAGS["INFO"], message)


def print_debug(message: str) -> None:
    """Print debug-level message — suppressed unless LOG_LEVEL=DEBUG."""
    print_log("DEBUG", TAGS["DEBUG"], message)


def print_info(message: str) -> None:
    """Print an informational message."""
    print_log("INFO", TAGS["INFO"], message)


def print_warning(message: str) -> None:
    """Print a warning to stderr."""
    print_log("WARNING", TAGS["WARNING"], message)


def print_error(message: str) -> None:
    """Print an error to stderr."""
    print_log("ERROR", TAGS["ERROR"], message)


def print_summary_header(message: str) -> None:
    """Print summary header."""
    print_log("INFO", TAGS["INFO"], message)


def print_stat_item(label: str, value: str, indent: int = 1) -> None:
    """Print statistics item with indentation."""
    indent_str = "    " * indent
    message = f"{indent_str}{label}: {value}"
    print_log("INFO", TAGS["INFO"], message)
