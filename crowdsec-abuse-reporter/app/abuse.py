#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/abuse.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import smtplib
from contextlib import contextmanager
from email.message import Message
from email.mime.base import MIMEBase

from gillbates_smtp_client import (
    BACKOFF_FACTOR,
    EMAIL_REGEX,
    MAX_RETRIES,
    RETRY_DELAY,
    DeliveryReport,
    LogSink,
    SmtpConfig,
    UncertainSendError,
    build_message,
    format_recipient_errors,
    make_attachment,
    normalize_recipients,
    send_message,
    send_with_retry,
    validate_email,
)
from gillbates_smtp_client import (
    smtp_connection as _smtp_connection,
)
from gillbates_smtp_client import (
    split_recipients as _split_recipients,
)

from .config import (
    SENDER_NAME,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_SENDER,
    SMTP_SERVER,
    SMTP_USE_TLS,
    SMTP_USERNAME,
    SMTP_VALIDATE_CERTIFICATE,
)
from .logger import print_config_info, print_debug, print_mail_error, print_warning
from .version import VERSION

SMTP_TIMEOUT = 30

__all__ = [
    "BACKOFF_FACTOR",
    "EMAIL_REGEX",
    "MAX_RETRIES",
    "RETRY_DELAY",
    "SMTP_TIMEOUT",
    "UncertainSendError",
    "send_abuse_mail",
    "smtp_connection",
    "split_recipients",
    "validate_email",
]


def _log_sink(recipient: str | None = None) -> LogSink:
    """Route the shared client's log lines through this app's logger; errors name the recipient."""
    return LogSink(
        debug=print_debug,
        info=print_config_info,
        warning=print_warning,
        error=lambda message: print_mail_error(recipient, message),
    )


def _smtp_config(timeout: float = SMTP_TIMEOUT) -> SmtpConfig:
    # Read the settings at call time so they can be patched per test.
    return SmtpConfig(
        host=SMTP_SERVER,
        port=SMTP_PORT,
        starttls=SMTP_USE_TLS,
        validate_certificate=SMTP_VALIDATE_CERTIFICATE,
        username=SMTP_USERNAME,
        password=SMTP_PASSWORD,
        timeout=timeout,
        unverified_tls_warning="SMTP TLS session without certificate verification (SMTP_VALIDATE_CERTIFICATE=false)",
    )


def _check_smtp_settings() -> None:
    """Reject unusable settings with messages that name this app's variables.

    The shared client checks the same rules, with generic wording.
    """
    if bool(SMTP_USERNAME) != bool(SMTP_PASSWORD):
        raise RuntimeError("SMTP_USERNAME and SMTP_PASSWORD must either both be set or both be empty.")
    if not SMTP_USE_TLS:
        raise RuntimeError("SMTP requires TLS. Set SMTP_USE_TLS=true; plaintext SMTP is not supported.")


@contextmanager
def smtp_connection(timeout: int = SMTP_TIMEOUT):
    """Open one SMTP connection (STARTTLS and AUTH as configured) and close it on exit.

    Connections are not reused across sends.

    Raises:
        RuntimeError: Half-configured credentials, or TLS switched off.
    """
    _check_smtp_settings()
    with _smtp_connection(_smtp_config(timeout), log=_log_sink()) as server:
        yield server


def split_recipients(recipients_str: str) -> list[str]:
    """Split a comma- or semicolon-separated string into valid addresses.

    Invalid entries are dropped and their count is reported.
    """
    return _split_recipients(recipients_str, _log_sink())


def _normalize_recipients(value: str | list[str] | None) -> list[str]:
    """Normalize recipient input through the same validation path."""
    return normalize_recipients(value, _log_sink())


def send_abuse_mail(
    recipient: str,
    subject: str,
    body: str,
    bcc: list[str] | None = None,
    xarf_attachment: str | bytes | None = None,
    max_retries: int = MAX_RETRIES,
    retry_delay: float = RETRY_DELAY,
    timeout: int = SMTP_TIMEOUT,
) -> tuple[bool, str | None]:
    """Send an abuse report email via SMTP, retrying transient failures.

    Args:
        recipient: One address or several, separated by comma or semicolon
        subject: Email subject line
        body: Plain-text body
        bcc: Optional BCC recipients
        xarf_attachment: Optional X-ARF report as string or bytes
        max_retries: Total number of send attempts
        retry_delay: Initial delay between attempts in seconds, multiplied by
            BACKOFF_FACTOR after each retry
        timeout: SMTP connection timeout in seconds

    Returns:
        (True, None) on success, otherwise (False, error text). The error is an
        UncertainSendError when the delivery outcome is unknown.
    """
    log = _log_sink(recipient)

    def build(recipients: list[str]) -> Message:
        _check_smtp_settings()
        return _create_mime_message(recipients, subject, body, xarf_attachment)

    # Pass the primary recipients so a refused BCC copy does not fail the whole
    # report (which would re-send to the abuse contact next run).
    result = send_with_retry(
        _smtp_config(timeout),
        build,
        SMTP_SENDER,
        recipient,
        bcc,
        max_retries=max_retries,
        retry_delay=retry_delay,
        backoff_factor=BACKOFF_FACTOR,
        log=log,
    )
    if result.ok:
        _log_refusals(result.report)
        # The caller (process_single_alert) logs success.
        return True, None
    return False, result.error


def _log_refusals(report: DeliveryReport) -> None:
    """Log refused recipients of an otherwise delivered report."""
    if report.refused_primary:
        # Other primary recipients accepted the mail, so it was delivered; a
        # failed result would send it to them again on the next run.
        print_config_info(f"Partial delivery, primary recipient(s) refused: {', '.join(report.refused_primary)}")
    elif report.refused_other:
        print_config_info(f"BCC copy refused (report delivered to abuse contact): {', '.join(report.refused_other)}")


def _create_mime_message(
    recipients: list[str],
    subject: str,
    body: str,
    xarf_attachment: str | bytes | None = None,
) -> Message:
    """Build the message; header values are sanitized to a single line.

    With an X-ARF report the layout follows the XARF e-mail transport guide
    (RFC 6522 multipart/report with feedback-report type): text, feedback
    headers, JSON payload. Without one it is a plain text mail.
    """
    parts = _xarf_parts(xarf_attachment) if xarf_attachment else []
    return build_message(
        sender_name=SENDER_NAME,
        sender_address=SMTP_SENDER,
        recipients=recipients,
        subject=subject,
        body=body,
        report_type="feedback-report" if xarf_attachment else None,
        parts=parts,
        boundary_prefix="=_xarf_",
    )


def _xarf_parts(xarf_attachment: str | bytes) -> list[Message]:
    """Return the feedback-report part and the base64 JSON payload 'xarf.json'."""
    feedback = MIMEBase("message", "feedback-report")
    feedback.set_payload(f"Feedback-Type: xarf\nUser-Agent: crowdsec-abuse-reporter/{VERSION}\nVersion: 1\n")
    feedback.add_header("Content-Disposition", "inline")

    payload = make_attachment(xarf_attachment, "application/json", "xarf.json")
    print_debug("X-ARF attachment added to email")
    return [feedback, payload]


def _send_smtp_message(
    msg: Message,
    all_recipients: list[str],
    primary_recipients: list[str],
    timeout: int = SMTP_TIMEOUT,
) -> None:
    """Send the message over a freshly opened SMTP connection.

    Raises:
        smtplib.SMTPRecipientsRefused: Every primary recipient was refused.
        gillbates_smtp_client.SendOutcomeUncertainError: The connection failed mid-transaction.
    """
    report = send_message(_smtp_config(timeout), msg, SMTP_SENDER, all_recipients, primary_recipients, log=_log_sink())
    _log_refusals(report)


def _format_recipient_errors(smtp_error: smtplib.SMTPRecipientsRefused) -> str:
    """Format per-recipient refusals as 'addr: code message' joined by '; '."""
    return format_recipient_errors(smtp_error)
