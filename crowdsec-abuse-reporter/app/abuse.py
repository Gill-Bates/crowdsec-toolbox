#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/abuse.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import re
import smtplib
import ssl
import time
from contextlib import contextmanager
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .config import (
    SENDER_NAME,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_SENDER,
    SMTP_SERVER,
    SMTP_USE_TLS,
    SMTP_USERNAME,
    SMTP_VERIFY_SSL,
)
from .logger import print_config_info, print_mail_error

MAX_RETRIES = 3
RETRY_DELAY = 5.0
BACKOFF_FACTOR = 1.5
SMTP_TIMEOUT = 30

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


@contextmanager
def smtp_connection(timeout: int = SMTP_TIMEOUT):
    """
    SMTP connection context manager with connection pooling capabilities.

    Args:
        timeout: SMTP connection timeout in seconds

    Yields:
        SMTP connection object configured with TLS and authentication
    """
    # A half-configured credential pair is a configuration error, not a request
    # to send anonymously. Failing loudly beats silently attempting an
    # unauthenticated send that the relay may accept and treat as open relay.
    if bool(SMTP_USERNAME) != bool(SMTP_PASSWORD):
        raise RuntimeError(
            "SMTP_USERNAME and SMTP_PASSWORD must either both be set or both be "
            "empty."
        )

    # Refuse to transmit credentials over an unencrypted channel. Without TLS,
    # SMTP AUTH sends the username/password base64-encoded but in the clear,
    # which would expose them (and the report contents) on the transport path.
    if SMTP_USERNAME and not SMTP_USE_TLS:
        raise RuntimeError(
            "SMTP authentication requires TLS. Set SMTP_USE_TLS=true or clear "
            "SMTP_USERNAME/SMTP_PASSWORD."
        )

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=timeout)
    try:
        if SMTP_USE_TLS:
            context = ssl.create_default_context()
            if not SMTP_VERIFY_SSL:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            verify_note = "with" if SMTP_VERIFY_SSL else "without"
            print_config_info(
                f"Started TLS session ({verify_note} certificate verification)"
            )

        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            print_config_info(f"Authenticated as {SMTP_USERNAME}")

        yield server
    finally:
        # Gracefully close connection
        try:
            server.quit()
        except Exception:
            server.close()


def validate_email(email: str) -> bool:
    """
    Validate email format using regex pattern.

    Args:
        email: Email address to validate

    Returns:
        Boolean indicating if email format is valid
    """
    return bool(EMAIL_REGEX.match(email.strip()))


def split_recipients(recipients_str: str) -> list[str]:
    """
    Split recipients string into list of validated email addresses.

    Args:
        recipients_str: Comma or semicolon separated email addresses

    Returns:
        List of cleaned and validated email addresses
    """
    if not recipients_str:
        return []

    # Normalize separators and split
    recipients = recipients_str.replace(";", ",").split(",")

    # Clean whitespace and filter empty strings
    cleaned_recipients = [
        recipient.strip() for recipient in recipients if recipient.strip()
    ]

    # Validate email format using regex
    valid_recipients = [addr for addr in cleaned_recipients if validate_email(addr)]

    if len(valid_recipients) != len(cleaned_recipients):
        invalid_count = len(cleaned_recipients) - len(valid_recipients)
        print_config_info(f"Filtered out {invalid_count} invalid email addresses")

    return valid_recipients


def _sanitize_header(value: object) -> str:
    """Normalize header values to a single safe line."""
    return " ".join(str(value).splitlines()).strip()


def _normalize_recipients(value: str | list[str] | None) -> list[str]:
    """Normalize recipient input through the same validation path."""
    if value is None:
        return []
    if isinstance(value, str):
        return split_recipients(value)

    normalized = []
    for item in value:
        normalized.extend(split_recipients(str(item)))
    return normalized


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
    """
    Send abuse report email via SMTP with comprehensive error handling and retry logic.

    Args:
        recipient: Single recipient or comma-separated recipients
        subject: Email subject line
        body: Email body content
        bcc: Optional list of BCC recipients
        xarf_attachment: Optional X-ARF report as string or bytes
        max_retries: Maximum number of retry attempts
        retry_delay: Initial delay between retries in seconds
        timeout: SMTP connection timeout in seconds

    Returns:
        Tuple of (success_status, error_message)
    """
    # Parse and validate recipients once; the same recipient set is reused
    # across retries.
    recipients = _normalize_recipients(recipient)
    if not recipients:
        return False, "No valid recipients provided"

    all_recipients = recipients + _normalize_recipients(bcc)

    current_retry_delay = retry_delay

    for attempt in range(max_retries):
        try:
            # Log retry attempts
            if attempt > 0:
                print_config_info(f"Retry attempt {attempt + 1}/{max_retries}")

            # Log recipient information (truncated for privacy)
            recipient_preview = ", ".join(recipients[:2])
            if len(recipients) > 2:
                recipient_preview += f"... (+{len(recipients) - 2} more)"
            print_config_info(
                f"Sending to {len(recipients)} recipient(s): {recipient_preview}"
            )

            # Create MIME message
            msg = _create_mime_message(recipients, subject, body, xarf_attachment)

            # Send email via SMTP (always use pooled connection for efficiency).
            # Pass the primary recipients so a refused BCC copy does not fail the
            # whole report (which would re-send to the abuse contact next run).
            _send_smtp_message(msg, all_recipients, recipients, timeout)

            # Note: Success logging is handled by the caller (process_single_alert)
            # to avoid duplicate log messages
            return True, None

        except smtplib.SMTPRecipientsRefused as e:
            error_msg = f"Recipients refused: {_format_recipient_errors(e)}"
            print_mail_error(recipient, error_msg)
            # Don't retry for recipient errors
            return False, error_msg

        except smtplib.SMTPAuthenticationError as e:
            error_msg = f"SMTP authentication failed: {e}"
            print_mail_error(recipient, error_msg)
            return False, error_msg

        except smtplib.SMTPConnectError as e:
            error_msg = f"SMTP connect error (server rejected connection): {e}"
            print_mail_error(recipient, error_msg)
            # A 4xx greeting (typically 421 "service not available") is a
            # transient refusal and belongs in the bounded backoff below.
            # 5xx means the server refuses us outright — do not retry.
            transient = isinstance(e.smtp_code, int) and 400 <= e.smtp_code < 500
            if transient and attempt < max_retries - 1:
                print_config_info(f"Retrying in {current_retry_delay:.1f} seconds...")
                time.sleep(current_retry_delay)
                current_retry_delay *= BACKOFF_FACTOR
                continue
            return False, error_msg

        except (smtplib.SMTPException, ConnectionError, TimeoutError) as e:
            error_msg = (
                f"SMTP/connection error (attempt {attempt + 1}/{max_retries}): {e}"
            )
            print_mail_error(recipient, error_msg)

            # Retry for temporary failures with exponential backoff
            if attempt < max_retries - 1:
                print_config_info(f"Retrying in {current_retry_delay:.1f} seconds...")
                time.sleep(current_retry_delay)
                current_retry_delay *= BACKOFF_FACTOR
            else:
                return False, error_msg

        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            print_mail_error(recipient, error_msg)
            return False, error_msg

    # Only reachable when max_retries <= 0, i.e. the loop never ran.
    return False, f"All {max_retries} attempts failed"


def _create_mime_message(
    recipients: list[str],
    subject: str,
    body: str,
    xarf_attachment: str | bytes | None = None,
) -> MIMEMultipart:
    """
    Create MIME multipart message with headers and attachments.

    Args:
        recipients: List of recipient email addresses
        subject: Email subject
        body: Email body content
        xarf_attachment: Optional X-ARF attachment

    Returns:
        Configured MIMEMultipart message
    """
    msg = MIMEMultipart()

    # Set message headers
    from_header = f"{SENDER_NAME} <{SMTP_SENDER}>" if SENDER_NAME else SMTP_SENDER
    msg["From"] = _sanitize_header(from_header)

    # Only the first recipient is shown; the rest stay in the SMTP envelope.
    msg["To"] = _sanitize_header(recipients[0])

    msg["Subject"] = _sanitize_header(subject)

    # Attach text body
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # Attach X-ARF report if provided
    if xarf_attachment:
        _attach_xarf_report(msg, xarf_attachment)

    return msg


def _attach_xarf_report(msg: MIMEMultipart, xarf_attachment: str | bytes) -> None:
    """
    Attach X-ARF report to the MIME message.

    Args:
        msg: MIMEMultipart message
        xarf_attachment: X-ARF report data as string or bytes

    Raises:
        ValueError: If attachment data is invalid
    """
    if not xarf_attachment:
        raise ValueError("X-ARF attachment data cannot be empty")

    if isinstance(xarf_attachment, str):
        attachment_data = xarf_attachment.encode("utf-8")
    else:
        attachment_data = xarf_attachment

    attachment = MIMEApplication(
        attachment_data, _subtype="x-arf+json", Name="abuse-report.xarf"
    )
    attachment.add_header(
        "Content-Disposition", 'attachment; filename="abuse-report.xarf"'
    )

    msg.attach(attachment)
    print_config_info("X-ARF attachment added to email")


def _send_smtp_message(
    msg: MIMEMultipart,
    all_recipients: list[str],
    primary_recipients: list[str],
    timeout: int = SMTP_TIMEOUT,
) -> None:
    """
    Send message via SMTP connection with pooling.

    Args:
        msg: MIMEMultipart message to send
        all_recipients: Complete list of recipients (To + BCC)
        primary_recipients: The abuse-contact recipients (excluding BCC)
        timeout: SMTP connection timeout in seconds
    """
    with smtp_connection(timeout=timeout) as server:
        # sendmail() only raises when *every* recipient is refused. With more
        # than one recipient (abuse contact + BCC) a partial refusal returns a
        # dict and would otherwise be silently treated as full success.
        refused = server.sendmail(
            from_addr=SMTP_SENDER, to_addrs=all_recipients, msg=msg.as_string()
        )
        if not refused:
            return

        # Fail only when a primary (abuse-contact) recipient was refused — that
        # means the report did not reach its target. A refused BCC copy must not
        # fail the send, or the report would be re-sent to the abuse contact on
        # the next run (duplicate delivery).
        primary = set(primary_recipients)
        refused_primary = {addr: err for addr, err in refused.items() if addr in primary}
        if refused_primary:
            raise smtplib.SMTPRecipientsRefused(refused_primary)

        print_config_info(
            f"BCC copy refused (report delivered to abuse contact): "
            f"{', '.join(refused)}"
        )


def _format_recipient_errors(smtp_error: smtplib.SMTPRecipientsRefused) -> str:
    """
    Format SMTP recipient refusal errors into readable string.

    Args:
        smtp_error: SMTPRecipientsRefused exception

    Returns:
        Formatted error string
    """
    errors = []
    for recipient, (code, message) in smtp_error.recipients.items():
        errors.append(f"{recipient}: {code} {message}")

    return "; ".join(errors) if errors else str(smtp_error)
