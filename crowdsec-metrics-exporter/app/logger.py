#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/logger.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Logging module: one line per record, "<UTC time> | LEVEL | source | message".
WARNING and above go to stderr, the rest to stdout; colour only on a TTY.

The formatting core (``format_timestamp`` through ``setup_logging``, minus
the tool-specific tables) is a copy of the abuse reporter's logger.py and must
stay identical; see the app AGENTS.md and test_shared_code.py.
"""

import logging
import os
import sys
import unicodedata
from datetime import UTC, datetime

from .config import LOG_LEVEL

# Color codes for terminal output (only used when stdout/stderr is a TTY)
COLORS = {
    "DEBUG": "\033[36m",  # Cyan
    "INFO": "\033[37m",  # White
    "WARNING": "\033[93m",  # Yellow
    "ERROR": "\033[91m",  # Red
    "RESET": "\033[0m",  # Reset
}

# Level-column values; CRITICAL maps to ERROR.
TAGS = {
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "WARNING": "WARNING",
    "ERROR": "ERROR",
    "CRITICAL": "ERROR",
}

LOG_SOURCE = "crowdsec_metrics"
_STDERR_LEVELS = {"WARNING", "ERROR", "CRITICAL"}


def format_timestamp() -> str:
    """Return the UTC timestamp of a log line."""
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sanitize_log_message(message: object) -> str:
    """Escape control characters to keep log entries single-line."""
    escaped = []
    for char in str(message):
        if char == "\r":
            escaped.append("\\r")
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\t":
            escaped.append("\\t")
        elif unicodedata.category(char) == "Cc":
            escaped.append(f"\\x{ord(char):02x}")
        elif char in {"\u2028", "\u2029"}:
            escaped.append(f"\\u{ord(char):04x}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _format_line(tag: str, message: str) -> str:
    return f"{format_timestamp()} | {tag:<8} | {LOG_SOURCE} | {_sanitize_log_message(message)}"


def _write_line(level: str, line: str) -> None:
    """Write a formatted line to stderr (WARNING and above) or stdout, coloured on a TTY."""
    stream = sys.stderr if level in _STDERR_LEVELS else sys.stdout
    if stream.isatty() and not os.environ.get("NO_COLOR"):
        line = f"{COLORS.get(level, COLORS['INFO'])}{line}{COLORS['RESET']}"
    print(line, file=stream)


class _AppLogFormatter(logging.Formatter):
    """Render a stdlib record as one app log line, traceback appended after ` | `."""

    def format(self, record: logging.LogRecord) -> str:
        message = _sanitize_log_message(record.getMessage())
        # Without this, logger.exception() would drop the traceback entirely.
        if record.exc_info:
            message = f"{message} | {_sanitize_log_message(self.formatException(record.exc_info))}"
        if record.stack_info:
            message = f"{message} | {_sanitize_log_message(record.stack_info)}"
        return _format_line(TAGS.get(record.levelname, TAGS["INFO"]), message)


class _SplitStreamHandler(logging.Handler):
    """WARNING and above to stderr, the rest to stdout; colour only on a TTY."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            _write_line(record.levelname, self.format(record))
        except Exception:
            self.handleError(record)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logging once so module-level ``logger.*`` calls are emitted. Idempotent."""
    root = logging.getLogger()
    if getattr(root, "_app_logging_configured", False):
        return

    resolved = getattr(logging, str(level).upper(), None)
    if not isinstance(resolved, int):
        resolved = logging.INFO

    handler = _SplitStreamHandler()
    handler.setFormatter(_AppLogFormatter())

    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(resolved)

    # Keep third-party HTTP libraries quiet unless explicitly debugging.
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(max(resolved, logging.WARNING))

    root._app_logging_configured = True  # noqa: SLF001 marker attribute on the root logger


logger = logging.getLogger(LOG_SOURCE)
# LOG_LEVEL is validated once in config.py; configure the root logger on import.
setup_logging(LOG_LEVEL)


def print_debug(message: str) -> None:
    """Log a debug message (only visible when the log level is DEBUG)."""
    logger.debug(message)


def print_info(message: str) -> None:
    """Log an informational message."""
    logger.info(message)


def print_success(message: str) -> None:
    """Log a success message at INFO level."""
    logger.info(message)


def print_warning(message: str) -> None:
    """Log a warning."""
    logger.warning(message)


def print_error(message: str) -> None:
    """Log an error."""
    logger.error(message)
