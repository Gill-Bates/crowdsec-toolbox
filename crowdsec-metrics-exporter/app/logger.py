#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/logger.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Logging module: one line per record, "<UTC time> | LEVEL | source | message".
WARNING and above go to stderr, the rest to stdout; colour only on a TTY.
"""

import logging
import os
import sys
import time
from typing import ClassVar

from .config import LOG_LEVEL

_RESET = "\033[0m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_RED = "\033[31m"


LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S UTC"


def _escape(text: str) -> str:
    """Keep a log entry on one line."""
    return text.replace("\r", "\\r").replace("\n", "\\n")


class ColorFormatter(logging.Formatter):
    """Single-line formatter; colours are decided per stream at emit time."""

    # Log timestamps are always UTC, independent of the container timezone.
    converter = staticmethod(time.gmtime)

    COLORS: ClassVar[dict[str, str]] = {"DEBUG": _CYAN, "INFO": _CYAN, "WARNING": _YELLOW, "ERROR": _RED}

    def __init__(self, *args, color: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.color = color

    def format(self, record: logging.LogRecord) -> str:
        """Format a record on one line, with the traceback appended after ` | `."""
        record.message = _escape(record.getMessage())
        line = f"{self.formatTime(record, self.datefmt)} | {record.levelname:<8} | {record.name} | {record.message}"
        if record.exc_info:
            line += f" | {_escape(self.formatException(record.exc_info))}"
        if not self.color:
            return line
        return f"{self.COLORS.get(record.levelname, '')}{line}{_RESET}"


class _SplitStreamHandler(logging.Handler):
    """WARNING and above to stderr, everything else to stdout."""

    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(ColorFormatter(datefmt=LOG_DATE_FORMAT))

    def emit(self, record: logging.LogRecord) -> None:
        stream = sys.stderr if record.levelno >= logging.WARNING else sys.stdout
        try:
            self.formatter.color = stream.isatty() and not os.environ.get("NO_COLOR")  # type: ignore[union-attr]
            stream.write(self.format(record) + "\n")
            stream.flush()
        except Exception:
            self.handleError(record)


logger = logging.getLogger("crowdsec_metrics")
# LOG_LEVEL is validated once in config.py and imported as the single source of truth.
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
logger.propagate = False
logger.addHandler(_SplitStreamHandler())


def print_debug(message: str) -> None:
    """Log a debug message (only visible when the logger level is DEBUG)."""
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
