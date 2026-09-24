#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/logger.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Logging module for colored console output.
Provides consistent logging with emoji icons and color coding.
"""

import logging
import os
import sys
from typing import ClassVar

from .config import LOG_LEVEL

# Plain ANSI escape codes, replacing colorama. Only emitted when stdout is a
# TTY and NO_COLOR is not set (https://no-color.org/); the reset code always
# follows a color code so no autoreset shim is needed.
_RESET = "\033[0m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"

_COLOR_ENABLED = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


class ColorFormatter(logging.Formatter):
    """Custom formatter for colored log output."""

    COLORS: ClassVar[dict[str, str]] = {
        "DEBUG": _CYAN,
        "INFO": _CYAN,
        "WARNING": _YELLOW,
        "ERROR": _RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with appropriate color."""
        message = super().format(record)
        if not _COLOR_ENABLED:
            return message
        color = getattr(record, "color", None) or self.COLORS.get(record.levelname, "")
        return f"{color}{message}{_RESET}"


# Create base logger
logger = logging.getLogger("crowdsec_metrics")
# LOG_LEVEL is validated once in config.py (raises SystemExit on an invalid
# value) and imported here as the single source of truth. Importing it from
# .config also pulls in config.py's settings.env loading, so a LOG_LEVEL set
# there is honoured regardless of the order in which callers import the two
# modules.
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
logger.propagate = False

# Console handler with colored output
console_handler = logging.StreamHandler(sys.stdout)
# Same line layout as WireBuddy: "2026-09-23 18:15:13 | INFO     | name | msg".
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
console_handler.setFormatter(ColorFormatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
logger.addHandler(console_handler)


def print_debug(message: str) -> None:
    """Print debug message (only visible when the logger level is DEBUG)."""
    logger.debug(f"🐛 {message}")


def print_info(message: str) -> None:
    """Print informational message with cyan color."""
    logger.info(f"ℹ {message}")


def print_success(message: str) -> None:
    """Print success message with green color."""
    logger.info(f"✓ {message}", extra={"color": _GREEN})


def print_warning(message: str) -> None:
    """Print warning message with yellow color."""
    logger.warning(f"⚠ {message}")


def print_error(message: str) -> None:
    """Print error message with red color."""
    logger.error(f"✗ {message}")
