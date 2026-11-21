#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/logger.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Logging module: one line per record, "<UTC time> | LEVEL | source | message".
WARNING and above go to stderr, the rest to stdout; colour only on a TTY.

The formatting core lives in the external ``gillbates-logging`` package; this module only
binds it to the exporter's log source and exposes the ``print_*`` helpers.
"""

import logging

from gillbates_logging import LineLog

from .config import LOG_LEVEL

LOG_SOURCE = "crowdsec_metrics"
LOG = LineLog(LOG_SOURCE)

logger = logging.getLogger(LOG_SOURCE)
# LOG_LEVEL is validated once in config.py; configure the root logger on import.
LOG.setup(LOG_LEVEL)


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
