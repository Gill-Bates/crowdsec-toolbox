#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/kbinterrupt.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Keyboard interrupt handling module.
Provides graceful shutdown for SIGINT and SIGTERM signals.
"""

import signal
import sys

from .logger import print_warning


def handle_exit(signum: int, frame: object) -> None:
    """Handle SIGINT and SIGTERM signals for graceful shutdown."""
    print_warning(f"Interrupted by {signal.Signals(signum).name}. Exiting cleanly...")
    sys.exit(0)


def register_handlers() -> None:
    """Register signal handlers for clean application shutdown."""
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
