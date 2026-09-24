#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/heartbeat.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
CrowdSec LAPI heartbeat check.

Runs a lightweight login-only check against the LAPI and writes
/data/api_heartbeat on success. The Docker HEALTHCHECK uses the age of
that file to detect a prolonged LAPI outage between main processing runs.
"""

import logging
import os
import sys
from pathlib import Path

from app.crowdsec import check_lapi_health
from app.logger import print_config_info, setup_logging

logger = logging.getLogger(__name__)

DATA_DIR = "/data"
_HEARTBEAT_FILE = Path(DATA_DIR) / "api_heartbeat"


def run_heartbeat() -> bool:
    """Check LAPI health, log the result, and update the heartbeat file.

    Returns True only when the LAPI is reachable AND the heartbeat file was
    refreshed. A failed file update is treated as a heartbeat failure: reporting
    success while /data/api_heartbeat stays stale would give the Docker
    HEALTHCHECK a contradictory signal and hide mount/permission problems.
    The file is only refreshed on success, so a stale file signals an outage.
    """
    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))

    healthy = check_lapi_health()

    # Failures go through the stdlib logger at ERROR severity: this process
    # feeds the container HEALTHCHECK, and log aggregation must be able to
    # alert on it by level rather than by matching INFO text.
    if not healthy:
        logger.error("LAPI heartbeat: UNREACHABLE — skipping file update")
        return False

    try:
        _HEARTBEAT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _HEARTBEAT_FILE.touch()
    except OSError as e:
        logger.error("Could not update %s: %s", _HEARTBEAT_FILE, e)
        return False

    print_config_info("LAPI heartbeat: OK")
    return True


if __name__ == "__main__":
    ok = run_heartbeat()
    sys.exit(0 if ok else 1)
