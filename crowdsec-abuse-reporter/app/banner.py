#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/banner.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Banner Module.
Displays the application header/logo.
"""

from __future__ import annotations

import sys

from .version import GIT_SHA as _DEFAULT_GIT_SHA
from .version import VERSION as _DEFAULT_VERSION


def print_banner(version: str | None = None, git_sha: str | None = None) -> None:
    """
    Print the ASCII banner to stdout and center the metadata below it.
    """
    if version is None:
        version = _DEFAULT_VERSION
    if git_sha is None:
        git_sha = _DEFAULT_GIT_SHA
    # Check if we have color support
    is_tty = sys.stdout.isatty()

    if is_tty:
        CYAN = "\033[96m"
        WHITE = "\033[97m"
        GRAY = "\033[90m"
        RESET = "\033[0m"
        BOLD = "\033[1m"
    else:
        CYAN = WHITE = GRAY = RESET = BOLD = ""

    banner = r"""
       _                                                    _
  __ _| |__  _   _ ___  ___       _ __ ___ _ __   ___  _ __| |_ ___ _ __
 / _` | '_ \| | | / __|/ _ \_____| '__/ _ \ '_ \ / _ \| '__| __/ _ \ '__|
| (_| | |_) | |_| \__ \  __/_____| | |  __/ |_) | (_) | |  | ||  __/ |
 \__,_|_.__/ \__,_|___/\___|     |_|  \___| .__/ \___/|_|   \__\___|_|
                                          |_|
    """

    lines = [line.rstrip() for line in banner.splitlines() if line.strip()]
    banner_width = max((len(line) for line in lines), default=40)
    min_indent = min(
        (len(line) - len(line.lstrip()) for line in lines),
        default=0,
    )
    visual_width = max(banner_width - min_indent, 1)

    title_text = ">>> crowdsec-abuse-reporter | Automated Abuse Reporting <<<"
    version_text = f"v{version} ({git_sha[:7]}) | by Gill-Bates"
    disclaimer_text = "Independent project; not affiliated with CrowdSec"

    def center_below_banner(text: str) -> str:
        return (" " * min_indent) + text.center(visual_width)

    print(f"{CYAN}{BOLD}{banner}{RESET}")
    print(f"{WHITE}{center_below_banner(title_text)}{RESET}")
    print(f"{GRAY}{center_below_banner(version_text)}{RESET}")
    print(f"{GRAY}{center_below_banner(disclaimer_text)}{RESET}\n")
