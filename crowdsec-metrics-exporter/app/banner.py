#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/app/banner.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Print the startup banner. Only TITLE differs from the sibling tool's copy."""

import os
import sys

from .version import GIT_SHA as _DEFAULT_GIT_SHA
from .version import VERSION as _DEFAULT_VERSION
from .version_check import version_notice

TITLE = ">>> crowdsec-metrics-exporter | Metrics Export Tool for CrowdSec <<<"


def print_banner(version: str | None = None, git_sha: str | None = None) -> None:
    """Print the centered logo and metadata, using color only for a terminal."""
    if version is None:
        version = _DEFAULT_VERSION
    if git_sha is None:
        git_sha = _DEFAULT_GIT_SHA
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if use_color:
        cyan, white, gray, reset, bold = "\033[96m", "\033[97m", "\033[90m", "\033[0m", "\033[1m"
    else:
        cyan = white = gray = reset = bold = ""

    banner = r"""
    ______                       _______
   / ____/________ _      ______/ / ___/___  _____
  / /   / ___/ __ \ | /| / / __  /\__ \/ _ \/ ___/
 / /___/ /  / /_/ / |/ |/ / /_/ /___/ /  __/ /__
 \____/_/   \____/|__/|__/\__,_//____/\___/\___/
    """
    lines = [line.rstrip() for line in banner.splitlines() if line.strip()]
    version_text = f"v{version} ({git_sha[:7]}) | by Gill-Bates"
    disclaimer = "Independent project; not affiliated with CrowdSec"
    canvas_width = max(
        max((len(line) for line in lines), default=40),
        len(TITLE),
        len(version_text),
        len(disclaimer),
    )
    # Center the logo as one block: centering each line separately would shift
    # lines of different length by different amounts and distort the ASCII art.
    logo_width = max((len(line) for line in lines), default=0)
    offset = (canvas_width - logo_width) // 2
    banner_text = "\n".join((" " * offset + line).ljust(canvas_width) for line in lines)
    output = (
        f"{cyan}{bold}{banner_text}{reset}\n"
        f"{white}{TITLE.center(canvas_width)}{reset}\n"
        f"{gray}{version_text.center(canvas_width)}{reset}\n"
        f"{gray}{disclaimer.center(canvas_width)}{reset}\n\n"
    )
    sys.stdout.write(output)
    # Flush first so the banner is visible while the release lookup runs.
    sys.stdout.flush()
    notice = version_notice(version, use_color)
    if notice:
        sys.stdout.write(notice + "\n\n")
