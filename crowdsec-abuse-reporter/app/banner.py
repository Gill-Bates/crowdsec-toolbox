#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/banner.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Print the startup banner. Only TITLE differs from the sibling tool's copy."""

import gillbates_logging

from .version import GIT_SHA as _DEFAULT_GIT_SHA
from .version import VERSION as _DEFAULT_VERSION

TITLE = ">>> crowdsec-abuse-reporter | Automated Abuse Reporting <<<"
RELEASE_REPO = "Gill-Bates/crowdsec-toolbox"

_LOGO = r"""
    ______                       _______
   / ____/________ _      ______/ / ___/___  _____
  / /   / ___/ __ \ | /| / / __  /\__ \/ _ \/ ___/
 / /___/ /  / /_/ / |/ |/ / /_/ /___/ /  __/ /__
 \____/_/   \____/|__/|__/\__,_//____/\___/\___/
"""


def print_banner(version: str | None = None, git_sha: str | None = None) -> None:
    """Print the centered logo, metadata and the release notice; colour per the logging package."""
    if version is None:
        version = _DEFAULT_VERSION
    if git_sha is None:
        git_sha = _DEFAULT_GIT_SHA
    gillbates_logging.print_banner(
        _LOGO,
        TITLE,
        (f"v{version} ({git_sha[:7]}) | by Gill-Bates", "Independent project; not affiliated with CrowdSec"),
        release_repo=RELEASE_REPO,
        version=version,
    )
