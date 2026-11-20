#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/version.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Application version and build revision."""

import os
import tomllib
from pathlib import Path


def _version_from_pyproject() -> str | None:
    """Read the repository version for direct, non-container runs."""
    # parents[1] is this tool's own directory, which holds its pyproject.toml.
    path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle).get("project", {}).get("version")
    except OSError, tomllib.TOMLDecodeError:
        return None
    return value.strip() if isinstance(value, str) and value.strip() else None


# Container builds inject both values. Direct repository runs obtain their
# version from this tool's pyproject.toml and use "dev" as the commit marker.
VERSION = os.environ.get("APP_VERSION") or _version_from_pyproject() or "dev"
GIT_SHA = os.environ.get("GIT_SHA", "dev")
