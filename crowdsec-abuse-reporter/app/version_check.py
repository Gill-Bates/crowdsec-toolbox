#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/version_check.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#
"""Startup check for a newer crowdsec-toolbox GitHub release. Identical in both tools."""

import re
from typing import Any

import httpx

REPO_SLUG = "Gill-Bates/crowdsec-toolbox"
# One vX.Y.Z tag releases both tools with the same version (see release.yml), so the
# repository's latest GitHub release is the right reference for each of them.
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPO_SLUG}/releases/latest"
RELEASES_URL = f"https://github.com/{REPO_SLUG}/releases/latest"
TIMEOUT_SECONDS = 3.0

_VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?P<pre>[-+.]?[0-9A-Za-z.+-]*)$")

VersionKey = tuple[tuple[int, int, int], int, tuple[tuple[int, int | str], ...]]


def parse_version(raw: Any) -> VersionKey | None:
    """Return a sortable key for a version string, or None if unparsable.

    Follows SemVer precedence: a pre-release suffix sorts below the plain release of the same
    numbers, pre-release stages compare piecewise ("rc2" < "rc10") and build metadata is ignored.
    """
    if not isinstance(raw, str):
        return None

    match = _VERSION_RE.match(raw.strip())
    if not match:
        return None

    major, minor, patch = (int(part or 0) for part in match.group(1, 2, 3))
    pre = match.group("pre").split("+", 1)[0]
    pre_parts = tuple(
        (0, int(token)) if token.isdigit() else (1, token.lower()) for token in re.findall(r"\d+|[A-Za-z]+", pre)
    )
    return (major, minor, patch), 0 if pre_parts else 1, pre_parts


def fetch_latest_version() -> str | None:
    """Return the latest release tag, or None on any failure."""
    try:
        response = httpx.get(
            LATEST_RELEASE_API,
            timeout=TIMEOUT_SECONDS,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "crowdsec-toolbox-version-check",
            },
        )
        response.raise_for_status()
        tag = response.json().get("tag_name")
    except Exception:
        # Offline, rate limit or bad JSON must never affect startup.
        return None
    return tag if isinstance(tag, str) else None


def build_version_message(running: str, latest_tag: str | None) -> tuple[str, str] | None:
    """Return (text, colour) with colour in {"green", "yellow"}, or None to stay silent."""
    running_key = parse_version(running)
    latest_key = parse_version(latest_tag)
    if running_key is None or latest_key is None:
        return None
    latest = str(latest_tag).strip().removeprefix("v")
    if latest_key > running_key:
        return (
            f"A new version is available: v{latest} (running: v{running.removeprefix('v')}) - {RELEASES_URL}",
            "yellow",
        )
    if latest_key == running_key:
        return "Your version is up to date.", "green"
    return f"Your version (v{running.removeprefix('v')}) is newer than the latest release.", "yellow"


def version_notice(running: str, use_color: bool) -> str | None:
    """Return the ready-to-print notice line (with ANSI codes if requested), or None."""
    # A "dev" build has nothing to compare, so it must not cost a request.
    if parse_version(running) is None:
        return None
    message = build_version_message(running, fetch_latest_version())
    if message is None:
        return None
    text, color = message
    if not use_color:
        return text
    code = "\033[92m" if color == "green" else "\033[93m"
    return f"{code}{text}\033[0m"
