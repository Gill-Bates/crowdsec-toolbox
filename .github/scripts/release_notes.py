#!/usr/bin/env python3
#
# .github/scripts/release_notes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Compose one GitHub release note from both tool changelogs and cloc output."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ci_output import REPO_URL, log, print_header
from release_tags import VERSION_RE

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"


class ReleaseNotesError(Exception):
    """A release note cannot be assembled from the requested version inputs."""


def extract_release_section(changelog: str, version: str, source: str) -> tuple[str, str]:
    """Return the dated changelog heading and body for one release version."""
    heading_prefix = f"## [{version}] - "
    lines = changelog.splitlines()
    starts = [index for index, line in enumerate(lines) if line.startswith(heading_prefix)]
    if len(starts) != 1:
        raise ReleaseNotesError(f"{source}: expected one dated heading for version {version}")

    start = starts[0]
    end = next((index for index in range(start + 1, len(lines)) if lines[index].startswith("## [")), len(lines))
    body = "\n".join(lines[start + 1 : end]).strip()
    if not body:
        raise ReleaseNotesError(f"{source}: version {version} has an empty changelog section")
    return lines[start], body


def compose_release_notes(version: str, abuse_changelog: str, metrics_changelog: str, cloc: str) -> str:
    """Combine matching tool sections and append the cloc statistics."""
    if VERSION_RE.fullmatch(version) is None:
        raise ReleaseNotesError(f"invalid release version: {version!r}")
    abuse_heading, abuse_body = extract_release_section(abuse_changelog, version, "abuse reporter changelog")
    metrics_heading, metrics_body = extract_release_section(metrics_changelog, version, "metrics exporter changelog")
    if abuse_heading != metrics_heading:
        raise ReleaseNotesError("the tool changelogs have different release dates or headings")
    cloc_body = cloc.strip()
    if not cloc_body:
        raise ReleaseNotesError("cloc output is empty")

    return (
        f"{abuse_heading}\n\n"
        f"### Abuse Reporter\n\n{abuse_body}\n\n"
        f"### Metrics Exporter\n\n{metrics_body}\n\n"
        f"### Code Statistics (cloc)\n\n```\n{cloc_body}\n```\n"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--abuse-changelog", type=Path, required=True)
    parser.add_argument("--metrics-changelog", type=Path, required=True)
    parser.add_argument("--cloc-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)
    summary = (__doc__ or "").strip().splitlines()
    print_header(SCRIPT, summary[0] if summary else "", __author__, HELP_URL)

    args = build_parser().parse_args(argv)
    try:
        notes = compose_release_notes(
            args.version,
            args.abuse_changelog.read_text(encoding="utf-8"),
            args.metrics_changelog.read_text(encoding="utf-8"),
            args.cloc_file.read_text(encoding="utf-8"),
        )
        args.output.write_text(notes, encoding="utf-8")
    except (OSError, UnicodeError, ReleaseNotesError) as error:
        log("error", f"could not build release notes: {error}")
        return 1
    log("info", f"Wrote combined release notes for v{args.version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
