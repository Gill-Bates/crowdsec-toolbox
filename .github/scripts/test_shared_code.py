#!/usr/bin/env python3
#
# .github/scripts/test_shared_code.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Fail when the deliberately duplicated code of the two tools drifts apart.

The tools share no package, so these blocks are copies. Comparing the AST
ignores comments, formatting and docstrings, not behavior.
"""

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ABUSE = ROOT / "crowdsec-abuse-reporter" / "app"
METRICS = ROOT / "crowdsec-metrics-exporter" / "app"

# (abuse-reporter file, exporter file, names that must be identical)
SHARED = (
    ("banner.py", "banner.py", ("print_banner",)),
    (
        "version_check.py",
        "version_check.py",
        (
            "REPO_SLUG",
            "LATEST_RELEASE_API",
            "RELEASES_URL",
            "TIMEOUT_SECONDS",
            "_VERSION_RE",
            "parse_version",
            "fetch_latest_version",
            "build_version_message",
            "version_notice",
        ),
    ),
    ("version.py", "version.py", ("_version_from_pyproject", "VERSION", "GIT_SHA")),
    (
        "crowdsec.py",
        "crowdsec.py",
        (
            "LAPI_CREDENTIALS_HINT",
            "_RETRY_STATUS_CODES",
            "_LAPI_MAX_ATTEMPTS",
            "_read_lapi_credentials_file",
            "_resolve_lapi_credentials",
            "_get_lapi_base_url",
            "_build_lapi_client",
            "_format_lapi_auth_hint",
            "_auth_rejected",
            "_request_with_retry",
            "_get_lapi_token",
        ),
    ),
)


def _without_docstrings(node: ast.AST) -> ast.AST:
    """Drop docstrings from the node and everything nested in it, keeping the rest."""
    for child in ast.walk(node):
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and ast.get_docstring(child):
            child.body = child.body[1:] or [ast.Pass()]
    return node


def _definitions(path: Path) -> dict[str, str]:
    """Map each top-level function, class and assigned name to its AST dump."""
    found: dict[str, str] = {}
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.FunctionDef | ast.ClassDef):
            found[node.name] = ast.dump(_without_docstrings(node))
        elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            found[node.targets[0].id] = ast.dump(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            found[node.target.id] = ast.dump(node)
    return found


class SharedCodeTest(unittest.TestCase):
    def test_duplicated_blocks_stay_identical(self):
        for abuse_file, metrics_file, names in SHARED:
            abuse = _definitions(ABUSE / abuse_file)
            metrics = _definitions(METRICS / metrics_file)
            for name in names:
                with self.subTest(file=abuse_file, name=name):
                    self.assertIn(name, abuse)
                    self.assertIn(name, metrics)
                    self.assertEqual(abuse[name], metrics[name], f"{name} differs between the tools")


if __name__ == "__main__":
    unittest.main()
