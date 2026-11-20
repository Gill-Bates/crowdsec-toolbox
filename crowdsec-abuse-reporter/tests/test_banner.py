#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/tests/test_banner.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import io
import sys
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import version_check
from app.banner import print_banner


class BannerTest(unittest.TestCase):
    def test_print_banner_centers_logo_and_metadata_on_one_canvas(self):
        buffer = io.StringIO()

        with patch.object(version_check, "fetch_latest_version", return_value=None), redirect_stdout(buffer):
            print_banner("1.2.3", "abcdef1234567890")

        self.assertTrue(buffer.getvalue().endswith("\n\n"))
        lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
        title_line = next(line for line in lines if "crowdsec-abuse-reporter" in line)
        version_line = next(line for line in lines if "| by Gill-Bates" in line)
        banner_lines = lines[: lines.index(title_line)]
        disclaimer_line = next(line for line in lines if "not affiliated with CrowdSec" in line)
        canvas_width = max(map(len, [*banner_lines, title_line, version_line, disclaimer_line]))

        self.assertEqual(len(title_line), canvas_width)
        self.assertTrue(all(len(line) == canvas_width for line in banner_lines))
        self.assertEqual(title_line, ">>> crowdsec-abuse-reporter | Automated Abuse Reporting <<<".center(canvas_width))
        self.assertEqual(version_line, "v1.2.3 (abcdef1) | by Gill-Bates".center(canvas_width))
        self.assertEqual(disclaimer_line, "Independent project; not affiliated with CrowdSec".center(canvas_width))

    def _banner_output(self, running, latest):
        buffer = io.StringIO()
        with patch.object(version_check, "fetch_latest_version", return_value=latest), redirect_stdout(buffer):
            print_banner(running, "abcdef1234567890")
        return buffer.getvalue()

    def test_notice_follows_the_banner_and_compares_semantically(self):
        out = self._banner_output("1.9.0", "v1.10.0")
        self.assertTrue(
            out.endswith(f"A new version is available: v1.10.0 (running: v1.9.0) - {version_check.RELEASES_URL}\n\n")
        )
        self.assertIn("Independent project", out.split("A new version")[0])
        self.assertTrue(self._banner_output("1.0.4", "v1.0.4").endswith("Your version is up to date.\n\n"))
        self.assertTrue(self._banner_output("1.2.0-rc1", "v1.2.0").count("A new version is available: v1.2.0") == 1)

    def test_notice_stays_silent_on_failure_or_dev_build(self):
        self.assertTrue(self._banner_output("1.0.4", None).rstrip(" \n").endswith("not affiliated with CrowdSec"))
        with patch.object(version_check, "fetch_latest_version") as fetch:
            self.assertTrue(self._banner_output("dev", "v9.0.0").rstrip(" \n").endswith("not affiliated with CrowdSec"))
            fetch.assert_not_called()

    def test_fetch_failures_return_none_and_send_a_timeout(self):
        seen = {}

        def fake_get(url, **kwargs):
            seen.update(kwargs, url=url)
            return unittest.mock.Mock(json=lambda: {"tag_name": "v2.0.0"})

        with patch.object(version_check.httpx, "get", fake_get):
            self.assertEqual(version_check.fetch_latest_version(), "v2.0.0")
        self.assertLessEqual(seen["timeout"], 5)
        self.assertTrue(seen["url"].endswith("/repos/Gill-Bates/crowdsec-toolbox/releases/latest"))
        for error in (version_check.httpx.ConnectError("offline"), ValueError("bad json")):
            with patch.object(version_check.httpx, "get", side_effect=error):
                self.assertIsNone(version_check.fetch_latest_version())

    def test_prerelease_precedence(self):
        parse = version_check.parse_version
        self.assertLess(parse("1.2.0-rc2"), parse("1.2.0-rc10"))
        self.assertLess(parse("1.2.0-rc1"), parse("1.2.0"))
        self.assertEqual(parse("1.2.0+b5"), parse("1.2.0"))
        self.assertIsNone(parse("nightly"))


if __name__ == "__main__":
    unittest.main()
