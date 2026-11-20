#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/tests/test_banner.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.banner import print_banner


class BannerTest(unittest.TestCase):
    def test_print_banner_centers_logo_and_metadata_on_one_canvas(self):
        buffer = io.StringIO()

        with redirect_stdout(buffer):
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


if __name__ == "__main__":
    unittest.main()
