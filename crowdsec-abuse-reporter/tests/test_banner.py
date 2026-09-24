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
    def test_print_banner_centers_metadata_within_visual_banner_width(self):
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            print_banner("1.2.3", "abcdef1234567890")

        lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
        title_line = next(
            line for line in lines if "crowdsec-abuse-reporter" in line
        )
        version_line = next(line for line in lines if "| by Gill-Bates" in line)
        banner_lines = lines[: lines.index(title_line)]

        min_indent = min(len(line) - len(line.lstrip()) for line in banner_lines)
        banner_width = max(len(line.rstrip()) for line in banner_lines)
        visual_width = banner_width - min_indent

        self.assertEqual(
            title_line,
            (" " * min_indent)
            + ">>> crowdsec-abuse-reporter | Automated Abuse Reporting <<<".center(
                visual_width
            ),
        )
        self.assertEqual(
            version_line,
            (" " * min_indent)
            + "v1.2.3 (abcdef1) | by Gill-Bates".center(visual_width),
        )
        disclaimer_line = next(
            line for line in lines if "not affiliated with CrowdSec" in line
        )
        self.assertEqual(
            disclaimer_line,
            (" " * min_indent)
            + "Independent project; not affiliated with CrowdSec".center(visual_width),
        )


if __name__ == "__main__":
    unittest.main()
