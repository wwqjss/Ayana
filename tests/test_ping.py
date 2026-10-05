"""命令帮助烟测（不导入 aiohttp 依赖）。"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestHelp(unittest.TestCase):
    def test_qqbot_has_core_commands(self):
        src = (ROOT / "ayana" / "qqbot.py").read_text(encoding="utf-8")
        for cmd in ("/ping", "/status", "/investigate", "/approve", "/health"):
            self.assertIn(cmd, src)

    def test_no_public_send_route_in_web(self):
        src = (ROOT / "ayana" / "web.py").read_text(encoding="utf-8")
        self.assertNotIn('add_post("/send"', src)


if __name__ == "__main__":
    unittest.main()
