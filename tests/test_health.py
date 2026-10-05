"""v0.1 遗留测试：改为纯逻辑烟测，不依赖 aiohttp。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana import VERSION


class TestVersion(unittest.TestCase):
    def test_version(self):
        self.assertRegex(VERSION, r"^\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
