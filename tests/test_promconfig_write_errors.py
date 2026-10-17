"""promconfig 写权限与默认路径：注册失败不得只显示 error。"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.promconfig import LocalConfigFS, PromConfigError, build_prom_config_service
from ayana.db import Database


class WriteDeniedTests(unittest.TestCase):
    def test_permission_error_mapped(self):
        import os

        tmp = Path(tempfile.mkdtemp())
        locked = tmp / "locked"
        locked.mkdir()
        os.chmod(locked, 0o500)  # 只读目录
        fs = LocalConfigFS(locked / "sub")
        try:
            asyncio.run(fs.write_text("file_sd/t.json", "[]"))
            self.skipTest("OS did not enforce readonly dir (Windows)")
        except PromConfigError as e:
            self.assertIn(e.code, ("write_denied", "write_failed", "bad_path"))
        finally:
            try:
                os.chmod(locked, 0o700)
            except OSError:
                pass

    def test_default_local_dir_under_db_path(self):
        tmp = Path(tempfile.mkdtemp())
        data = tmp / "data"
        data.mkdir()
        db = Database(data / "t.db")
        self.addCleanup(db.close)
        cfg = {
            "base_dir": str(tmp / "etc"),
            "db_path": str(data / "t.db"),
            "prometheus_config": {"local_dir": "prometheus", "require_promtool": False},
        }
        svc = build_prom_config_service(db, cfg)
        desc = svc.fs.describe()
        self.assertIn("data", desc["base_dir"])
        self.assertIn("prometheus", desc["base_dir"])

    def test_promtool_missing_and_config_missing_codes(self):
        tmp = Path(tempfile.mkdtemp())
        db = Database(tmp / "t.db")
        self.addCleanup(db.close)
        cfg = {
            "base_dir": str(tmp),
            "db_path": str(tmp / "t.db"),
            "prometheus_config": {"local_dir": "prom", "require_promtool": True},
        }
        svc = build_prom_config_service(db, cfg)

        async def go():
            return await svc.add_target(address="127.0.0.1:9100", labels={"asset": "x"}, actor="t")

        with self.assertRaises(PromConfigError) as ctx:
            asyncio.run(go())
        self.assertIn(ctx.exception.code, ("prom_config_missing", "promtool_not_found", "promtool_failed"))


if __name__ == "__main__":
    unittest.main()
