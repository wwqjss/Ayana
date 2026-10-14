"""发行版数据隔离：全新安装不得包含个人资产/业务检查/自动 runbook。"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana import business, health, runbook, verify_profiles
from ayana.main import DEFAULT_ASSETS, ensure_promconfig_admin_perms, seed_assets
from ayana.db import Database

ROOT = Path(__file__).resolve().parents[1]

PERSONAL_TOKENS = (
    "nerv",
    "sora",
    "kanata",
    "hysteria",
    "frps",
    "harbor-core",
    "youtube",
    "google",
    "yomi",
)


class ReleaseDataIsolationTests(unittest.TestCase):
    """静态扫描：源码/知识/种子不得含个人环境业务定义。"""

    def test_required_checks_empty(self):
        self.assertEqual(health.REQUIRED_CHECKS, {})

    def test_runbook_empty(self):
        self.assertEqual(runbook.RUNBOOK, [])

    def test_no_nerv_specific_verify_profile(self):
        for prof in verify_profiles.PROFILES.values():
            blob = (prof.id + prof.name + str(prof.checks)).lower()
            for tok in ("nerv", "frps", "sora", "hysteria"):
                self.assertNotIn(tok, blob, f"profile {prof.id} leaks {tok}")

    def test_default_assets_are_demo_only(self):
        ids = [a["id"] for a in DEFAULT_ASSETS]
        for aid in ids:
            self.assertTrue(aid.startswith("demo-"), aid)
            self.assertNotIn(aid.lower(), PERSONAL_TOKENS)

    def test_knowledge_files_have_no_personal_assets(self):
        kdir = ROOT / "knowledge"
        if not kdir.is_dir():
            return
        for p in kdir.glob("*.md"):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            # 允许文档用「示例」说明，但不得绑定 nerv:xxx / sora:xxx 对象
            self.assertNotRegex(
                text,
                r"\b(nerv|sora|kanata|yomi):[a-z0-9_-]+",
                f"{p.name} binds personal asset objects",
            )

    def test_health_module_no_hardcoded_asset_ids(self):
        src = (ROOT / "ayana" / "health.py").read_text(encoding="utf-8")
        # REQUIRED_CHECKS 字面量不得再出现个人资产
        self.assertNotRegex(src, r'"nerv"\s*:')
        self.assertNotRegex(src, r'"sora"\s*:')
        self.assertNotRegex(src, r'"kanata"\s*:')


class FreshInstallDbTests(unittest.TestCase):
    def test_seed_only_demo_assets(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        seed_assets(db)
        ensure_promconfig_admin_perms(db)
        rows = {r["id"] for r in db.query("SELECT id FROM assets")}
        self.assertEqual(rows, {"demo-web", "demo-db"})
        self.assertFalse(rows & {"nerv", "sora", "kanata", "yomi"})

    def test_ssh_asset_add_does_not_create_business_checks(self):
        """新增 SSH 资产不得自动生成业务检查。"""
        from ayana.db import now as db_now

        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        seed_assets(db)
        # 模拟用户登记与个人环境同名的资产
        db.execute(
            "INSERT INTO assets(id,display_name,read_alias,write_alias,prom_asset,host,enabled,created_at,updated_at)"
            " VALUES('nerv','nerv','nerv','nerv-exec','nerv','10.0.0.1',1,?,?)",
            (db_now(), db_now()),
        )
        checks = db.query("SELECT id FROM checks")
        self.assertEqual(len(checks), 0)
        # 业务项来自 REQUIRED_CHECKS + Prometheus；当前 REQUIRED_CHECKS 为空
        self.assertIsNone(health.REQUIRED_CHECKS.get("nerv"))

    def test_prometheus_checks_without_prom_or_requirements(self):
        import asyncio

        class EmptyProm:
            async def query_range_vector(self, *a, **k):
                return []

        async def run():
            return await business.prometheus_checks(
                EmptyProm(), {"id": "nerv", "prom_asset": "nerv"}
            )

        items, errors = asyncio.run(run())
        self.assertEqual(items, [])
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
