"""KANATA 升级兼容：required_checks / runbook 走配置；通用验证能力保留。"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana import health, runbook, verify_profiles
from ayana.business import prometheus_checks


class ConfigInjectionTests(unittest.TestCase):
    def tearDown(self):
        health.apply_required_checks({})
        runbook.apply_runbook_rules([])

    def test_required_checks_from_config(self):
        cfg = {
            "host-a": [
                {
                    "object": "web",
                    "metric": "probe_success",
                    "selector": {"asset": "host-a", "service": "web"},
                    "freshness_sec": 90,
                }
            ]
        }
        out = health.apply_required_checks(cfg)
        self.assertIn("host-a", out)
        self.assertEqual(out["host-a"][0]["object"], "web")
        self.assertEqual(health.REQUIRED_CHECKS["host-a"][0]["freshness_sec"], 90)

    def test_required_checks_ignores_garbage(self):
        out = health.apply_required_checks({"x": "not-a-list", "y": [{"no": 1}]})
        # {"no":1} 仍有 object 空串，被保留但不报错；非法类型丢弃
        self.assertNotIn("x", out)

    def test_runbook_rules_from_config(self):
        rules = [
            {
                "id": "rb_web_restart",
                "name": "web 不可达 → 重启",
                "asset_id": "host-a",
                "object_name": "web",
                "capability": "service.restart",
                "max_per_day": 2,
                "cooldown_sec": 600,
            }
        ]
        out = runbook.apply_runbook_rules(rules)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].id, "rb_web_restart")
        self.assertEqual(out[0].max_per_day, 2)
        self.assertIsNotNone(runbook.get_runbook_rule("rb_web_restart"))
        self.assertEqual(len(runbook.list_runbook()), 1)

    def test_prometheus_checks_uses_injected_requirements(self):
        health.apply_required_checks(
            {
                "host-a": [
                    {
                        "object": "web",
                        "metric": "probe_success",
                        "selector": {"asset": "host-a", "service": "web"},
                        "freshness_sec": 120,
                    }
                ]
            }
        )

        class EmptyProm:
            async def query_range_vector(self, *a, **k):
                return []

        async def run():
            return await prometheus_checks(EmptyProm(), {"id": "host-a", "prom_asset": "host-a"})

        items, _ = asyncio.run(run())
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "web")
        self.assertTrue(items[0]["required"])
        self.assertEqual(items[0]["source"], "prometheus")


class GenericCapabilityTests(unittest.TestCase):
    def test_service_restart_has_generic_profile(self):
        p = verify_profiles.profile_for_action(
            capability="service.restart", asset_id="any-host", object_id="any-svc"
        )
        self.assertIsNotNone(p)
        self.assertEqual(p.id, "svc.recover")
        self.assertEqual(p.expect, "up")

    def test_service_stop_profile(self):
        p = verify_profiles.profile_for_action(capability="service.stop")
        self.assertEqual(p.id, "svc.stop")

    def test_unknown_capability_still_blocked(self):
        self.assertIsNone(
            verify_profiles.profile_for_action(capability="shell.interactive")
        )

    def test_no_personal_asset_in_profiles(self):
        for prof in verify_profiles.PROFILES.values():
            blob = (prof.id + prof.name + str(prof.checks)).lower()
            for tok in ("nerv", "sora", "kanata", "frps", "hysteria"):
                self.assertNotIn(tok, blob)


class MigrationScriptTests(unittest.TestCase):
    def _write_legacy(self, tmp: Path, required_src: str, runbook_src: str):
        (tmp / "health.py").write_text(required_src, encoding="utf-8")
        (tmp / "runbook.py").write_text(runbook_src, encoding="utf-8")
        return tmp / "health.py", tmp / "runbook.py"

    def test_migrate_script_parses_legacy_and_writes_config(self):
        import subprocess
        import json

        tmp = Path(tempfile.mkdtemp())
        health_py, runbook_py = self._write_legacy(
            tmp,
            'REQUIRED_CHECKS = {\n'
            '  "host-a": [\n'
            '    {"object": "web", "metric": "probe_success",'
            '     "selector": {"asset": "host-a", "service": "web"}, "freshness_sec": 120},\n'
            '  ],\n'
            '}\n',
            "RUNBOOK = [\n"
            "    RunbookRule(\n"
            '        id="rb_x",\n'
            '        name="x",\n'
            '        asset_id="host-a",\n'
            '        object_name="web",\n'
            '        capability="service.restart",\n'
            "    ),\n"
            "]\n",
        )
        cfg_path = tmp / "config.json"
        cfg_path.write_text('{"http_port": 6200}', encoding="utf-8")
        script = Path(__file__).resolve().parents[1] / "scripts" / "migrate_monitor_config.py"
        r = subprocess.run(
            [
                sys.executable,
                str(script),
                "--legacy-health",
                str(health_py),
                "--legacy-runbook",
                str(runbook_py),
                "--config",
                str(cfg_path),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        self.assertEqual(data["http_port"], 6200)  # 不覆盖其它键
        self.assertIn("host-a", data["required_checks"])
        self.assertEqual(data["runbook_rules"][0]["id"], "rb_x")

    def test_dry_run_does_not_write(self):
        import subprocess

        tmp = Path(tempfile.mkdtemp())
        health_py, runbook_py = self._write_legacy(
            tmp,
            'REQUIRED_CHECKS = {"a": [{"object": "o", "metric": "probe_success", "selector": {}}]}\n',
            'RUNBOOK = [RunbookRule(id="r1", name="n", capability="service.restart")]\n',
        )
        cfg_path = tmp / "config.json"
        cfg_path.write_text("{}", encoding="utf-8")
        before = cfg_path.read_text(encoding="utf-8")
        script = Path(__file__).resolve().parents[1] / "scripts" / "migrate_monitor_config.py"
        r = subprocess.run(
            [sys.executable, str(script), "--legacy-health", str(health_py),
             "--legacy-runbook", str(runbook_py), "--config", str(cfg_path), "--dry-run"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(cfg_path.read_text(encoding="utf-8"), before)
        self.assertIn("migration preview", r.stdout)

    def test_parse_mismatch_aborts(self):
        """RunbookRule 数量与解析数不一致时必须失败，禁止静默丢失。"""
        import subprocess

        tmp = Path(tempfile.mkdtemp())
        health_py, runbook_py = self._write_legacy(
            tmp,
            "REQUIRED_CHECKS = {}\n",
            "RUNBOOK = [RunbookRule(id=dynamic_id, name='x', capability='service.restart')]\n",
        )
        cfg_path = tmp / "config.json"
        cfg_path.write_text("{}", encoding="utf-8")
        script = Path(__file__).resolve().parents[1] / "scripts" / "migrate_monitor_config.py"
        r = subprocess.run(
            [sys.executable, str(script), "--legacy-health", str(health_py),
             "--legacy-runbook", str(runbook_py), "--config", str(cfg_path)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("parsed 0 rules", r.stderr)

    def test_merge_preserves_user_rules(self):
        import json
        import subprocess

        tmp = Path(tempfile.mkdtemp())
        health_py, runbook_py = self._write_legacy(
            tmp,
            'REQUIRED_CHECKS = {"a": [{"object": "o1", "metric": "probe_success", "selector": {}}]}\n',
            'RUNBOOK = [RunbookRule(id="rb_legacy", name="L", capability="service.restart")]\n',
        )
        cfg_path = tmp / "config.json"
        cfg_path.write_text(
            json.dumps({
                "runbook_rules": [{"id": "rb_user", "name": "U", "capability": "service.restart"}],
                "required_checks": {"a": [{"object": "keep", "metric": "probe_success", "selector": {}}]},
            }),
            encoding="utf-8",
        )
        script = Path(__file__).resolve().parents[1] / "scripts" / "migrate_monitor_config.py"
        r = subprocess.run(
            [sys.executable, str(script), "--legacy-health", str(health_py),
             "--legacy-runbook", str(runbook_py), "--config", str(cfg_path)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        ids = {x["id"] for x in data["runbook_rules"]}
        self.assertIn("rb_legacy", ids)
        self.assertIn("rb_user", ids)
        objs = {o["object"] for o in data["required_checks"]["a"]}
        self.assertIn("keep", objs)
        self.assertIn("o1", objs)


if __name__ == "__main__":
    unittest.main()
