"""HTTP probe registration: real config writes, rollback and MCP authority gates."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.incidents import IncidentService
from ayana.mcp_tools import McpToolError, OpsContext, OpsTools, TOOL_SPECS
from ayana.promconfig import LocalConfigFS, PromConfigError, PromConfigService, parse_simple_yaml
from ayana.session_bridge import SessionBridge


BASE = """# hand-written config and comments must remain byte-for-byte
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']
remote_write:
  - url: http://metrics.example/write
"""
URL = "http://172.16.0.14/"
PROBE = {"exporter": "blackbox:9115", "module": "http_2xx", "job_name": "romi-nginx-blackbox"}
LABELS = {"asset": "ROMI", "service": "nginx"}


class ProbeConfigTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.fs = LocalConfigFS(Path(self.tmp.name) / "prom")
        self.svc = PromConfigService(self.db, self.fs, require_promtool=False)
        self.svc._try_reload = AsyncMock(return_value={"ok": True})

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    async def seed(self, raw=BASE):
        await self.fs.write_text("prometheus.yml", raw)

    async def add(self, **kwargs):
        args = {"address": URL, "labels": LABELS, "probe": PROBE, "actor": "test"}
        args.update(kwargs)
        return await self.svc.add_target(**args)

    async def test_fixed_probe_job_preserves_existing_raw_and_uses_one_transaction(self):
        await self.seed()
        result = await self.add()
        raw = await self.fs.read_text("prometheus.yml")
        insertion = raw.index("  - job_name: romi-nginx-blackbox")
        end = raw.index("remote_write:")
        self.assertEqual(raw[:insertion] + raw[end:], BASE)
        job = parse_simple_yaml(raw)["scrape_configs"][1]
        self.assertEqual(job["metrics_path"], "/probe")
        self.assertEqual(job["params"], {"module": ["http_2xx"]})
        self.assertEqual(job["static_configs"], [{"targets": [URL], "labels": LABELS}])
        self.assertEqual(job["relabel_configs"], [
            {"source_labels": ["__address__"], "target_label": "__param_target"},
            {"source_labels": ["__param_target"], "target_label": "instance"},
            {"target_label": "__address__", "replacement": "blackbox:9115"},
        ])
        self.assertTrue(result["changed"])
        self.assertEqual(self.svc._txn_seq, 1)
        self.svc._try_reload.assert_awaited_once()
        self.assertFalse(await self.fs.exists("file_sd/ayana-nodes.json"))

    async def test_repeat_is_idempotent_without_reload(self):
        await self.seed()
        await self.add()
        before = await self.fs.read_text("prometheus.yml")
        result = await self.add()
        self.assertFalse(result["changed"])
        self.assertEqual(await self.fs.read_text("prometheus.yml"), before)
        self.svc._try_reload.assert_awaited_once()

    async def test_equivalent_existing_target_reuses_its_job_even_with_another_requested_name(self):
        await self.seed()
        await self.add()
        before = await self.fs.read_text("prometheus.yml")
        for probe in ({"exporter": "blackbox:9115"}, {**PROBE, "job_name": "different-name"}):
            result = await self.add(probe=probe)
            self.assertFalse(result["changed"])
            self.assertEqual(result["job"], PROBE["job_name"])
            self.assertEqual(await self.fs.read_text("prometheus.yml"), before)
        self.svc._try_reload.assert_awaited_once()

    async def test_reuses_equivalent_handwritten_probe_without_rewriting(self):
        handwritten = BASE.replace("remote_write:", """  # existing ROMI job owned by the operator
  - job_name: romi-nginx-blackbox
    scrape_interval: 30s
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets: ['http://172.16.0.14/', 'http://172.16.0.14:8081/']
        labels:
          asset: ROMI
          service: nginx
          host: romi.example
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox:9115
remote_write:""")
        await self.seed(handwritten)
        result = await self.add()
        self.assertFalse(result["changed"])
        self.assertEqual(await self.fs.read_text("prometheus.yml"), handwritten)
        self.svc._try_reload.assert_not_awaited()

    async def test_conflicting_job_is_never_overwritten(self):
        await self.seed()
        await self.add()
        before = await self.fs.read_text("prometheus.yml")
        for args in ({"address": "http://172.16.0.15/"}, {"probe": {**PROBE, "exporter": "other:9115"}},
                     {"labels": {"asset": "OTHER"}}, {"probe": {**PROBE, "module": "http_custom"}}):
            with self.subTest(args=args), self.assertRaises(PromConfigError) as error:
                await self.add(**args)
            self.assertEqual(error.exception.code, "probe_job_conflict")
            self.assertEqual(await self.fs.read_text("prometheus.yml"), before)

    async def test_duplicate_named_jobs_and_duplicate_scrape_keys_fail_closed(self):
        await self.seed()
        await self.add()
        raw = await self.fs.read_text("prometheus.yml")
        duplicate = "  - job_name: romi-nginx-blackbox\n    static_configs: []\n"
        for invalid in (raw.replace("remote_write:", duplicate + "remote_write:"), raw + "scrape_configs: []\n"):
            await self.seed(invalid)
            with self.assertRaises(PromConfigError):
                await self.add()
            self.assertEqual(await self.fs.read_text("prometheus.yml"), invalid)

    async def test_defaults_are_stable_and_node_target_semantics_stay_separate(self):
        await self.seed()
        result = await self.add(probe={"exporter": "blackbox:9115"})
        repeat = await self.add(probe={"exporter": "blackbox:9115"})
        self.assertEqual(result["job"], repeat["job"])
        self.assertFalse(repeat["changed"])
        node = await self.svc.add_target(address="172.16.0.14:9100", labels={"asset": "ROMI"})
        self.assertTrue(node["ok"])
        self.assertIn("172.16.0.14:9100", await self.fs.read_text("file_sd/ayana-nodes.json"))
        with self.assertRaises(PromConfigError):
            await self.svc.add_target(address=URL)

    async def test_invalid_inputs_do_not_touch_configuration(self):
        await self.seed()
        cases = [
            {"address": u} for u in ("file:///etc/passwd", "http://u:p@host/", "http://host/#fragment",
                                      "http://host/\nnext", "http://host/\rnext", "http://host/\x00", "http://host:0/",
                                      "http://host:65536/", "http:///path", "http://a\\b/")
        ]
        cases += [{"probe": {**PROBE, "exporter": e}} for e in (
            "http://blackbox:9115", "blackbox", "blackbox:0", "blackbox:65536", "a:9115/path",
            "u:p@host:9115", "blackbox:9115\n", "a:9115?x=y", "a:9115#x", "a:9115;id",
        )]
        cases += [{"probe": {**PROBE, "module": "http_2xx\nanything"}}, {"probe": {**PROBE, "job_name": "x\njob"}},
                  {"probe": {**PROBE, "relabel_configs": []}}, {"probe": []},
                  {"labels": {"__param_target": "http://other/"}}, {"labels": {"job": "other"}},
                  {"labels": {"instance": "other"}}]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(PromConfigError):
                await self.add(**args)
            self.assertEqual(await self.fs.read_text("prometheus.yml"), BASE)
        self.svc._try_reload.assert_not_awaited()

    async def test_query_and_ipv6_are_encoded_as_yaml_data(self):
        await self.seed()
        address = "https://[fd00::1]:8443/health?x=1&y=a:b"
        await self.add(address=address, probe={**PROBE, "exporter": "[fd00::2]:9115"})
        job = parse_simple_yaml(await self.fs.read_text("prometheus.yml"))["scrape_configs"][1]
        self.assertEqual(job["static_configs"][0]["targets"], [address])
        self.assertEqual(job["relabel_configs"][-1]["replacement"], "[fd00::2]:9115")

    async def test_promtool_failure_restores_original_and_reports_failure(self):
        await self.seed()
        self.svc.require_promtool = True
        self.svc._run_promtool_check = AsyncMock(return_value={"ok": False, "error": "invalid config"})
        with self.assertRaises(PromConfigError) as error:
            await self.add()
        self.assertEqual(error.exception.code, "promtool_failed")
        self.assertEqual(await self.fs.read_text("prometheus.yml"), BASE)
        self.assertEqual(self.svc._txn_seq, 0)

    async def test_reload_failure_restores_original_and_reports_failure(self):
        await self.seed()
        self.svc._try_reload = AsyncMock(side_effect=[{"ok": False, "status": 403}, {"ok": True}])
        with self.assertRaises(PromConfigError) as error:
            await self.add()
        self.assertEqual(error.exception.code, "reload_failed")
        self.assertEqual(await self.fs.read_text("prometheus.yml"), BASE)
        self.assertEqual(self.svc._try_reload.await_count, 2)

    async def test_missing_config_and_unsupported_layouts_fail_closed(self):
        with self.assertRaises(PromConfigError):
            await self.add()
        for raw in ("scrape_configs: [{job_name: existing}]\n", "scrape_configs: &jobs\n  - job_name: x\n"):
            await self.seed(raw)
            with self.assertRaises(PromConfigError):
                await self.add()
            self.assertEqual(await self.fs.read_text("prometheus.yml"), raw)
        self.svc._try_reload.assert_not_awaited()

    async def test_empty_and_unindented_scrape_lists(self):
        for raw in ("global: {}\n", "scrape_configs: [] # empty\nremote_write:\n  - url: http://metrics.example/write\n", "scrape_configs:\n- job_name: existing\n  static_configs: []\n"):
            with self.subTest(raw=raw):
                await self.seed(raw)
                await self.add()
                jobs = parse_simple_yaml(await self.fs.read_text("prometheus.yml"))["scrape_configs"]
                self.assertEqual(jobs[-1]["job_name"], PROBE["job_name"])

    async def test_concurrent_probe_additions_preserve_both_jobs(self):
        await self.seed()
        await asyncio.gather(self.add(), self.add(address="http://172.16.0.14:8081/", probe={**PROBE, "job_name": "other-probe"}))
        jobs = parse_simple_yaml(await self.fs.read_text("prometheus.yml"))["scrape_configs"]
        self.assertEqual({j["job_name"] for j in jobs}, {"prometheus", "romi-nginx-blackbox", "other-probe"})


class ProbeMcpTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.duty = DutySessionManager(self.db)
        self.sid = self.duty.create(origin="auto")["session_id"]
        self.duty.set_runtime_state(self.sid, "idle")
        self.db.execute("UPDATE duty_sessions SET remote_session_id='ses_probe' WHERE id=?", (self.sid,))
        self.pc = type("Prom", (), {})()
        self.pc.add_target = AsyncMock(return_value={"ok": True})
        self.bridge = SessionBridge(self.db, duty=self.duty)
        ctx = OpsContext(None, None, IncidentService(self.db), None, db=self.db, promconfig=self.pc,
                         session_bridge=self.bridge, managed_context=True)
        self.tools = OpsTools(ctx)
        self.meta = {"sessionId": "ses_probe", "turnId": "turn_probe", "actorId": "main"}
        self.args = {"address": URL, "labels": LABELS, "probe": PROBE}

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    async def test_probe_is_visible_in_schema(self):
        spec = next(s for s in TOOL_SPECS if s["name"] == "config.prom_target_add")
        self.assertIn("probe", spec["inputSchema"]["properties"])

    async def test_probe_write_obeys_readonly_and_manual_approval(self):
        self.duty.set_settings({"auto_access_mode": "readonly", "auto_approval_mode": "automatic"})
        with self.assertRaises(McpToolError) as error:
            await self.tools.call("config.prom_target_add", self.args, invocation_context=self.meta)
        self.assertEqual(error.exception.code, "readonly_mode_rejects_write")
        self.pc.add_target.assert_not_awaited()
        self.duty.set_settings({"auto_access_mode": "readwrite", "auto_approval_mode": "manual"})
        result = await self.tools.call("config.prom_target_add", self.args, invocation_context=self.meta)
        self.assertEqual(result["error"], "approval_required")
        self.pc.add_target.assert_not_awaited()

    async def test_automatic_and_approved_calls_pass_probe_to_service(self):
        self.duty.set_settings({"auto_access_mode": "readwrite", "auto_approval_mode": "automatic"})
        result = await self.tools.call("config.prom_target_add", self.args, invocation_context=self.meta)
        self.assertTrue(result["ok"])
        self.pc.add_target.assert_awaited_once_with(address=URL, labels=LABELS, probe=PROBE, actor="mcp_agent")
        self.pc.add_target.reset_mock()
        self.duty.set_setting("auto_approval_mode", "manual")
        result = await self.tools.call_approved("config.prom_target_add", self.args, authority_session_id=self.sid)
        self.assertTrue(result["ok"])
        self.pc.add_target.assert_awaited_once_with(address=URL, labels=LABELS, probe=PROBE, actor="mcp_agent")

    async def test_normal_target_handler_does_not_add_probe_argument(self):
        self.duty.set_settings({"auto_access_mode": "readwrite", "auto_approval_mode": "automatic"})
        await self.tools.call("config.prom_target_add", {"address": "host:9100"}, invocation_context=self.meta)
        self.pc.add_target.assert_awaited_once_with(address="host:9100", labels={}, actor="mcp_agent")


if __name__ == "__main__":
    unittest.main()
