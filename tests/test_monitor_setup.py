"""监控接入：账户角色、首登配置、未接入 vs 采集故障、示例资产。"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.auth import AuthService
from ayana.db import Database, now
from ayana.health import host_health
from ayana.main import seed_assets
from ayana.monitor import PromError
from ayana.access import AccessControl as Policy
from ayana.web import SESSION_COOKIE, WebApp


class _FakeRequest:
    def __init__(self, body=None, *, cookies=None, headers=None, remote="127.0.0.1", method="POST", path="/api/setup/monitor"):
        self._body = body if body is not None else {}
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.remote = remote
        self.method = method
        self.rel_url = SimpleNamespace(path=path, query={})

    async def json(self):
        return self._body


class AdminMonitorPermTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        self.addCleanup(self.tmp.cleanup)
        seed_assets(self.db)
        self.policy = Policy(self.db)
        for username, admin in (("admin", 1), ("viewer", 0)):
            self.db.execute(
                "INSERT INTO users(username,password_hash,is_admin,created_at,updated_at) VALUES(?,?,?,?,?)",
                (username, "test-hash", admin, now(), now()),
            )

    def test_admin_has_monitor_read_caps(self):
        for cap in ("asset.summary", "probe.status", "promconfig.read", "node_exporter.manage"):
            d = self.policy.check(
                subject_type="web_user",
                subject_id="admin",
                capability=cap,
                asset_id="demo-web",
                object_id="*",
            )
            self.assertTrue(d["allowed"], f"{cap} should be allowed for admin, got {d}")

    def test_seed_assets_does_not_create_permission_rules(self):
        # 旧 permissions/agent_ceiling 表已删除；注册/播种不再写授权规则
        self.assertIsNone(self.db.query_one(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='permissions'"
        ))
        self.assertIsNone(self.db.query_one(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_ceiling'"
        ))

    def test_viewer_can_read_monitor_but_cannot_manage_it(self):
        args = dict(subject_type="web_user", subject_id="viewer", asset_id="demo-web")
        self.assertTrue(self.policy.check(**args, capability="probe.status")["allowed"])
        self.assertFalse(self.policy.check(**args, capability="node_exporter.manage")["allowed"])

    def test_unknown_account_denied(self):
        self.assertFalse(self.policy.check(subject_type="web_user", subject_id="absent",
                                          capability="probe.status")["allowed"])


class StatusSemanticsTests(unittest.TestCase):
    def test_connection_error_is_not_configured(self):
        hh = host_health(metric_state="not_configured", metric_error="timeout:...")
        self.assertEqual(hh["state"], "not_configured")

    def test_exporter_down_is_collect_error(self):
        hh = host_health(
            metric_state="collect_error",
            metric_error="node_exporter_down",
            collect_error="node_exporter_down",
        )
        self.assertEqual(hh["state"], "collect_error")

    def test_conn_reflects_to_not_configured(self):
        hh = host_health(
            metric_state="collect_error",
            metric_error="Cannot connect to host 127.0.0.1:9090",
            collect_error="Cannot connect to host 127.0.0.1:9090",
        )
        self.assertEqual(hh["state"], "not_configured")

    def test_sample_asset_helper(self):
        self.assertTrue(
            WebApp._is_sample_asset({"id": "demo-web", "host": ""})
        )
        self.assertFalse(
            WebApp._is_sample_asset({"id": "nerv", "host": "10.0.0.1"})
        )
        self.assertFalse(
            WebApp._is_sample_asset({"id": "demo-web", "host": "10.0.0.2"})
        )


class SetupMonitorApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        self.addCleanup(self.tmp.cleanup)
        seed_assets(self.db)
        self.auth = AuthService(self.db, pepper="p", session_ttl=3600, max_failed=5, lockout=60)
        self.bootstrap = self.auth.ensure_bootstrap_admin("admin")
        self.uid = int(self.db.query_one("SELECT id FROM users WHERE username='admin'")["id"])
        static = Path(self.tmp.name) / "static"
        static.mkdir(exist_ok=True)
        (static / "index.html").write_text("<html></html>", encoding="utf-8")

        class _Prom:
            base_url = "http://127.0.0.1:9090"

            async def query(self, expr):
                raise PromError("Cannot connect to host 127.0.0.1:9090")

        self.webapp = WebApp(
            self.db,
            self.auth,
            Policy(self.db),
            None,
            None,
            None,
            _Prom(),
            static_dir=static,
            version="test",
        )

    def _login(self):
        res = self.auth.begin_login("admin", self.bootstrap, ip="127.0.0.1", ua="t")
        self.assertTrue(res["complete"])
        sess = res["session"]
        return sess, sess["session_id"]

    def _req(self, sess, sid, body=None, path="/api/setup/monitor"):
        return _FakeRequest(
            body or {},
            cookies={SESSION_COOKIE: sid},
            headers={"X-CSRF-Token": sess["csrf_token"], "User-Agent": "t"},
            path=path,
        )

    async def test_setup_allowed_before_password_change(self):
        sess, sid = self._login()
        resp = await self.webapp.api_setup_monitor_get(self._req(sess, sid, path="/api/setup/monitor"))
        data = json.loads(resp.text)
        self.assertTrue(data["ok"])

    async def test_setup_post_persists_and_probes(self):
        sess, sid = self._login()
        resp = await self.webapp.api_setup_monitor_post(
            self._req(sess, sid, {"prometheus_url": "http://10.1.2.3:9090", "alertmanager_url": "http://10.1.2.3:9093"})
        )
        data = json.loads(resp.text)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["prometheus_url"], "http://10.1.2.3:9090")
        self.assertEqual(self.webapp.prom.base_url, "http://10.1.2.3:9090")
        row = self.db.query_one("SELECT value FROM meta WHERE key='prometheus_url'")
        self.assertEqual(row["value"], "http://10.1.2.3:9090")
        # 探测失败也要反映
        self.assertIsNotNone(data.get("probe"))

    async def test_setup_rejects_bad_url(self):
        sess, sid = self._login()
        resp = await self.webapp.api_setup_monitor_post(
            self._req(sess, sid, {"prometheus_url": "ftp://x"})
        )
        data = json.loads(resp.text)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "bad_url")

    async def test_monitor_host_ok_for_admin(self):
        sess, sid = self._login()
        # 先完成首登改密（与真实流程一致）
        ch = await self.webapp.api_change_password(
            self._req(
                sess,
                sid,
                {"new_password": "brand-new-password", "confirm_password": "brand-new-password"},
                path="/api/password",
            )
        )
        self.assertTrue(json.loads(ch.text)["ok"])

        class _M:
            async def host_overview(self, asset_id):
                return {"state": "not_configured", "error": "timeout", "metrics": {}}

            async def host_history(self, asset_id, range_key):
                return {"state": "not_configured", "error": "timeout", "metrics": {}}

            async def hosts_status(self, assets):
                return []

        self.webapp._monitor = lambda: _M()

        async def _prom_items(a):
            return [], []

        self.webapp._prom_business_items = _prom_items
        self.webapp._native_business_states = lambda aid: []
        self.webapp._monitor_firing = lambda: {}

        req = self._req(sess, sid, path="/api/monitor/host/demo-web")
        req.match_info = {"asset_id": "demo-web"}
        resp = await self.webapp.api_monitor_host(req)
        data = json.loads(resp.text)
        self.assertTrue(data["ok"], data)
        self.assertTrue(data.get("monitor_not_configured"))
        self.assertTrue(data.get("sample"))

    async def test_setup_requires_admin(self):
        self.auth.create_user("bob", "password-bob", is_admin=False)
        res = self.auth.login("bob", "password-bob")
        sid = res["session_id"]
        sess = self.auth.get_session(sid)
        with self.assertRaises(Exception):
            await self.webapp.api_setup_monitor_post(
                self._req(sess, sid, {"prometheus_url": "http://x:9090"})
            )


if __name__ == "__main__":
    unittest.main()
