"""全局设置与一键接入 Prometheus 前置检查。"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.auth import AuthService
from ayana.db import Database
from ayana.access import AccessControl as Policy
from ayana.web import SESSION_COOKIE, WebApp


class _Req:
    def __init__(self, body=None, *, cookies=None, headers=None, method="POST", path="/api/settings/global"):
        self._body = body or {}
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.remote = "127.0.0.1"
        self.method = method
        self.rel_url = SimpleNamespace(path=path, query={})

    async def json(self):
        return self._body


class _LLM:
    def __init__(self):
        self.api_key = ""
        self.base_url = ""
        self.model = "m"


class _Prom:
    def __init__(self):
        self.base_url = "http://127.0.0.1:9090"
        self._fail_streak = 0
        self._open_until = 0.0
        self.ok = False

    async def query(self, expr):
        if not self.ok:
            raise RuntimeError("Cannot connect to host 127.0.0.1:9090")
        return {"result": []}


class GlobalSettingsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        self.auth = AuthService(self.db, pepper="p", session_ttl=3600, max_failed=5, lockout=60)
        self.auth.ensure_bootstrap_admin("admin")
        self.auth.change_password(1, "", "brand-new-password")
        static = Path(self.tmp.name) / "static"
        static.mkdir(exist_ok=True)
        (static / "index.html").write_text("<html></html>", encoding="utf-8")
        self.llm = _LLM()
        self.prom = _Prom()
        self.webapp = WebApp(
            self.db,
            self.auth,
            Policy(self.db),
            None,
            None,
            None,
            self.prom,
            static_dir=static,
            version="t",
            llm=self.llm,
        )
        res = self.auth.login("admin", "brand-new-password")
        self.sid = res["session_id"]
        self.sess = self.auth.get_session(self.sid)

    def _req(self, body=None, path="/api/settings/global", method="POST"):
        return _Req(
            body or {},
            cookies={SESSION_COOKIE: self.sid},
            headers={"X-CSRF-Token": self.sess["csrf_token"], "User-Agent": "t"},
            path=path,
            method=method,
        )

    async def test_get_masks_api_key(self):
        self.llm.api_key = "sk-secret-value-123456"
        resp = await self.webapp.api_settings_global_get(self._req(method="GET"))
        data = json.loads(resp.text)
        self.assertTrue(data["ok"])
        self.assertTrue(data["llm_api_key_set"])
        self.assertNotIn("secret-value-123456", json.dumps(data))
        self.assertIn("****", data["llm_api_key_masked"])

    async def test_post_persists_llm_and_prom(self):
        resp = await self.webapp.api_settings_global_post(
            self._req(
                {
                    "llm_base_url": "https://api.example.com/v1",
                    "llm_model": "mimo-test",
                    "llm_api_key": "sk-new-key",
                    "prometheus_url": "http://10.0.0.5:9090",
                }
            )
        )
        data = json.loads(resp.text)
        self.assertTrue(data["ok"], data)
        self.assertEqual(self.llm.base_url, "https://api.example.com/v1")
        self.assertEqual(self.llm.model, "mimo-test")
        self.assertEqual(self.llm.api_key, "sk-new-key")
        self.assertEqual(self.prom.base_url, "http://10.0.0.5:9090")
        row = self.db.query_one("SELECT value FROM meta WHERE key='llm_model'")
        self.assertEqual(row["value"], "mimo-test")

    async def test_setup_monitor_reports_prometheus_ok(self):
        self.prom.ok = True
        resp = await self.webapp.api_setup_monitor_get(self._req(method="GET", path="/api/setup/monitor"))
        data = json.loads(resp.text)
        self.assertTrue(data["prometheus_ok"])
        self.prom.ok = False
        resp = await self.webapp.api_setup_monitor_get(self._req(method="GET", path="/api/setup/monitor"))
        data = json.loads(resp.text)
        self.assertFalse(data["prometheus_ok"])
        self.assertIn("Prometheus", data["prometheus_hint"])


if __name__ == "__main__":
    unittest.main()
