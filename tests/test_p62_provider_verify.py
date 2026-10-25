"""P6.2 配置验证：测试连接分类、未验证不宣称可用、密钥不回显。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ayana.mimo_admin import MimoAdmin


class ClassifyTests(unittest.TestCase):
    def test_success(self):
        r = MimoAdmin.classify_api_response(200, '{"choices":[{"message":{"content":"PONG"}}]}')
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"], "success")

    def test_auth_failed(self):
        r = MimoAdmin.classify_api_response(401, '{"error":{"message":"Invalid API Key"}}')
        self.assertFalse(r["ok"])
        self.assertEqual(r["result"], "auth_failed")

    def test_quota_exhausted(self):
        r = MimoAdmin.classify_api_response(429, '{"error":{"message":"quota exhausted"}}')
        self.assertEqual(r["result"], "quota_exhausted")

    def test_rate_limited(self):
        r = MimoAdmin.classify_api_response(429, '{"error":{"message":"slow down"}}')
        self.assertEqual(r["result"], "rate_limited")

    def test_timeout(self):
        r = MimoAdmin.classify_api_response(0, "", timed_out=True)
        self.assertEqual(r["result"], "timeout")

    def test_server_error(self):
        r = MimoAdmin.classify_api_response(503, "unavailable")
        self.assertEqual(r["result"], "server_error")


class ProviderFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base = Path(self.tmp.name)
        self.admin = MimoAdmin()

    def tearDown(self):
        self.tmp.cleanup()

    def test_apply_writes_key_but_summary_never_shows_key(self):
        res = self.admin.apply_provider(
            provider_id="xiaomi",
            api_key="sk-never-show-me",
            base_url="https://example.test/v1",
            model="m1",
            config_dir=str(self.base),
            verified=False,
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["key_len"], len("sk-never-show-me"))
        blob = json.dumps(self.admin.provider_summary(config_dir=str(self.base)), ensure_ascii=False)
        self.assertNotIn("sk-never-show-me", blob)
        self.assertTrue(any(p.get("key_set") for p in self.admin.provider_summary(config_dir=str(self.base))["providers"]))

    def test_clear_removes_key(self):
        self.admin.apply_provider(
            provider_id="xiaomi", api_key="sk-x",
            base_url="https://example.test/v1", model="m1",
            config_dir=str(self.base),
        )
        self.admin.clear_provider(provider_id="xiaomi", config_dir=str(self.base))
        providers = self.admin.provider_summary(config_dir=str(self.base))["providers"]
        self.assertFalse(any(p.get("key_set") for p in providers))

    def test_test_connection_bad_request_without_key(self):
        r = self.admin.test_connection(base_url="https://x.test/v1", api_key="", model="m")
        self.assertFalse(r["ok"])
        self.assertEqual(r["result"], "bad_request")

    def test_test_connection_never_leaks_key_in_error(self):
        r = self.admin.test_connection(
            base_url="https://127.0.0.1:1/v1",
            api_key="sk-secret-should-not-leak",
            model="m",
            timeout=1.5,
        )
        self.assertFalse(r["ok"])
        self.assertNotIn("sk-secret-should-not-leak", json.dumps(r, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
