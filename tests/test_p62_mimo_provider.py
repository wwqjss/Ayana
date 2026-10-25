import json, os, tempfile, unittest
from pathlib import Path

from ayana.mimo_admin import MimoAdmin


class MimoProviderApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base = Path(self.tmp.name)
        self.admin = MimoAdmin()

    def tearDown(self):
        self.tmp.cleanup()

    def test_apply_provider_writes_config_without_echoing_key_in_summary(self):
        res = self.admin.apply_provider(
            provider_id="xiaomi",
            api_key="sk-secret-key-abc",
            base_url="https://api.xiaomimimo.com/v1",
            model="mimo-v2.6-flash",
            config_dir=str(self.base),
        )
        self.assertTrue(res["ok"])
        path = Path(res["path"])
        self.assertTrue(path.exists())
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["provider"]["xiaomi"]["options"]["apiKey"], "sk-secret-key-abc")
        self.assertEqual(data["model"], "xiaomi/mimo-v2.6-flash")
        # summary 不回显密钥
        summary = self.admin.provider_summary(config_dir=str(self.base))
        blob = json.dumps(summary, ensure_ascii=False)
        self.assertNotIn("sk-secret-key-abc", blob)

    def test_apply_requires_key(self):
        with self.assertRaises(ValueError):
            self.admin.apply_provider(api_key="", config_dir=str(self.base))


if __name__ == "__main__":
    unittest.main()
