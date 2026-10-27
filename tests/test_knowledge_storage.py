"""Persistent knowledge shared by independent Web and MCP processes."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ayana.knowledge import KnowledgeBase, knowledge_root
from ayana.main import App
from ayana.mcp_server import build_ops_context
from ayana.mcp_tools import McpToolError, OpsTools
from ayana.mimo_runtime_config import verified_runtime


class KnowledgeStorageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = {
            "db_path": str(self.root / "state.db"), "base_dir": str(self.root),
            "knowledge_dir": "editable-knowledge", "onewbot_token": "test",
            "webhook_token": "test", "web_auth_pepper": "test",
            "ssh_credential_key": "test", "auto_investigate": {"enabled": False},
            "prometheus_config": {"local_dir": str(self.root / "prom")},
        }

    def test_empty_config_keeps_development_root(self):
        self.assertEqual(knowledge_root({}), KnowledgeBase._default_root())

    def test_relative_root_uses_config_directory(self):
        self.assertEqual(knowledge_root(self.cfg), self.root / "editable-knowledge")

    async def test_mcp_upsert_visible_to_existing_web_knowledge_instance(self):
        app = App(self.cfg)
        self.addCleanup(app.db.close)
        child = build_ops_context(self.cfg)
        self.addCleanup(child.db.close)
        self.assertEqual(app.knowledge.root, child.knowledge.root)
        before = app.knowledge.revision
        with patch.dict(os.environ, {"AYANA_MCP_READONLY": "0"}):
            result = await OpsTools(child).knowledge_upsert({
                "doc_id": "probe-verified", "title": "HTTP probe verified",
                "objects": ["demo:nginx"], "body": "HTTP 200 observed", "verified": "result",
            })
        self.assertTrue(result["ok"])
        self.assertTrue((knowledge_root(self.cfg) / "probe-verified.md").is_file())
        self.assertEqual(app.knowledge.get("probe-verified").body.strip(), "HTTP 200 observed")
        self.assertNotEqual(app.knowledge.revision, before)
        self.assertEqual([d.id for d in app.knowledge.docs_for_object("demo", "nginx")], ["probe-verified"])
        self.assertEqual([d.id for d in app.knowledge.list_docs()], ["probe-verified"])

    async def test_readonly_mcp_still_rejects_knowledge_write(self):
        with patch.dict(os.environ, {"AYANA_MCP_READONLY": "1"}):
            child = build_ops_context(self.cfg)
        self.addCleanup(child.db.close)
        with self.assertRaises(McpToolError) as denied:
            await OpsTools(child).knowledge_upsert({"title": "must not write", "objects": ["demo:nginx"]})
        self.assertEqual(denied.exception.code, "readonly_mode_rejects_write")
        self.assertFalse(knowledge_root(self.cfg).exists())

    def test_child_uses_explicit_same_instance_knowledge_binding(self):
        selected = self.root / "selected-knowledge"
        with patch.dict(os.environ, {"AYANA_MCP_KNOWLEDGE_DIR": str(selected)}):
            child = build_ops_context(self.cfg)
        self.addCleanup(child.db.close)
        self.assertEqual(child.knowledge.root, selected)

    def test_runtime_binds_same_knowledge_directory_in_both_environments(self):
        db = SimpleNamespace(path=self.cfg["db_path"])
        admin = SimpleNamespace(runtime_configuration=lambda _: {"config": {}})
        runtime = verified_runtime(self.cfg, db, admin)
        selected = str(knowledge_root(self.cfg))
        self.assertEqual(runtime["environment"]["AYANA_MCP_KNOWLEDGE_DIR"], selected)
        self.assertEqual(runtime["config"]["mcp"]["ayana"]["environment"]["AYANA_MCP_KNOWLEDGE_DIR"], selected)

    def test_writable_knowledge_cannot_escape_its_content_directory(self):
        kb = KnowledgeBase(root=self.root / "content")
        for doc_id in ("../outside", "..\\outside", "bad\nname"):
            with self.subTest(doc_id=doc_id), self.assertRaises(ValueError):
                kb.upsert(doc_id=doc_id, title="blocked", body="no", objects=["demo:nginx"])
        self.assertFalse((self.root / "outside.md").exists())


if __name__ == "__main__":
    unittest.main()
