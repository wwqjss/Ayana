"""MD 知识库：front matter、多对象关联、共同命中、状态语义、不授予执行权。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database
from ayana.investigation import InvestigationService
from ayana.knowledge import KnowledgeBase, parse_front_matter
from ayana.ntsafe import NTResult
from ayana.policy import Policy

ROOT = Path(__file__).resolve().parents[1] / "knowledge"


class FakeNT:
    async def probe(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0)

    async def exec(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0)

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-probe","mode":"probe"}')


class FakeGate:
    def get(self, asset_id):
        class B:
            read_alias = asset_id
            write_alias = asset_id + "-exec"
        return B()


class FakeProm:
    async def probe_success(self, asset, service=""):
        return {"result": []}


class TestParseFrontMatter(unittest.TestCase):
    def test_parse_basic(self):
        text = "---\nid: x\ntitle: T\nstatus: active\ntype: issue\nobjects:\n  - sora:google\n  - sora:youtube\ntags:\n  - a\n---\n\n# Body\nhello\n"
        meta, body = parse_front_matter(text)
        self.assertEqual(meta["id"], "x")
        self.assertEqual(meta["objects"], ["sora:google", "sora:youtube"])
        self.assertIn("# Body", body)
        self.assertNotIn("id:", body)


class TestMarkdownKnowledge(unittest.TestCase):
    def setUp(self):
        self.kb = KnowledgeBase(db=None, root=ROOT)

    def test_load_files(self):
        ids = {d.id for d in self.kb.list_docs()}
        self.assertIn("hysteria2-chain", ids)
        self.assertIn("ayana-port-bind-failed", ids)

    def test_one_md_multi_objects(self):
        docs = self.kb.docs_for_object("sora", "google")
        self.assertTrue(any(d.id == "hysteria2-chain" for d in docs))
        names = set(docs[0].objects)
        self.assertIn("sora:hysteria-server", names)
        self.assertIn("sora:youtube", names)

    def test_find_by_registered_object_id(self):
        docs = self.kb.docs_for_object("sora", "sora:probe:google")
        self.assertTrue(any(d.id == "hysteria2-chain" for d in docs))

    def test_google_youtube_share_theme(self):
        shared = self.kb.docs_for_objects(
            [("sora", "google"), ("sora", "youtube")]
        )
        self.assertIn("hysteria2-chain", shared["shared_ids"])
        ctx = self.kb.investigation_context("sora", "google", extra_failures=["youtube"])
        self.assertIn("hysteria2-chain", ctx["context_text"])
        self.assertTrue(ctx["shared_docs"])
        self.assertIn("共同命中", ctx["common"]["shared_failure_meaning"])

    def test_active_only_for_investigation(self):
        # 临时 deprecated 文档
        tmp = self.kb.root / "_tmp_dep.md"
        tmp.write_text(
            "---\nid: dep-test\ntitle: old\ntype: system\nobjects:\n  - sora:google\n---\n# old\n",
            encoding="utf-8",
        )
        try:
            self.kb.reload()
            active = self.kb.docs_for_object("sora", "google", include_inactive=False)
            all_docs = self.kb.docs_for_object("sora", "google", include_inactive=True)
            # status defaults to active when missing; mark as deprecated
            d = self.kb.get("dep-test")
            self.assertIsNotNone(d)
            # force status
            d.status = "deprecated"
            active2 = [x for x in self.kb.docs_for_object("sora", "google") if x.status == "active"]
            self.assertFalse(any(x.id == "dep-test" for x in active2))
            ctx = self.kb.investigation_context("sora", "google")
            self.assertNotIn("dep-test", ctx["context_text"])
            self.assertTrue(any(h["id"] == "dep-test" for h in ctx["historical_docs"]))
        finally:
            tmp.unlink(missing_ok=True)
            self.kb.reload()

    def test_issue_knowledge_lookup(self):
        docs = self.kb.docs_for_object("kanata", "ayana")
        self.assertTrue(any(d.id == "ayana-port-bind-failed" for d in docs))
        self.assertTrue(any(d.type == "issue" for d in docs))


class TestInvestigationUsesMarkdown(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        t = 1.0
        self.db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " prom_asset, enabled, notes, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,1,'',?,?)",
            ("sora", "Sora", "sora", "sora-exec", "sora", "sora", t, t),
        )
        self.policy = Policy(self.db)
        self.policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="asset.summary",
            asset_id="sora", object_id="*", allow=True, require_approval=False,
            auto_allowed=False, actor="test",
        )
        self.kb = KnowledgeBase(self.db, root=ROOT)
        self.inv = InvestigationService(
            self.db, FakeNT(), FakeGate(), FakeProm(), self.policy, knowledge=self.kb
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_investigation_injects_md_body(self):
        res = asyncio.run(
            self.inv.run(
                asset_id="sora",
                object_id="google",
                capability="asset.summary",
                actor_type="auto_rule",
                actor_id="agent",
            )
        )
        self.assertTrue(res.get("ok"))
        knol = res.get("knowledge") or {}
        self.assertTrue(knol.get("docs"))
        self.assertIn("Hysteria2", knol.get("context_text", ""))
        self.assertIn("google", knol.get("context_text", ""))

    def test_knowledge_does_not_grant_write(self):
        d = self.policy.check(
            subject_type="auto_rule",
            subject_id="agent",
            capability="service.restart",
            asset_id="sora",
            object_id="sora:service:hysteria-server",
            auto=True,
        )
        self.assertFalse(d["allowed"])

    def test_without_permission_denied(self):
        self.db.execute("DELETE FROM permissions")
        res = asyncio.run(
            self.inv.run(
                asset_id="sora",
                object_id="google",
                capability="asset.summary",
                actor_type="auto_rule",
                actor_id="agent",
            )
        )
        self.assertFalse(res.get("ok"))


if __name__ == "__main__":
    unittest.main()
