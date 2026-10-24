"""P1：knowledge.upsert 自动 active + 相似合并。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.knowledge import KnowledgeBase, format_doc  # noqa: E402
from ayana.mcp_tools import OpsContext, OpsTools  # noqa: E402


class FakeTransport:
    async def exec_shell(self, *a, **k):
        raise NotImplementedError


class FakeProm:
    async def query(self, expr):
        return {"status": "success", "data": {"result": []}}


class FakeIncidents:
    def get_incident(self, *a, **k):
        return None


class TestKnowledgeUpsert(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name) / "kb"
        self.root.mkdir()
        self.kb = KnowledgeBase(None, root=self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_active_verified(self):
        res = self.kb.upsert(
            title="MySQL replica lag",
            type="issue",
            objects=["kanata:mysql"],
            tags=["replica"],
            body="## 现象\nlag\n## 有效命令\nSHOW SLAVE STATUS\n",
            verified="result",
            root_cause="unknown",
            source_incident="inc_1",
            verified_at="2026-10-24T13:00:00Z",
        )
        self.assertEqual(res["action"], "created")
        self.assertEqual(res["status"], "active")
        self.assertEqual(res["verified"], "result")
        doc = self.kb.get(res["doc_id"])
        self.assertIsNotNone(doc)
        self.assertEqual(doc.revision, 1)
        self.assertTrue(doc.usable_for_context())
        # 文件落盘且 front matter 可回读
        raw = Path(doc.path).read_text(encoding="utf-8")
        self.assertIn("verified: result", raw)
        self.assertIn("root_cause: unknown", raw)

    def test_speculation_not_usable_for_context(self):
        res = self.kb.upsert(
            title="MySQL replica lag guess",
            type="issue",
            objects=["kanata:mysql"],
            tags=["replica"],
            body="猜测是网络抖动，未验证。",
            verified="speculation",
        )
        doc = self.kb.get(res["doc_id"])
        # 允许入库，但不得当已验证事实；active+speculation → 降为 draft
        self.assertEqual(doc.verified, "speculation")
        self.assertFalse(doc.usable_for_context())
        self.assertNotIn(doc, self.kb.docs_for_object("kanata", "mysql"))

    def test_speculation_cannot_pollute_verified_fact(self):
        """推测不得合并进 verified=result 条目并把它降级。"""
        created = self.kb.upsert(
            title="frps TargetDown recovery",
            type="issue",
            objects=["nerv:frps"],
            tags=["frps"],
            body="restart + probe_success=1 on 32659",
            verified="result",
            root_cause="unknown",
        )
        polluted = self.kb.upsert(
            title="frps 端口是 7000/7500",
            type="issue",
            objects=["nerv:frps"],
            tags=["frps"],
            body="猜测 7000/7500，未验证",
            verified="speculation",
        )
        self.assertEqual(polluted["action"], "created", "推测必须另立稿，不得 merged")
        self.assertNotEqual(polluted["doc_id"], created["doc_id"])
        fact = self.kb.get(created["doc_id"])
        self.assertEqual(fact.verified, "result")
        self.assertEqual(fact.status, "active")
        self.assertEqual(fact.revision, 1)
        self.assertTrue(fact.usable_for_context())
        guess = self.kb.get(polluted["doc_id"])
        self.assertEqual(guess.verified, "speculation")
        self.assertFalse(guess.usable_for_context())
        ctx_ids = [d.id for d in self.kb.docs_for_object("nerv", "frps")]
        self.assertIn(created["doc_id"], ctx_ids)
        self.assertNotIn(polluted["doc_id"], ctx_ids)

    def test_similar_merges_revision(self):
        self.kb.upsert(
            title="MySQL replica lag",
            type="issue",
            objects=["kanata:mysql"],
            tags=["replica"],
            body="## 现象\nlag on replica\n",
            verified="result",
            source_incident="inc_1",
        )
        res2 = self.kb.upsert(
            title="MySQL replica lag on kanata",
            type="issue",
            objects=["kanata:mysql"],
            tags=["replica", "mysql"],
            body="## 现象\nlag again\n## 修复与验证\nrestart replica thread\n",
            verified="result",
            source_incident="inc_2",
            change_note="补充重启复制线程步骤",
        )
        self.assertEqual(res2["action"], "updated")
        self.assertEqual(res2["revision"], 2)
        docs = self.kb.list_docs()
        self.assertEqual(len(docs), 1)
        self.assertIn("变更说明", self.kb.get(res2["doc_id"]).body)

    def test_different_object_creates_new(self):
        self.kb.upsert(
            title="MySQL replica lag",
            type="issue",
            objects=["kanata:mysql"],
            tags=["replica"],
            body="lag",
            verified="result",
        )
        res = self.kb.upsert(
            title="MySQL replica lag",
            type="issue",
            objects=["nerv:mysql"],
            tags=["replica"],
            body="lag",
            verified="result",
        )
        self.assertEqual(res["action"], "created")
        self.assertEqual(len(self.kb.list_docs()), 2)

    def test_deprecate_invalidates(self):
        res = self.kb.upsert(
            title="Bad advice",
            type="issue",
            objects=["kanata:mysql"],
            tags=["bad"],
            body="rm -rf /",
            verified="result",
        )
        d = self.kb.deprecate(res["doc_id"], reason="错误经验")
        self.assertTrue(d["ok"])
        doc = self.kb.get(res["doc_id"])
        self.assertEqual(doc.status, "deprecated")
        self.assertFalse(doc.usable_for_context())

    def test_format_roundtrip(self):
        self.kb.upsert(
            title="Ayana port bind",
            type="issue",
            objects=["kanata:ayana"],
            tags=["6200"],
            body="## 现象\nbind fail\n",
            verified="result",
            root_cause="stale process",
        )
        doc = self.kb.list_docs()[0]
        raw = format_doc(doc)
        self.assertTrue(raw.startswith("---"))
        again = self.kb  # reload path
        again.reload()
        d2 = again.get(doc.id)
        self.assertEqual(d2.root_cause, "stale process")
        self.assertEqual(d2.revision, 1)


class TestMcpKnowledgeUpsert(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name) / "kb"
        self.root.mkdir()
        self.kb = KnowledgeBase(None, root=self.root)
        self.tools = OpsTools(
            OpsContext(
                transport=FakeTransport(),
                prom=FakeProm(),
                incidents=FakeIncidents(),
                knowledge=self.kb,
                db=None,
            )
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_upsert_via_mcp(self):
        out = asyncio.run(
            self.tools.call(
                "knowledge.upsert",
                {
                    "title": "frps down",
                    "type": "issue",
                    "objects": ["nerv:frps"],
                    "tags": ["frps"],
                    "body": "## 现象\nTargetDown\n## 修复与验证\nreset-failed+restart; probe=1\n",
                    "verified": "result",
                    "root_cause": "unknown",
                    "source_incident": "inc_b520fdebd01a",
                },
            )
        )
        self.assertTrue(out["ok"])
        self.assertEqual(out["action"], "created")
        again = asyncio.run(
            self.tools.call(
                "knowledge.upsert",
                {
                    "title": "frps TargetDown on nerv",
                    "objects": ["nerv:frps"],
                    "tags": ["frps"],
                    "body": "## 现象\nTargetDown\n## 有效命令\nss -lnt\n",
                    "verified": "result",
                },
            )
        )
        self.assertEqual(again["action"], "updated")
        self.assertEqual(again["revision"], 2)

    def test_upsert_requires_objects(self):
        with self.assertRaises(Exception):
            asyncio.run(self.tools.call("knowledge.upsert", {"title": "x"}))


if __name__ == "__main__":
    unittest.main()
