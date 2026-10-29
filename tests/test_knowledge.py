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
from ayana.access import AccessControl as Policy

ROOT = Path(__file__).resolve().parents[1] / "knowledge"

# v0.7.3+ 发行版只带两个示例文档（去个人化）
DISTRO_IDS = {"service-probe-example", "ayana-port-bind-failed"}


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
        text = "---\nid: x\ntitle: T\nstatus: active\ntype: issue\nobjects:\n  - demo:svc-a\n  - demo:svc-b\ntags:\n  - a\n---\n\n# Body\nhello\n"
        meta, body = parse_front_matter(text)
        self.assertEqual(meta["id"], "x")
        self.assertEqual(meta["objects"], ["demo:svc-a", "demo:svc-b"])
        self.assertIn("# Body", body)
        self.assertNotIn("id:", body)


class TestMarkdownKnowledge(unittest.TestCase):
    def setUp(self):
        self.kb = KnowledgeBase(db=None, root=ROOT)

    def test_load_files(self):
        """发行版自带两个示例文档，不含个人环境文档。"""
        ids = {d.id for d in self.kb.list_docs()}
        self.assertEqual(ids, DISTRO_IDS)

    def test_distro_docs_structure(self):
        """两个文档均可解析，且 status/type 合法。"""
        example = self.kb.get("service-probe-example")
        self.assertIsNotNone(example)
        self.assertEqual(example.type, "system")
        # status "example" 不在 VALID_STATUS → 解析为 invalid，不得默认 active
        self.assertEqual(example.status, "invalid")
        issue = self.kb.get("ayana-port-bind-failed")
        self.assertIsNotNone(issue)
        self.assertEqual(issue.type, "issue")
        self.assertIn("bind", issue.body.lower())

    def test_one_md_multi_objects(self):
        """一个文档可关联多个对象（用临时文档验证机制）。"""
        tmp = self.kb.root / "_tmp_multi.md"
        tmp.write_text(
            "---\nid: multi-test\ntitle: multi\ntype: system\nstatus: active\nobjects:\n"
            "  - demo:svc-a\n  - demo:svc-b\n---\n# multi\nbody\n",
            encoding="utf-8",
        )
        try:
            self.kb.reload()
            docs = self.kb.docs_for_object("demo", "svc-a")
            self.assertTrue(any(d.id == "multi-test" for d in docs))
            names = set(docs[0].objects)
            self.assertIn("demo:svc-a", names)
            self.assertIn("demo:svc-b", names)
        finally:
            tmp.unlink(missing_ok=True)
            self.kb.reload()

    def test_find_by_registered_object_id(self):
        """asset:probe:object 形式的引用可命中。"""
        tmp = self.kb.root / "_tmp_probe.md"
        tmp.write_text(
            "---\nid: probe-test\ntitle: probe\ntype: system\nstatus: active\nobjects:\n"
            "  - demo:probe:svc-x\n---\n# probe\n",
            encoding="utf-8",
        )
        try:
            self.kb.reload()
            docs = self.kb.docs_for_object("demo", "demo:probe:svc-x")
            self.assertTrue(any(d.id == "probe-test" for d in docs))
        finally:
            tmp.unlink(missing_ok=True)
            self.kb.reload()

    def test_multi_object_share_theme(self):
        """多对象共同命中同一文档 → shared 语义。"""
        tmp = self.kb.root / "_tmp_shared.md"
        tmp.write_text(
            "---\nid: shared-test\ntitle: shared\ntype: system\nstatus: active\nobjects:\n"
            "  - demo:svc-a\n  - demo:svc-b\n---\n# shared\n",
            encoding="utf-8",
        )
        try:
            self.kb.reload()
            shared = self.kb.docs_for_objects(
                [("demo", "svc-a"), ("demo", "svc-b")]
            )
            self.assertIn("shared-test", shared["shared_ids"])
            ctx = self.kb.investigation_context("demo", "svc-a", extra_failures=["svc-b"])
            self.assertIn("shared-test", ctx["context_text"])
            self.assertTrue(ctx["shared_docs"])
            self.assertIn("共同命中", ctx["common"]["shared_failure_meaning"])
        finally:
            tmp.unlink(missing_ok=True)
            self.kb.reload()

    def test_active_only_for_investigation(self):
        # 临时 deprecated 文档
        tmp = self.kb.root / "_tmp_dep.md"
        tmp.write_text(
            "---\nid: dep-test\ntitle: old\ntype: system\nstatus: active\nobjects:\n  - demo:svc-a\n---\n# old\n",
            encoding="utf-8",
        )
        try:
            self.kb.reload()
            active = self.kb.docs_for_object("demo", "svc-a", include_inactive=False)
            all_docs = self.kb.docs_for_object("demo", "svc-a", include_inactive=True)
            self.assertTrue(all_docs)
            # status defaults to active when missing; mark as deprecated
            d = self.kb.get("dep-test")
            self.assertIsNotNone(d)
            # force status
            d.status = "deprecated"
            active2 = [x for x in self.kb.docs_for_object("demo", "svc-a") if x.status == "active"]
            self.assertFalse(any(x.id == "dep-test" for x in active2))
            ctx = self.kb.investigation_context("demo", "svc-a")
            self.assertNotIn("dep-test", ctx["context_text"])
            self.assertTrue(any(h["id"] == "dep-test" for h in ctx["historical_docs"]))
        finally:
            tmp.unlink(missing_ok=True)
            self.kb.reload()

    def test_issue_knowledge_lookup(self):
        """发行版 issue 文档可按 id 取回（objects 为空的示例不做对象匹配）。"""
        d = self.kb.get("ayana-port-bind-failed")
        self.assertIsNotNone(d)
        self.assertEqual(d.type, "issue")
        # 按 id 检索可用
        hits = self.kb.list_docs(q="ayana-port-bind")
        self.assertTrue(any(x.id == "ayana-port-bind-failed" for x in hits))


class TestInvestigationUsesMarkdown(unittest.TestCase):
    """知识正文注入：MiMoCode 经 knowledge.query/get 获取 Markdown 正文。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        t = 1.0
        self.db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " prom_asset, enabled, notes, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,1,'',?,?)",
            ("demo", "Demo", "demo", "demo-exec", "demo", "demo", t, t),
        )
        self.kb = KnowledgeBase(self.db, root=ROOT)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_knowledge_injects_md_body(self):
        """命中对象的知识文档返回 Markdown 正文。"""
        tmp = self.kb.root / "_tmp_inv.md"
        tmp.write_text(
            "---\nid: inv-test\ntitle: inv\ntype: issue\nstatus: active\nobjects:\n"
            "  - demo:svc-a\n---\n# inv\nINJECTED_MARKER\n",
            encoding="utf-8",
        )
        try:
            self.kb.reload()
            knol = self.kb.investigation_context("demo", "svc-a")
            self.assertTrue(knol.get("docs"))
            self.assertIn("INJECTED_MARKER", knol.get("context_text", ""))
            self.assertIn("inv-test", knol.get("context_text", ""))
        finally:
            tmp.unlink(missing_ok=True)
            self.kb.reload()


if __name__ == "__main__":
    unittest.main()
