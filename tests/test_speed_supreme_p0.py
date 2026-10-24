"""P0：SSHTransport.exec_shell 与 MCP 工具层。"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database  # noqa: E402
from ayana.knowledge import KnowledgeBase  # noqa: E402
from ayana.incidents import IncidentService  # noqa: E402
from ayana.mcp_server import McpStdioServer, build_ops_context  # noqa: E402
from ayana.mcp_tools import McpToolError, OpsContext, OpsTools  # noqa: E402
from ayana.ntsafe import NTResult  # noqa: E402
from ayana.transport import SSHAssetStore, SSHTransport, TransportError  # noqa: E402
from ayana.credentials import CredentialStore  # noqa: E402


def make_db():
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "t.db")
    return tmp, db


class TestExecShell(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.store = SSHAssetStore(self.db)
        self.creds = CredentialStore(self.db, master_key="k")
        self.tr = SSHTransport(self.store, self.creds)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_empty_command_rejected(self):
        with self.assertRaises(TransportError) as cm:
            asyncio.run(self.tr.exec_shell("nerv", "   "))
        self.assertEqual(cm.exception.code, "bad_command")

    def test_null_byte_rejected(self):
        with self.assertRaises(TransportError) as cm:
            asyncio.run(self.tr.exec_shell("nerv", "echo\x00hi"))
        self.assertEqual(cm.exception.code, "unsafe_command")

    def test_metachar_command_reaches_endpoint_lookup(self):
        """通用命令允许元字符：不再因 unsafe_token 拒绝，而是走端点校验。"""
        with self.assertRaises(TransportError) as cm:
            asyncio.run(self.tr.exec_shell("nerv", "journalctl -u frps | tail -5"))
        self.assertNotEqual(cm.exception.code, "unsafe_token")
        self.assertIn(cm.exception.code, ("endpoint_missing", "host_key_untrusted"))

    def test_token_path_still_blocks_metachar(self):
        with self.assertRaises(TransportError) as cm:
            asyncio.run(self.tr.exec("nerv", ["echo", "a;b"]))
        self.assertEqual(cm.exception.code, "unsafe_token")


class FakeTransport:
    def __init__(self):
        self.calls = []

    async def exec_shell(self, asset_id, command, timeout=None, *, channel="write"):
        self.calls.append((asset_id, command, timeout, channel))
        return NTResult(ok=True, output="ok\n", returncode=0, mode="exec", account="u")


class FakeProm:
    async def query(self, expr):
        return {"status": "success", "data": {"resultType": "vector", "result": []}}


class TestMcpTools(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.kb = KnowledgeBase(self.db, root=self.tmp.name + "/kb")
        Path(self.tmp.name, "kb").mkdir(exist_ok=True)
        self.kb.reload()
        self.incidents = IncidentService(self.db)
        self.transport = FakeTransport()
        self.ctx = OpsContext(
            transport=self.transport,
            prom=FakeProm(),
            incidents=self.incidents,
            knowledge=self.kb,
            db=self.db,
        )
        self.tools = OpsTools(self.ctx)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_specs_names(self):
        names = {s["name"] for s in self.tools.specs()}
        self.assertEqual(
            names,
            {
                "host.exec",
                "metrics.query",
                "incident.list",
                "incident.get",
                "incident.note",
                "incident.close",
                "knowledge.query",
                "knowledge.get",
                "knowledge.upsert",
                "asset.list",
                "session.get",
                "session.write_ops",
            },
        )

    def test_host_exec(self):
        out = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "kanata", "command": "systemctl status ayana", "channel": "read"},
            )
        )
        self.assertTrue(out["ok"])
        self.assertEqual(self.transport.calls[0][1], "systemctl status ayana")
        self.assertEqual(self.transport.calls[0][3], "read")

    def test_host_exec_requires_command(self):
        with self.assertRaises(McpToolError):
            asyncio.run(self.tools.call("host.exec", {"asset_id": "kanata"}))

    def test_metrics_query(self):
        out = asyncio.run(self.tools.call("metrics.query", {"query": "up"}))
        self.assertTrue(out["ok"])

    def test_incident_note_and_get(self):
        self.db.execute(
            "INSERT INTO incidents(id, title, status, stage, asset_id, object_id, severity,"
            " created_at, updated_at) VALUES('inc_1','t','open','pending','kanata','mysql','warn',1,1)"
        )
        out = asyncio.run(
            self.tools.call("incident.note", {"incident_id": "inc_1", "text": "checked replica"})
        )
        self.assertTrue(out["ok"])
        got = asyncio.run(self.tools.call("incident.get", {"incident_id": "inc_1"}))
        self.assertTrue(got["ok"])
        self.assertEqual(got["incident"]["id"], "inc_1")

    def test_incident_close(self):
        self.db.execute(
            "INSERT INTO incidents(id, title, status, stage, asset_id, object_id, severity,"
            " created_at, updated_at) VALUES('inc_2','t','open','pending','kanata','mysql','warn',1,1)"
        )
        out = asyncio.run(
            self.tools.call("incident.close", {"incident_id": "inc_2", "reason": "restarted frps"})
        )
        self.assertTrue(out["ok"])
        row = self.db.query_one("SELECT status, outcome FROM incidents WHERE id='inc_2'")
        self.assertEqual(row["status"], "closed")

    def test_knowledge_query_and_get(self):
        md = Path(self.tmp.name, "kb", "issue-kanata-mysql.md")
        md.write_text(
            "---\n"
            "id: issue-kanata-mysql\n"
            "title: MySQL replica lag\n"
            "status: active\n"
            "type: issue\n"
            "objects: [kanata:mysql]\n"
            "tags: [replica]\n"
            "verified: result\n"
            "root_cause: unknown\n"
            "---\n"
            "## 现象\nreplica lag\n",
            encoding="utf-8",
        )
        self.kb.reload()
        out = asyncio.run(
            self.tools.call(
                "knowledge.query",
                {"asset_id": "kanata", "object": "mysql", "query": "replica"},
            )
        )
        self.assertTrue(out["ok"])
        self.assertEqual(out["docs"][0]["id"], "issue-kanata-mysql")
        full = asyncio.run(self.tools.call("knowledge.get", {"doc_id": "issue-kanata-mysql"}))
        self.assertIn("replica lag", full["knowledge"]["body"])

    def test_unknown_tool(self):
        with self.assertRaises(McpToolError):
            asyncio.run(self.tools.call("nope", {}))


class TestMcpServer(unittest.IsolatedAsyncioTestCase):
    async def test_initialize_and_tools_list(self):
        tmp, db = make_db()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(db.close)
        kb = KnowledgeBase(db, root=tmp.name + "/kb")
        Path(tmp.name, "kb").mkdir(exist_ok=True)
        kb.reload()
        ctx = OpsContext(
            transport=FakeTransport(),
            prom=FakeProm(),
            incidents=IncidentService(db),
            knowledge=kb,
            db=db,
        )
        srv = McpStdioServer(OpsTools(ctx))
        init = await srv.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}
        )
        self.assertEqual(init["result"]["serverInfo"]["name"], "ayana-mcp")
        lst = await srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(len(lst["result"]["tools"]), 12)
        call = await srv.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "host.exec", "arguments": {"asset_id": "a", "command": "true"}},
            }
        )
        self.assertFalse(call["result"]["isError"])
        payload = json.loads(call["result"]["content"][0]["text"])
        self.assertTrue(payload["ok"])

    async def test_tools_call_error_is_structured(self):
        tmp, db = make_db()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(db.close)
        kb = KnowledgeBase(db, root=tmp.name + "/kb")
        Path(tmp.name, "kb").mkdir(exist_ok=True)
        kb.reload()
        ctx = OpsContext(
            transport=FakeTransport(),
            prom=FakeProm(),
            incidents=IncidentService(db),
            knowledge=kb,
            db=db,
        )
        srv = McpStdioServer(OpsTools(ctx))
        call = await srv.handle(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "host.exec", "arguments": {"asset_id": "a"}},
            }
        )
        self.assertTrue(call["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
