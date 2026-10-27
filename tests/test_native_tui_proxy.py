"""Exercise the real HTTP/SSE scope proxy against a local native API fixture.

No model calls: these tests check protocol compatibility, ownership and safety.
"""
import asyncio
import base64
import json
import tempfile
import time
import unittest
from pathlib import Path

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from ayana.agent_tui import AgentTuiManager, TERMINAL_REPLY
from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.mimo_serve import MimoServeClient


class NativeProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "db.sqlite")
        self.duty = DutySessionManager(self.db)
        self.sid = self.duty.create(origin="manual", created_by="admin")["session_id"]
        self.rid = "ses_native"
        self.db.execute("UPDATE duty_sessions SET remote_session_id=? WHERE id=?", (self.rid, self.sid))
        self.duty.set_runtime_state(self.sid, "idle")
        self.db.execute("UPDATE agent_runtime_bindings SET remote_session_id=? WHERE session_id=?", (self.rid, self.sid))
        self.calls = []
        self.busy = False
        self.history = []
        self.receipt_response = True
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.upstream)
        self.server = TestServer(app)
        await self.server.start_server()
        native = MimoServeClient(base_url=str(self.server.make_url("")).rstrip("/"), password="upstream-only", directory="/native/work")
        self.manager = AgentTuiManager(self.db, lambda: native, workdir="/native/work",
            home=str(Path(self.tmp.name) / "home"), state_dir=str(Path(self.tmp.name) / "tui"),
            proxy_port=0, runtime_resolver=lambda: {"model": "verified/model"})
        await self.manager.start()
        token = self.manager._token(self.sid, self.rid)
        self.http = ClientSession(headers={"Authorization": "Basic " + base64.b64encode(("ayana-tui:" + token).encode()).decode()})
        self.url = self.manager.proxy_url

    async def asyncTearDown(self):
        await self.http.close()
        await self.manager.stop()
        await self.server.close()
        self.db.close()
        self.tmp.cleanup()

    async def upstream(self, request):
        body = await request.json() if request.can_read_body else None
        self.calls.append((request.method, request.path, dict(request.query), body))
        if request.path == "/event":
            frames = [
                {"type": "server.connected", "properties": {}},
                {"type": "session.updated", "properties": {"info": {"id": "ses_other", "title": "PRIVATE"}}},
                {"type": "message.part.delta", "properties": {"delta": "UNOWNED"}},
                {"type": "message.updated", "properties": {"info": {"sessionID": self.rid, "id": "msg_native"}}},
                {"type": "message.part.updated", "properties": {"part": {"sessionID": self.rid, "text": "REAL_NATIVE_OUTPUT"}}},
                {"type": "session.status", "properties": {"sessionID": self.rid, "status": {"type": "idle"}}},
            ]
            return web.Response(text="".join("data: " + json.dumps(item) + "\n\n" for item in frames), content_type="text/event-stream")
        if request.path == "/session/status":
            return web.json_response({self.rid: {"type": "busy"}} if self.busy else {})
        if request.path == "/agent":
            return web.json_response([{"name": "ayana-readonly", "permission": [{"permission": "*", "action": "deny", "pattern": "*"}]}, {"name": "build"}])
        if request.path.endswith("/prompt_async"):
            if not self.receipt_response:
                return web.json_response({"accepted": True}, status=202)
            return web.json_response({"receiptId": "receipt_native"}, status=202)
        if request.path.endswith("/message"):
            return web.json_response(self.history)
        if request.path == "/session/" + self.rid:
            return web.json_response({"id": self.rid, "directory": self.manager.workdir, "title": "test"})
        return web.json_response([])

    def control(self):
        self.manager._connections["live_connection"] = {"session_id": self.sid, "username": "admin"}
        self.manager.acquire_control(self.sid, "admin", "live_connection")

    async def prompt(self, body=None):
        return await self.http.post(self.url + "/session/" + self.rid + "/prompt_async", json=body or {
            "messageID": "msg_original", "agent": "build", "model": {"providerID": "evil", "modelID": "evil"},
            "parts": [{"id": "prt_original", "type": "text", "text": "inspect"}], "system": "override", "tools": {"bash": True}})

    async def test_native_global_stream_has_envelope_and_only_own_rid(self):
        async with self.http.get(self.url + "/global/event") as response:
            self.assertEqual(response.status, 200)
            body = await response.text()
        frames = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]
        self.assertTrue(frames)
        self.assertTrue(all(item["directory"] == self.manager.workdir for item in frames))
        self.assertIn("REAL_NATIVE_OUTPUT", body)
        self.assertNotIn("PRIVATE", body)
        self.assertNotIn("UNOWNED", body)
        self.assertTrue(all("payload" in item for item in frames))

    async def test_native_flat_stream_remains_compatible(self):
        async with self.http.get(self.url + "/event") as response:
            text = await response.text()
        self.assertIn('"type": "message.updated"', text)
        self.assertNotIn('"payload"', text)

    async def test_bootstrap_routes_and_query_scope(self):
        for suffix in ("actors", "task", "recovery", "children", "todo", "diff", "message"):
            async with self.http.get(self.url + "/session/" + self.rid + "/" + suffix, params={"agent_id": "*", "limit": "100", "directory": "/evil"}) as response:
                self.assertEqual(response.status, 200, suffix)
            self.assertEqual(self.calls[-1][2]["directory"], self.manager.workdir)
            self.assertEqual(self.calls[-1][2]["agent_id"], "*")

    async def test_agent_info_keeps_native_ruleset_and_hides_unrestricted_agent(self):
        async with self.http.get(self.url + "/agent") as response:
            data = await response.json()
        self.assertEqual([item["name"] for item in data], ["ayana-readonly"])
        self.assertIsInstance(data[0]["permission"], list)

    async def test_native_prompt_preserves_ids_and_forces_verified_permissions(self):
        self.control()
        async with await self.prompt() as response:
            self.assertEqual(response.status, 202)
        body = [item[3] for item in self.calls if item[0] == "POST"][0]
        self.assertEqual(body["messageID"], "msg_original")
        self.assertEqual(body["parts"][0]["id"], "prt_original")
        self.assertEqual(body["agent"], "ayana-readonly")
        self.assertEqual(body["model"], {"providerID": "verified", "modelID": "model"})
        self.assertNotIn("system", body)
        self.assertNotIn("tools", body)
        row = self.db.query_one("SELECT * FROM agent_runtime_receipts WHERE receipt_id='receipt_native'")
        self.assertEqual(row["origin"], "tui")
        self.assertEqual(row["session_id"], self.sid)

    async def test_accepted_turn_blocks_second_native_input(self):
        self.control()
        responses = await asyncio.gather(self.prompt(), self.prompt())
        self.assertEqual(sorted(response.status for response in responses), [202, 409])
        for response in responses:
            response.release()
        self.assertEqual(sum(item[0] == "POST" for item in self.calls), 1)

    async def test_same_native_busy_admits_human_guidance_to_durable_queue(self):
        self.control(); self.busy = True
        async with await self.prompt() as response:
            self.assertEqual(response.status, 202)
        self.assertEqual(sum(item[0] == "POST" for item in self.calls),1)
        row=self.db.query_one("SELECT * FROM agent_runtime_receipts WHERE session_id=?",(self.sid,))
        self.assertEqual(row["remote_session_id"],self.rid)
        self.assertEqual(row["status"],"queued")
        self.assertFalse(any(item[1].endswith('/abort') for item in self.calls))

    async def test_unacknowledged_submission_becomes_unknown_and_never_replays(self):
        self.control(); self.receipt_response = False
        for _ in range(2):
            async with await self.prompt() as response:
                self.assertEqual(response.status, 409)
        self.assertEqual(sum(item[0] == "POST" for item in self.calls), 1)
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))

    async def test_welcome_creates_no_second_native_session(self):
        self.control()
        async with self.http.post(self.url + "/session", json={"titleLocale": "zh-CN"}) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual((await response.json())["id"], self.rid)
        self.assertFalse(any(item[0] == "POST" for item in self.calls))

    async def test_native_empty_body_session_create_uses_reserved_rid(self):
        self.control()
        async with self.http.post(self.url + "/session") as response:
            self.assertEqual(response.status, 200)
            self.assertEqual((await response.json())["id"], self.rid)
        self.assertFalse(any(item[0] == "POST" for item in self.calls))

    async def test_new_web_process_credentials_work_without_runtime_token_reload(self):
        token = self.manager._token(self.sid, self.rid)
        self.manager._tokens.clear()
        header = {"Authorization": "Basic " + base64.b64encode((self.sid + ":" + token).encode()).decode()}
        async with self.http.get(self.url + "/session/" + self.rid, headers=header) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual((await response.json())["id"], self.rid)
        header = {"Authorization": "Basic " + base64.b64encode((self.sid + ":wrong").encode()).decode()}
        async with self.http.get(self.url + "/session/" + self.rid, headers=header) as response:
            self.assertEqual(response.status, 401)

    async def test_separate_web_manager_issues_credentials_and_control_after_proxy_start(self):
        web_db = Database(Path(self.tmp.name) / "db.sqlite")
        try:
            web_manager = AgentTuiManager(web_db, self.manager.serve_client_factory,
                workdir=self.manager.workdir, home=self.manager.home, state_dir=str(self.manager.state_dir),
                proxy_port=self.manager.proxy_port, runtime_resolver=lambda: {"model": "verified/model"})
            token = web_manager._token(self.sid, self.rid)
            self.manager._tokens.clear()
            web_manager._connections["web_socket"] = {"session_id": self.sid, "username": "admin"}
            web_manager.acquire_control(self.sid, "admin", "web_socket")
            self.assertEqual(self.manager._connections, {})
            header = {"Authorization": "Basic " + base64.b64encode((self.sid + ":" + token).encode()).decode()}
            async with self.http.post(self.url + "/session/" + self.rid + "/prompt_async", headers=header,
                    json={"messageID": "msg_cross_process", "parts": [{"type": "text", "text": "inspect"}]}) as response:
                self.assertEqual(response.status, 202)
            receipt = web_db.query_one("SELECT session_id,status FROM agent_runtime_receipts WHERE receipt_id='receipt_native'")
            self.assertEqual(receipt["session_id"], self.sid)
            self.assertEqual(receipt["status"], "accepted")
        finally:
            web_db.close()

    async def test_welcome_cannot_replace_session_with_existing_history(self):
        self.control(); self.history = [{"info": {"id": "msg_existing"}}]
        async with self.http.post(self.url + "/session", json={}) as response:
            self.assertEqual(response.status, 409)

    async def test_observer_cannot_prompt_or_create(self):
        async with await self.prompt() as response:
            self.assertEqual(response.status, 409)
        async with self.http.post(self.url + "/session", json={}) as response:
            self.assertEqual(response.status, 409)

    async def test_shell_permission_and_other_session_routes_stay_forbidden(self):
        self.control()
        for path in ("/session/ses_other/message", "/session/" + self.rid + "/shell", "/permission/allow", "/config", "/session/" + self.rid + "/command"):
            async with self.http.post(self.url + path, json={"command": "id"}) as response:
                self.assertEqual(response.status, 403, path)

    async def test_archived_session_allows_history_but_no_prompt(self):
        self.control()
        self.db.execute("UPDATE duty_sessions SET status='archived' WHERE id=?", (self.sid,))
        async with self.http.get(self.url + "/session/" + self.rid + "/message") as response:
            self.assertEqual(response.status, 200)
        async with await self.prompt() as response:
            self.assertEqual(response.status, 403)

    def test_ambiguous_or_mixed_session_events_are_rejected(self):
        self.assertFalse(self.manager._event_matches({"type": "message.part.delta", "properties": {"messageID": "msg_other"}}, self.rid))
        self.assertFalse(self.manager._event_matches({"type": "message.part.updated", "properties": {"sessionID": self.rid, "part": {"sessionID": "ses_other"}}}, self.rid))

    def test_observer_terminal_reports_cannot_encode_user_instructions(self):
        for report in ("\x1b[1;1R", "\x1b[?1;2c", "\x1b[>0;276;0c", "\x1b[8;24;80t", "\x1b]11;rgb:0000/0000/0000\x07", "\x1b[?2026;2$y", "\x1b[?1004;0$y"):
            self.assertIsNotNone(TERMINAL_REPLY.fullmatch(report))
        for instruction in ("inspect", "\r", "\x1b[13u", "\x1b[97u", "\x1b[1;1Rinspect\r", "\x1b]52;c;c2VjcmV0\x07", "\x1b[?2026;9$y", "\x1b[?9999;1$y", "\x1b[?2026;2$yinspect\r"):
            self.assertIsNone(TERMINAL_REPLY.fullmatch(instruction))


if __name__ == "__main__":
    unittest.main()
