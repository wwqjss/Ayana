"""Saved SSH identities survive group assignment; selections drive real dispatch."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from aiohttp import web

from ayana.db import Database, now
from ayana.duty_session import DutySessionManager
from ayana.exec_facts import NTResult
from ayana.mcp_tools import McpToolError, OpsContext, OpsTools
from ayana.session_bridge import SessionBridge
from ayana.terminal import TerminalError, TerminalService
from ayana.transport import SSHAssetStore, SSHTransport, TransportError, session_ssh_scope
from ayana.web import WebApp


class SSHFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Database(Path(self.temp.name) / "state.db")
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO assets(id,display_name,host,read_alias,write_alias,created_at,updated_at)"
                        " VALUES('host','Host','host.example','','',?,?)", (now(), now()))
        self.store = SSHAssetStore(self.db)
        self.store.add_role(name="ops")
        self.store.upsert_endpoint(asset_id="host", role="default", host="host.example",
                                   username="root", credential_id="original")
        self.store.trust_host_key("host", "default", "SHA256:known", key_line="host.example ssh-ed25519 AAAA")
        self.duty = DutySessionManager(self.db)
        self.sid = self.duty.create(created_by="admin")["session_id"]

    def endpoint(self, role="default"):
        return self.store.get_endpoint("host", role)


class EndpointPreservationTests(SSHFixture):
    def test_omitted_credential_preserves_saved_account_and_trust(self):
        original = self.endpoint()
        self.store.upsert_endpoint(asset_id="host", role="default", host="host.example", username="root")
        current = self.endpoint()
        for field in ("id", "credential_id", "host_key_sha256", "host_key_line", "host_key_trusted_at"):
            self.assertEqual(current[field], original[field])

    def test_explicit_blank_clears_credential(self):
        self.store.upsert_endpoint(asset_id="host", role="default", host="host.example", username="root", credential_id="")
        self.assertEqual(self.endpoint()["credential_id"], "")
        self.assertEqual(self.endpoint()["host_key_sha256"], "SHA256:known")

    def test_changed_host_or_port_requires_new_trust(self):
        for host, port in (("other.example", 22), ("host.example", 2200)):
            with self.subTest(host=host, port=port):
                self.store.trust_host_key("host", "default", "SHA256:known", key_line="host.example ssh-ed25519 AAAA")
                self.store.upsert_endpoint(asset_id="host", role="default", host=host, port=port, username="root")
                current = self.endpoint()
                self.assertEqual(current["host_key_sha256"], "")
                self.assertEqual(current["host_key_line"], "")
                self.assertIsNone(current["host_key_trusted_at"])


class SSHWebTests(SSHFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.user = {"username": "admin", "is_admin": True}
        self.app = WebApp.__new__(WebApp)
        self.app.db, self.app.ssh_store, self.app.duty = self.db, self.store, self.duty
        self.app.incidents = SimpleNamespace(duty=self.duty)
        self.app._require_auth = lambda request: self.user
        self.app._check_csrf = lambda *args: None

    def request(self, body, *, sid=None):
        async def data():
            return body
        return SimpleNamespace(json=data, match_info={"sid": sid or self.sid})

    async def assign(self, **fields):
        return await self.app.api_ssh_account_add(self.request({"asset_id": "host", "group": "ops", **fields}))

    async def test_existing_account_group_assignment_keeps_credential_and_trusted_pin(self):
        result = await self.assign(credential_id="", username="root")
        self.assertEqual(result.status, 200)
        target = self.endpoint("ops")
        self.assertEqual(target["credential_id"], "original")
        self.assertEqual(target["host_key_sha256"], "SHA256:known")
        self.assertEqual(target["host_key_line"], self.endpoint()["host_key_line"])
        self.assertTrue(target["host_key_trusted_at"])

    async def test_explicit_other_credential_is_kept_without_copying_account_trust(self):
        response = await self.assign(credential_id="chosen", username="root")
        self.assertEqual(response.status, 200)
        self.assertEqual(self.endpoint("ops")["credential_id"], "chosen")
        self.assertIsNone(self.endpoint("ops")["host_key_trusted_at"])

    async def test_new_host_port_or_user_does_not_copy_a_different_account(self):
        for changes in ({"host": "other.example"}, {"port": 2200}, {"username": "observer"}):
            with self.subTest(changes=changes):
                self.store.delete_endpoint("host", "ops")
                self.assertEqual((await self.assign(**changes)).status, 200)
                target = self.endpoint("ops")
                self.assertEqual(target["credential_id"], "")
                self.assertIsNone(target["host_key_trusted_at"])

    async def test_generic_endpoint_route_preserves_missing_and_honors_explicit_clear(self):
        body = {"asset_id": "host", "role": "default", "host": "host.example", "username": "root"}
        self.assertEqual((await self.app.api_ssh_endpoint_upsert(self.request(body))).status, 200)
        self.assertEqual(self.endpoint()["credential_id"], "original")
        self.assertEqual((await self.app.api_ssh_endpoint_upsert(self.request({**body, "credential_id": ""}))).status, 200)
        self.assertEqual(self.endpoint()["credential_id"], "")

    async def test_session_switch_and_reset_follow_global_selection(self):
        response = await self.app.api_agent_session_account_group(self.request({"group": "ops"}))
        reply = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(reply["effective_permissions"]["ssh_account_group"], "ops")
        self.assertEqual(reply["effective_permissions"]["ssh_account_group_source"], "session")
        response = await self.app.api_agent_session_account_group(self.request({"group": ""}))
        reply = json.loads(response.body)
        self.assertEqual(reply["effective_permissions"]["ssh_account_group"], "default")
        self.assertEqual(reply["effective_permissions"]["ssh_account_group_source"], "global")

    async def test_invalid_group_or_viewer_cannot_switch(self):
        response = await self.app.api_agent_session_account_group(self.request({"group": "missing"}))
        self.assertEqual(response.status, 400)
        self.assertEqual(json.loads(response.body)["error"], "ssh_account_group_not_found")
        self.user["is_admin"] = False
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_agent_session_account_group(self.request({"group": "ops"}))
        self.assertEqual(self.duty.get(self.sid)["ssh_account_group"], "")

    async def test_global_api_exposes_one_group_for_all_purposes(self):
        response = await self.app.api_agent_settings_post(self.request({"ssh_default_group": "ops"}))
        self.assertEqual(response.status, 200)
        settings = json.loads((await self.app.api_agent_settings_get(self.request({}))).body)
        self.assertEqual(settings["settings"]["ssh_default_group"], "ops")
        self.assertNotIn("ssh_investigate_role", settings["settings"])
        self.assertNotIn("ssh_execute_role", settings["settings"])
        self.assertEqual({group["name"] for group in settings["ssh_roles"]}, {"default", "ops"})

    async def test_retired_form_filler_returns_410_without_loading_deleted_module(self):
        response = await self.app.api_assist_configure(self.request({"domain": "checks", "text": "monitor"}))
        self.assertEqual(response.status, 410)
        self.assertTrue(json.loads(response.body)["retired"])

    async def test_retired_action_approval_cannot_dispatch_or_mutate_historical_write(self):
        bridge = SessionBridge(self.db, duty=self.duty)
        self.app.session_bridge = bridge
        self.app.transport = SimpleNamespace(exec_shell=AsyncMock())
        bridge.claim_write("old-incident", "old-action", target="host")
        self.db.execute("UPDATE session_write_ops SET status='awaiting_approval' WHERE action_key='old-action'")
        for handler in (self.app.api_agent_pending_approve, self.app.api_agent_pending_reject):
            response = await handler(self.request({"incident_id": "old-incident", "action_key": "old-action"}))
            self.assertEqual(response.status, 410)
            self.assertTrue(json.loads(response.body)["retired"])
        self.app.transport.exec_shell.assert_not_awaited()
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops WHERE action_key='old-action'")["status"],
                         "awaiting_approval")

    async def test_retired_action_tool_cannot_reenter_old_dispatcher(self):
        loop = SimpleNamespace(run_action_and_verify=AsyncMock())
        tools = OpsTools(OpsContext(transport=None, prom=None, incidents=None, knowledge=None, db=self.db, ops_loop=loop))
        self.assertNotIn("action.execute", {spec["name"] for spec in tools.specs()})
        with self.assertRaises(McpToolError) as error:
            await tools.call("action.execute", {"incident_id": "old", "asset_id": "host"})
        self.assertEqual(error.exception.code, "tool_retired")
        loop.run_action_and_verify.assert_not_awaited()

    async def test_retired_permission_switch_cannot_change_account_group_or_dispatch(self):
        self.app.agent_tui = SimpleNamespace(change_permissions=Mock())
        response = await self.app.api_agent_session_permissions(self.request({
            "access_mode": "readonly", "approval_mode": "manual", "revision": 1, "connection_id": "old"}))
        self.assertEqual(response.status, 410)
        self.app.agent_tui.change_permissions.assert_not_called()
        self.assertEqual(self.duty.get(self.sid)["ssh_account_group"], "")

    async def test_connection_page_tests_exact_group_and_reports_effective_group(self):
        self.app.cred_store = None
        self.store.upsert_endpoint(asset_id="host", role="ops", host="host.example", username="operator")
        for selection in ("ops", "missing"):
            request = self.request({"role": selection})
            request.match_info = {"asset_id": "host"}
            response = await self.app.api_asset_channel_test(request)
            result = json.loads(response.body)
            self.assertEqual(result["account_group"], selection)
            self.assertFalse(result["ok"])
            self.assertEqual(result["ssh_configured"], selection == "ops")
            self.assertEqual(result["detail"], "endpoint_without_credential" if selection == "ops" else "ssh_not_configured")
        self.duty.set_setting("ssh_default_group", "ops")
        request = self.request({})
        request.match_info = {"asset_id": "host"}
        result = json.loads((await self.app.api_asset_channel_test(request)).body)
        self.assertEqual((result["account_group"], result["detail"]), ("ops", "endpoint_without_credential"))

    async def test_key_switch_missing_group_cannot_modify_different_group_account(self):
        self.app.cred_store = SimpleNamespace(rotate=Mock(), reveal_secret=Mock())
        before = dict(self.endpoint())
        response = await self.app.api_ssh_switch_to_key(self.request({"asset_id": "host", "role": "missing"}))
        self.assertEqual(response.status, 400)
        self.assertEqual(json.loads(response.body)["error"], "no_ssh_endpoint")
        self.assertEqual(dict(self.endpoint()), before)
        self.app.cred_store.rotate.assert_not_called()
        self.app.cred_store.reveal_secret.assert_not_called()

    async def test_terminal_precheck_reports_and_requires_requested_group(self):
        self.app.terminal = SimpleNamespace(stats=lambda: {})
        self.app._session = lambda request: self.user
        self.app._terminal_ok = lambda *args: None
        request = self.request({})
        request.rel_url = SimpleNamespace(query={"asset_id": "host", "role": "ops"})
        result = json.loads((await self.app.api_terminal_check(request)).body)
        self.assertEqual((result["account_group"], result["detail"]), ("ops", "no_ssh_endpoint"))

    def test_asset_form_defaults_to_global_account_group(self):
        self.duty.set_setting("ssh_default_group", "ops")
        self.assertEqual(self.app._asset_payload({"id": "new-host", "host": "host.example"})["role"], "ops")


class ActualDispatchGroupTests(SSHFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.store.upsert_endpoint(asset_id="host", role="ops", host="host.example", username="operator")
        self.store.trust_host_key("host", "ops", "SHA256:known", key_line="host.example ssh-ed25519 AAAA")
        self.transport = SSHTransport(self.store, None)

    async def test_connection_test_uses_requested_group_instead_of_global_default(self):
        process = SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(b"healthy", b"")))
        with patch("ayana.transport.fetch_host_key", new=AsyncMock(return_value={"ok": True, "fingerprint": "SHA256:known"})), \
                patch("ayana.transport.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
            result = await self.transport.test_connection("host", "ops")
        self.assertEqual((result["account_group"], result["account"]), ("ops", "operator"))
        argv = spawn.call_args.args
        self.assertEqual(argv[argv.index("-l") + 1], "operator")

    async def test_connection_test_missing_requested_group_never_uses_default(self):
        self.store.delete_endpoint("host", "ops")
        with patch("ayana.transport.asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            with self.assertRaises(TransportError) as error:
                await self.transport.test_connection("host", "ops")
        self.assertEqual(error.exception.code, "endpoint_missing")
        spawn.assert_not_awaited()

    async def test_human_terminal_uses_global_default_and_rejects_missing_explicit_group(self):
        self.duty.set_setting("ssh_default_group", "ops")
        terminal = TerminalService(self.db, self.store, None)
        # ops has no credential; default has one. Reaching no_credential proves
        # the global choice is honored without opening an SSH connection.
        with self.assertRaises(TerminalError) as error:
            await terminal.create(asset_id="host", username="admin")
        self.assertEqual(error.exception.code, "no_credential")
        with self.assertRaises(TerminalError) as error:
            await terminal.create(asset_id="host", role="missing", username="admin")
        self.assertEqual(error.exception.code, "no_ssh_endpoint")

    def test_node_exporter_uses_global_group_and_never_local_fallback_for_missing_group(self):
        app = WebApp.__new__(WebApp)
        app.transport = self.transport
        app.promconfig = SimpleNamespace(cfg_local_assets=lambda: ["host"])
        self.duty.set_setting("ssh_default_group", "ops")
        self.assertIs(app._ne_transport("host"), self.transport)
        self.store.delete_endpoint("host", "ops")
        with self.assertRaises(web.HTTPForbidden) as error:
            app._ne_transport("host")
        self.assertEqual(json.loads(error.exception.text)["error"], "configured_ssh_endpoint_missing")

    async def test_next_dispatch_uses_selected_account_for_both_read_and_write(self):
        process = SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(b"healthy", b"")))
        with patch("ayana.transport.fetch_host_key", new=AsyncMock(return_value={"ok": True, "fingerprint": "SHA256:known"})), \
                patch("ayana.transport.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
            with session_ssh_scope(self.db, self.sid):
                first = await self.transport.exec_shell("host", "date -u", channel="read")
                self.duty.set_session_account_group(self.sid, "ops")
                second = await self.transport.exec_shell("host", "date -u", channel="write")
                third = await self.transport.exec_shell("host", "date -u", channel="read")
        self.assertEqual((first.account_group, first.account), ("default", "root"))
        self.assertEqual((second.account_group, second.account), ("ops", "operator"))
        self.assertEqual((third.account_group, third.account), ("ops", "operator"))

    async def test_missing_selected_endpoint_never_falls_back(self):
        self.duty.set_session_account_group(self.sid, "ops")
        self.store.delete_endpoint("host", "ops")
        with session_ssh_scope(self.db, self.sid):
            for purpose in ("read", "write"):
                with self.subTest(purpose=purpose), self.assertRaises(TransportError) as error:
                    self.transport._endpoint_for_channel("host", purpose)
                self.assertEqual(error.exception.code, "configured_ssh_endpoint_missing")

    async def test_missing_group_is_rejected_before_dispatch_without_unknown_ledger(self):
        self.duty.set_session_account_group(self.sid, "ops")
        self.store.delete_endpoint("host", "ops")
        bridge = SessionBridge(self.db, duty=self.duty)
        tools = OpsTools(OpsContext(transport=self.transport, prom=None, incidents=None,
                                   knowledge=None, db=self.db, session_bridge=bridge))
        request = {"asset_id": "host", "command": "date -u", "channel": "write"}
        with patch("ayana.transport.asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            with session_ssh_scope(self.db, self.sid):
                result = await tools.call("host.exec", request)
        self.assertEqual(result["error"], "configured_ssh_endpoint_missing")
        row = self.db.query_one("SELECT status FROM session_write_ops WHERE action_key=?", (result["action_key"],))
        self.assertEqual(row["status"], "released")
        spawn.assert_not_awaited()
        # Once configured, the same operation can dispatch using that group.
        self.store.upsert_endpoint(asset_id="host", role="ops", host="host.example", username="operator")
        self.store.trust_host_key("host", "ops", "SHA256:known", key_line="host.example ssh-ed25519 AAAA")
        process = SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(b"healthy", b"")))
        with patch("ayana.transport.fetch_host_key", new=AsyncMock(return_value={"ok": True, "fingerprint": "SHA256:known"})), \
                patch("ayana.transport.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
            with session_ssh_scope(self.db, self.sid):
                retried = await tools.call("host.exec", request)
        self.assertEqual(retried["exec_state"], "success")
        self.assertEqual(retried["account_group"], "ops")
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops WHERE action_key=?",
                                           (result["action_key"],))["status"], "done")

    async def test_untrusted_selected_account_never_becomes_unknown_execution(self):
        self.duty.set_session_account_group(self.sid, "ops")
        self.db.execute("UPDATE ssh_endpoints SET host_key_trusted_at=NULL WHERE role='ops'")
        bridge = SessionBridge(self.db, duty=self.duty)
        tools = OpsTools(OpsContext(transport=self.transport, prom=None, incidents=None,
                                   knowledge=None, db=self.db, session_bridge=bridge))
        with patch("ayana.transport.asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            with session_ssh_scope(self.db, self.sid):
                result = await tools.call("host.exec", {"asset_id": "host", "command": "date -u", "channel": "write"})
        self.assertEqual(result["error"], "host_key_untrusted")
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops WHERE action_key=?",
                                           (result["action_key"],))["status"], "released")
        spawn.assert_not_awaited()

    async def test_switch_while_ssh_prepares_refuses_old_account_before_process_start(self):
        async def scan(*args, **kwargs):
            self.duty.set_session_account_group(self.sid, "ops")
            return {"ok": True, "fingerprint": "SHA256:known"}
        with patch("ayana.transport.fetch_host_key", side_effect=scan), \
                patch("ayana.transport.asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            with session_ssh_scope(self.db, self.sid), self.assertRaises(TransportError) as error:
                await self.transport.exec_shell("host", "date -u", channel="write")
        self.assertEqual(error.exception.code, "ssh_account_group_changed")
        self.assertTrue(error.exception.dispatch_not_started)
        spawn.assert_not_awaited()

    async def test_mcp_result_and_audit_record_actual_selected_group(self):
        bridge = SessionBridge(self.db, duty=self.duty)
        async def execute(*args, **kwargs):
            return NTResult(ok=True, output="healthy", returncode=0, account="operator", account_group="ops")
        tools = OpsTools(OpsContext(transport=SimpleNamespace(exec_shell=execute), prom=None,
                                   incidents=None, knowledge=None, db=self.db, session_bridge=bridge))
        result = await tools.call("host.exec", {"asset_id": "host", "command": "date -u", "channel": "write"})
        self.assertEqual(result["account_group"], "ops")
        row = self.db.query_one("SELECT detail_json FROM audit_log WHERE entry='mcp_host_exec_write' ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(row["detail_json"])["ssh_account_group"], "ops")


if __name__ == "__main__":
    unittest.main()
