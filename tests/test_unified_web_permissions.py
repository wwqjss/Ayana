"""The console has one account role model and cannot revive retired rule grants."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from aiohttp.test_utils import TestClient, TestServer

from ayana.auth import AuthService
from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.web import SESSION_COOKIE, WebApp, web


class UnifiedWebPermissionsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "web.db")
        self.auth = AuthService(self.db, pepper="test", session_ttl=3600, max_failed=5, lockout=60)
        for username, admin in (("operator", True), ("viewer", False)):
            self.auth.create_user(username, "test-password", is_admin=admin)
        self.admin = self.auth.login("operator", "test-password")
        self.viewer = self.auth.login("viewer", "test-password")
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,enabled,created_at,updated_at) VALUES('host','Host','host','host-exec',1,1,1)")
        self.db.execute(
            "INSERT INTO permissions(subject_type,subject_id,asset_id,capability,object_id,"
            "allow,require_approval,auto_allowed,created_at,updated_at,created_by)"
            " VALUES('web_user','operator','host','checks.write','*',0,1,0,1,1,'legacy')"
        )
        self.old_policy = Mock()
        self.old_policy.check.side_effect = AssertionError("retired policy must not control the console")
        self.old_policy.effective_decision.side_effect = AssertionError("retired policy must not control the console")
        self.actions = Mock()
        self.app = WebApp(self.db, self.auth, self.old_policy, None, None, self.actions, None,
                          static_dir=Path(self.tmp.name))
        self.client = TestClient(TestServer(self.app.build()))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.db.close()
        self.tmp.cleanup()

    def request(self, session, *, body=None, path="/api/checks", method="POST"):
        async def read_json():
            return body
        return SimpleNamespace(
            cookies={SESSION_COOKIE: session["session_id"]},
            headers={"X-CSRF-Token": session["csrf_token"]}, remote="", method=method,
            rel_url=SimpleNamespace(query={}, path=path), json=read_json, match_info={"aid": "old-action"},
        )

    def legacy_rows(self):
        return [tuple(row) for row in self.db.query("SELECT * FROM permissions ORDER BY id")]

    async def test_all_legacy_api_routes_return_retirement_without_parsing_or_writing(self):
        routes = (
            ("GET", "/api/permissions"), ("GET", "/api/permissions/model"),
            ("GET", "/api/permissions/effective"), ("GET", "/api/permissions/history"),
            ("POST", "/api/permissions"), ("POST", "/api/permissions/validate"),
            ("POST", "/api/permissions/delete"), ("POST", "/api/permissions/preview"),
            ("GET", "/api/agent-ceiling"), ("POST", "/api/agent-ceiling"),
            ("GET", "/api/permission-changes"), ("POST", "/api/permission-changes"),
            ("GET", "/api/permission-changes/old"),
            ("POST", "/api/permission-changes/old/authorize"),
            ("POST", "/api/permission-changes/old/reject"),
        )
        before = self.legacy_rows()
        for method, path in routes:
            with self.subTest(method=method, path=path):
                response = await self.client.request(
                    method, path, data="malformed legacy request",
                    cookies={SESSION_COOKIE: self.admin["session_id"]},
                    headers={"X-CSRF-Token": self.admin["csrf_token"]},
                )
                self.assertEqual(response.status, 410, await response.text())
                payload = await response.json()
                self.assertEqual(payload["error"], "legacy_permissions_retired")
                self.assertEqual(payload["settings_api"], "/api/agent/settings")
        self.assertEqual(self.legacy_rows(), before)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) AS n FROM permission_changes")["n"], 0)
        self.old_policy.check.assert_not_called()
        self.old_policy.effective_decision.assert_not_called()

    async def test_legacy_retirement_still_requires_login_and_csrf(self):
        response = await self.client.get("/api/permissions")
        self.assertEqual(response.status, 401)
        response = await self.client.post("/api/permissions", json={},
                                          cookies={SESSION_COOKIE: self.admin["session_id"]})
        self.assertEqual(response.status, 403)
        self.assertEqual(json.loads(await response.text())["error"], "bad_csrf")

    async def test_reader_sees_inventory_without_per_asset_rules_but_cannot_write(self):
        session = self.auth.get_session(self.viewer["session_id"])
        self.assertEqual(self.app._visible_asset_ids(session), {"host"})
        self.assertTrue(self.app._account_capability(session, "checks.read")["allowed"])
        self.assertFalse(self.app._account_capability(session, "checks.write")["allowed"])
        with self.assertRaises(web.HTTPForbidden):
            self.app._check_write(self.request(self.viewer))
        for method in ("api_action_propose", "api_action_approve", "api_action_reject",
                       "api_action_cancel", "api_action_execute", "api_action_decision"):
            with self.subTest(method=method), self.assertRaises(web.HTTPForbidden):
                await getattr(self.app, method)(self.request(self.viewer))
        self.assertEqual(self.actions.mock_calls, [])

    async def test_admin_role_allows_human_writes_without_legacy_rule_lookup(self):
        before = self.legacy_rows()
        session = self.app._check_write(self.request(self.admin))
        self.assertEqual(session["username"], "operator")
        self.assertTrue(self.app._account_capability(session, "checks.write")["allowed"])
        self.assertIsNone(self.app._terminal_ok(session, "host"))
        self.assertEqual(self.legacy_rows(), before)
        self.assertEqual(self.old_policy.mock_calls, [])

    async def test_terminal_rechecks_current_account_role_and_asset_state(self):
        session = self.auth.get_session(self.admin["session_id"])
        self.assertIsNone(self.app._terminal_ok(session, "host"))
        self.db.execute("UPDATE users SET is_admin=0 WHERE username='operator'")
        changed = self.auth.get_session(self.admin["session_id"])
        self.assertEqual(self.app._terminal_ok(changed, "host")["error"], "permission_denied")
        self.db.execute("UPDATE users SET is_admin=1 WHERE username='operator'")
        self.db.execute("UPDATE assets SET enabled=0 WHERE id='host'")
        self.assertEqual(self.app._terminal_ok(self.auth.get_session(self.admin["session_id"]), "host")["error"], "asset_unavailable")
        self.assertEqual(self.app._terminal_ok({"username": "admin", "is_admin": False}, "host")["error"], "permission_denied")
        self.assertEqual(self.app._terminal_ok(None, "host")["error"], "unauthorized")

    async def test_old_permanent_approval_cannot_grant_or_execute(self):
        before = self.legacy_rows()
        response = await self.app.api_action_decision(self.request(self.admin, body={"decision": "allow_always"}))
        self.assertEqual(response.status, 410)
        self.assertEqual(json.loads(response.body)["error"], "legacy_permissions_retired")
        self.assertEqual(self.actions.mock_calls, [])
        self.assertEqual(self.legacy_rows(), before)

    async def test_asset_case_mismatch_never_hides_sessions(self):
        duty = DutySessionManager(self.db)
        self.app.duty = duty
        sid = duty.create(origin="manual")["session_id"]
        self.db.execute(
            "INSERT INTO incidents(id,title,asset_id,object_id,status,created_at,updated_at)"
            " VALUES('inc_case','HOST / x','HOST','x','open',1,1)"
        )
        duty.join_incident(sid, "inc_case")
        session = duty.get(sid)
        self.assertTrue(self.app._agent_session_visible(self.auth.get_session(self.admin["session_id"]), session))

    async def test_incident_disposition_uses_live_session_modes(self):
        duty = DutySessionManager(self.db)
        sid = duty.create(origin="manual")["session_id"]
        action = {"id": "action", "state": "proposed", "mode": "autonomous",
                  "params_json": json.dumps({"_ayana_session_id": sid}), "capability": "service.restart"}
        duty.set_settings({"auto_access_mode": "readwrite", "auto_approval_mode": "automatic"})
        self.db.execute("UPDATE duty_sessions SET access_mode='readonly',approval_mode='manual' WHERE id=?", (sid,))
        disposition = self.app._incident_disposition({"actions": [action]})
        self.assertNotIn("policy", disposition)
        self.assertEqual(disposition["authority"]["access_mode"], "readonly")
        self.assertEqual(disposition["authority"]["approval_mode"], "manual")
        self.assertFalse(disposition["authority"]["write_allowed"])
        self.db.execute("UPDATE duty_sessions SET access_mode='readwrite' WHERE id=?", (sid,))
        self.assertTrue(self.app._incident_disposition({"actions": [action]})["authority"]["write_allowed"])
        self.assertEqual(self.old_policy.mock_calls, [])

    async def test_assist_permission_forms_are_retired(self):
        response = await self.client.get(
            "/api/assist/form?domain=permissions",
            cookies={SESSION_COOKIE: self.admin["session_id"]},
        )
        self.assertEqual(response.status, 410, await response.text())
        self.assertEqual((await response.json())["error"], "legacy_permissions_retired")
        response = await self.client.post(
            "/api/assist/configure", json={"domain": "permissions", "text": "x"},
            cookies={SESSION_COOKIE: self.admin["session_id"]},
            headers={"X-CSRF-Token": self.admin["csrf_token"]},
        )
        self.assertEqual(response.status, 410, await response.text())
        self.assertEqual((await response.json())["error"], "legacy_permissions_retired")
