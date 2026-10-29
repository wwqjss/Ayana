"""Check source recovery and account-group selection; isolated DBs, no SSH."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from ayana.checks import CheckService, check_recovery_evidence
from ayana.db import Database, now
from ayana.exec_facts import NTResult
from ayana.incidents import IncidentService
from ayana.transport import SSHAssetStore, SSHTransport, TransportError, resolve_exec_channel


class FakeTransport:
    def __init__(self):
        self.result = NTResult(ok=False, output="inactive", returncode=3)

    async def probe(self, *args, **kwargs):
        return self.result


class CheckRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.db.close)
        self.db.execute(
            "INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at)"
            " VALUES('host','Host','host','host',?,?)", (now(), now())
        )
        self.transport = FakeTransport()
        self.incidents = IncidentService(self.db)
        self.checks = CheckService(self.db, self.transport, incidents=self.incidents)

    def create(self, kind="service", name="worker"):
        params = {"unit": name} if kind == "service" else {"port": 8080}
        if kind == "command":
            params = {"argv": ["true"]}
        return self.checks.create_check(
            asset_id="host", kind=kind, name=name, params=params, fail_threshold=1
        )

    def episode(self, check):
        return dict(self.db.query_one(
            "SELECT * FROM alert_episodes WHERE json_extract(annotations_json,'$.check_id')=?"
            " ORDER BY first_seen DESC LIMIT 1", (check["id"],)
        ))

    def incident(self, check):
        return dict(self.db.query_one("SELECT * FROM incidents WHERE id=?", (self.episode(check)["incident_id"],)))

    async def fail(self, check):
        self.transport.result = NTResult(ok=True, output="", returncode=0) if check["kind"] == "port" else NTResult(ok=False, output="inactive", returncode=3)
        await self.checks.run_one(self.checks.get_check(check["id"]))

    async def pass_check(self, check):
        self.transport.result = NTResult(ok=True, output="LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*" if check["kind"] == "port" else "active", returncode=0)
        await self.checks.run_one(self.checks.get_check(check["id"]))

    async def test_service_success_resolves_source_and_records_typed_evidence_once(self):
        check = self.create()
        await self.fail(check)
        await self.pass_check(check)
        self.assertEqual(self.episode(check)["status"], "resolved")
        self.assertEqual((self.incident(check)["status"], self.incident(check)["outcome"]), ("resolved", "recovered"))
        event = self.db.query_one("SELECT payload_json FROM events WHERE type='incident_resolved'")
        evidence = json.loads(event["payload_json"])["evidence"]["checks"][0]
        self.assertEqual(evidence["contract"], "check.service")
        self.assertEqual(evidence["check_id"], check["id"])
        self.assertGreater(evidence["result_id"], 0)
        await self.pass_check(check)
        self.assertEqual(len(self.db.query("SELECT id FROM events WHERE type='incident_resolved'")), 1)
        self.assertEqual(len(self.db.query("SELECT id FROM events WHERE type='check_recovered'")), 1)

    async def test_port_uses_its_own_success_instead_of_an_unrelated_prom_probe(self):
        check = self.create("port", "api-port")
        await self.fail(check)
        await self.pass_check(check)
        self.assertEqual(self.incident(check)["outcome"], "recovered")
        evidence = check_recovery_evidence(self.db, self.episode(check), 1)
        self.assertEqual((evidence["verdict"], evidence["contract"]), ("green", "check.port"))

    async def test_healthy_sibling_check_cannot_close_another_failed_check(self):
        first, second = self.create(name="one"), self.create(name="two")
        await self.fail(first)
        await self.fail(second)
        await self.pass_check(first)
        self.assertEqual(self.episode(second)["status"], "firing")
        self.assertEqual(self.incident(first)["status"], "open")
        await self.pass_check(second)
        self.assertEqual(self.incident(first)["outcome"], "recovered")
        evidence = self.incidents._incident_recovery_evidence(self.incident(first)["id"], 1)
        self.assertEqual({item["check_id"] for item in evidence["checks"]}, {first["id"], second["id"]})

    async def test_repeated_success_repairs_a_previously_missed_legacy_transition(self):
        check = self.create()
        await self.fail(check)
        episode = self.episode(check)
        annotations = json.loads(episode["annotations_json"])
        annotations.pop("check_contract")
        self.db.execute("UPDATE alert_episodes SET annotations_json=? WHERE id=?", (json.dumps(annotations), episode["id"]))
        with patch.object(self.checks, "_resolve_alert", new=AsyncMock()):
            await self.pass_check(check)
        self.assertEqual(self.checks.get_check(check["id"])["fail_streak"], 0)
        self.assertEqual(self.episode(check)["status"], "firing")
        await self.pass_check(check)
        self.assertEqual(self.incident(check)["outcome"], "recovered")

    async def test_changed_check_target_cannot_certify_the_original_failure(self):
        check = self.create()
        await self.fail(check)
        self.checks.update_check(check["id"], params={"unit": "different"})
        await self.pass_check(check)
        self.assertEqual(self.episode(check)["status"], "firing")
        self.assertEqual(self.incident(check)["status"], "open")

    async def test_disabled_or_missing_check_cannot_resolve_a_firing_episode(self):
        check = self.create()
        await self.fail(check)
        with patch.object(self.checks, "_resolve_alert", new=AsyncMock()):
            await self.pass_check(check)
        self.db.execute("UPDATE checks SET enabled=0 WHERE id=?", (check["id"],))
        await self.checks._resolve_alert(check)
        self.assertEqual(self.episode(check)["status"], "firing")
        self.db.execute("DELETE FROM checks WHERE id=?", (check["id"],))
        await self.checks._resolve_alert(check)
        self.assertEqual(self.incident(check)["status"], "open")

    async def test_stale_success_cannot_resolve_a_firing_episode(self):
        check = self.create()
        await self.fail(check)
        with patch.object(self.checks, "_resolve_alert", new=AsyncMock()):
            await self.pass_check(check)
        self.db.execute("UPDATE check_results SET at=? WHERE check_id=?", (now()-300, check["id"]))
        await self.checks._resolve_alert(check)
        self.assertEqual(self.episode(check)["status"], "firing")
        self.assertEqual(self.incident(check)["status"], "open")

    async def test_newer_failed_result_overrides_a_recorded_recovery_proof(self):
        check = self.create()
        await self.fail(check)
        await self.pass_check(check)
        stamp = now()
        self.db.execute("INSERT INTO check_results(check_id,at,ok,state,detail) VALUES(?,?,0,'fail','inactive')", (check["id"], stamp))
        self.db.execute("UPDATE checks SET last_at=?,last_ok=0,last_state='fail' WHERE id=?", (stamp, check["id"]))
        self.assertEqual(check_recovery_evidence(self.db, self.episode(check), 1)["verdict"], "red")

    async def test_old_episode_cannot_resolve_a_new_generation(self):
        check = self.create()
        await self.fail(check)
        incident_id = self.incident(check)["id"]
        self.db.execute("UPDATE incidents SET generation=2 WHERE id=?", (incident_id,))
        self.db.event("incident_reopened", incident_id=incident_id, payload={"generation": 2})
        await self.pass_check(check)
        self.assertEqual(self.incident(check)["status"], "open")
        self.assertEqual(self.episode(check)["status"], "firing")

    async def test_failed_transport_output_cannot_be_a_successful_service_observation(self):
        check = self.create()
        await self.fail(check)
        self.transport.result = NTResult(ok=False, output="active", returncode=255)
        result = await self.checks.run_one(self.checks.get_check(check["id"]))
        self.assertFalse(result["ok"])
        self.assertEqual(self.episode(check)["status"], "firing")

    async def test_generic_command_check_does_not_acquire_a_service_recovery_contract(self):
        check = self.create("command", "generic")
        await self.fail(check)
        await self.pass_check(check)
        self.assertEqual(self.incident(check)["outcome"], "closed_unverified")


class CheckAccountGroupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.db.close)
        self.db.execute(
            "INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at)"
            " VALUES('host','Host','host','host',?,?)", (now(), now())
        )
        self.store = SSHAssetStore(self.db)
        self.ssh = SSHTransport(self.store, None)

    def group(self, name, user):
        self.store.add_role(name=name)
        self.store.upsert_endpoint(asset_id="host", role=name, host="host.example", username=user)

    async def test_global_default_group_is_used_by_unscoped_checks(self):
        self.group("observers", "observer")
        self.group("operators", "operator")
        self.db.execute("INSERT OR REPLACE INTO agent_settings(key,value,updated_at,updated_by) VALUES('ssh_default_group','observers',?,'test')", (now(),))
        async def run(asset, kind, command, timeout):
            ep = self.ssh._endpoint_for_channel(asset, kind)
            return NTResult(ok=True, output="active", returncode=0, account=ep.username)
        self.ssh._run_command = run
        channel = resolve_exec_channel("host", self.ssh, role="read")
        result = await channel.probe("host", ["systemctl", "is-active", "worker"])
        self.assertEqual(result.account, "observer")
        self.assertEqual(self.store.get_endpoint("host", "operators")["username"], "operator")

    async def test_explicit_custom_default_group_is_a_valid_channel(self):
        self.group("team", "team-user")
        self.db.execute("DELETE FROM ssh_account_groups WHERE name='default'")
        self.db.execute("UPDATE agent_settings SET value='team' WHERE key='ssh_default_group'")
        self.assertIs(resolve_exec_channel("host", self.ssh, role="read"), self.ssh)
        self.assertEqual(self.ssh._endpoint_for_channel("host", "read").username, "team-user")

    async def test_missing_selected_group_never_falls_back_to_another_group_or_local(self):
        self.group("operators", "operator")
        self.db.execute("INSERT OR REPLACE INTO agent_settings(key,value,updated_at,updated_by) VALUES('ssh_default_group','missing',?,'test')", (now(),))
        with self.assertRaises(TransportError) as caught:
            resolve_exec_channel("host", self.ssh, local_assets={"host"}, role="read")
        self.assertEqual(caught.exception.code, "configured_ssh_endpoint_missing")
        self.assertEqual(self.store.get_endpoint("host", "operators")["username"], "operator")


if __name__ == "__main__":
    unittest.main()
