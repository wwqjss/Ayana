"""2026-10-12 审查：隔离来源、验证契约、执行收敛与独立人工义务。"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import aiohttp  # 先加载真实模块；后台任务测试需要 aiohttp.web。

from ayana.actions import ActionError, ActionService
from ayana.agent import AgentLoop
from ayana.alertmanager import AlertIngest
from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.main import App
from ayana.ntsafe import NTResult
from ayana.policy import Policy
from ayana.runbook import RunbookRule, apply_runbook_rules, get_runbook_rule
from ayana.verify_profiles import PROFILES, profile_for_action


# 测试本地 runbook 规则（发行版 RUNBOOK 为空，由部署方注入）
def _test_rule() -> RunbookRule:
    return RunbookRule(
        id="rb_frps_down_restart",
        name="frps down restart",
        asset_id="nerv",
        object_name="frps",
        alertname="TargetDown",
        capability="service.restart",
        reason="restart frps",
        require_probe_fail=True,
    )


class TestExecutionSafety(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "test.db")
        stamp = now()
        self.db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " host_id_verified_at, prom_asset, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("nerv", "NERV", "read", "write", "NERV", stamp, "nerv", stamp, stamp),
        )
        for name in ("frps", "nginx"):
            self.db.execute(
                "INSERT INTO objects(id, asset_id, kind, name, unit, auto_recover, created_at)"
                " VALUES(?,?,?,?,?,1,?)",
                (f"nerv:service:{name}", "nerv", "service", name, name, stamp),
            )
        self.db.execute(
            "INSERT INTO incidents(id,title,asset_id,object_id,created_at,updated_at)"
            " VALUES('inc1','nerv / frps: TargetDown','nerv','frps',?,?)", (stamp, stamp),
        )
        self.db.execute(
            "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
            " VALUES('admin','x',0,1,?,?)",
            (now(), now()),
        )
        self.policy = Policy(self.db)
        for kind, identity, cap, automatic in (
            ("web_user", "admin", "service.restart", False),
            ("web_user", "admin", "asset.summary", False),
            ("auto_rule", "agent", "service.restart", True),
            ("auto_rule", "agent", "asset.summary", True),
        ):
            self.policy.upsert_permission(
                subject_type=kind, subject_id=identity, capability=cap, asset_id="nerv",
                object_id="*", allow=True, require_approval=False, auto_allowed=automatic,
            )
        binding = SimpleNamespace(
            asset_id="nerv", read_alias="read", write_alias="write",
            expected_host_id="NERV", host_id_verified_at=stamp,
        )
        self.gate = SimpleNamespace(
            get=lambda asset: binding,
            verify_account=AsyncMock(return_value={"ok": True, "mode": "exec"}),
        )
        self.transport = SimpleNamespace(
            exec=AsyncMock(return_value=NTResult(ok=True, output="done", returncode=0)),
        )
        self.samples = [{"metric": {"asset": "nerv", "service": "frps"},
                         "value": 0, "sample_at": now() - 1}]

        async def samples(asset, service="", **kw):
            return [s for s in self.samples
                    if s["metric"]["service"] == service and s["sample_at"] > kw["start"]]

        self.prom = SimpleNamespace(probe_success_since=samples)
        self.actions = ActionService(
            self.db, None, self.gate, self.policy, self.prom, transport=self.transport,
            verify_timeout=2,
        )
        # 注入测试本地 runbook 规则（发行版 RUNBOOK 为空）
        apply_runbook_rules([{
            "id": "rb_frps_down_restart", "name": "frps down restart",
            "asset_id": "nerv", "object_name": "frps", "alertname": "TargetDown",
            "capability": "service.restart", "reason": "restart frps",
            "require_probe_fail": True,
        }])
        self.addCleanup(lambda: apply_runbook_rules([]))
        self.incidents = IncidentService(self.db)
        self.notifier = Mock()
        self.investigation = SimpleNamespace(
            prom=self.prom,
            run_loop=AsyncMock(return_value={
                "id": "inv1", "evidence": [{"source": "ssh_probe", "classification": "observed",
                                             "ok": True, "observed": {"service_state": "active"}}],
            }),
        )
        self.agent = AgentLoop(
            self.db, self.investigation, self.actions, self.policy,
            SimpleNamespace(enabled=False), self.notifier, auto_enabled=True,
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def incident(self):
        return dict(self.db.query_one("SELECT * FROM incidents WHERE id='inc1'"))

    def proposal(self, *, mode="manual", object_id="frps"):
        return self.actions.propose(
            asset_id="nerv", object_id=object_id, capability="service.restart", incident_id="inc1",
            proposer_type="auto_rule" if mode == "auto" else "web_user",
            proposer_id="agent" if mode == "auto" else "admin", mode=mode,
            runbook_id="rb_frps_down_restart" if mode == "auto" else "",
        )["id"]

    def seed_episode(self, *, quarantined=False, incident_id="inc1"):
        self.db.execute(
            "INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,alertname,status,"
            " asset_id,object_id,incident_id,first_seen,last_seen,source_state,source_health)"
            " VALUES('ep1','am','fp','2026-10-12T00:00:00Z','TargetDown','firing',"
            " 'nerv','frps',?,?,?, ?,?)",
            (incident_id, now(), now(), "quarantine" if quarantined else "firing",
             "quarantine" if quarantined else "ok"),
        )

    async def test_quarantine_cannot_create_or_correlate_incident(self):
        ingest = AlertIngest(self.db)
        result = ingest.ingest_webhook({"alerts": [{
            "status": "firing", "startsAt": "invalid-date", "fingerprint": "broken",
            "labels": {"alertname": "TargetDown", "asset": "nerv", "service": "frps"},
        }]})
        self.assertEqual(result["quarantined"], 1)
        ep = self.db.query_one("SELECT * FROM alert_episodes")
        self.assertEqual(self.incidents.upsert_from_episode(ep["id"]), "")
        stop = asyncio.Event()
        worker = SimpleNamespace(
            db=self.db, _stop=stop, incidents=self.incidents, notifier=self.notifier,
            qq=SimpleNamespace(admin_qq=""),
        )

        async def tick_end(_):
            stop.set()

        with patch("ayana.main.asyncio.sleep", new=tick_end):
            await App._bg_correlate(worker)
        self.assertEqual(self.db.query_one("SELECT incident_id FROM alert_episodes")["incident_id"], "")
        self.notifier.enqueue.assert_not_called()

    async def test_agent_rejects_legacy_quarantined_incident(self):
        self.seed_episode(quarantined=True)
        result = await self.agent.handle_incident("inc1")
        self.assertEqual(result["action"], "escalated_source")
        self.investigation.run_loop.assert_not_called()
        self.transport.exec.assert_not_called()
        self.assertTrue(self.incident()["need_human"])

    async def test_final_gate_rechecks_source_after_identity_wait(self):
        self.seed_episode()
        action_id = self.proposal(mode="auto")
        self.actions.approve(action_id, approver_type="auto_rule", approver_id="agent")

        async def identity_wait(*args, **kwargs):
            self.db.execute("UPDATE alert_episodes SET source_state='quarantine' WHERE id='ep1'")
            return {"ok": True, "mode": "exec"}

        self.gate.verify_account = identity_wait
        with self.assertRaises(ActionError) as denied:
            await self.actions.execute(action_id, actor_type="auto_rule", actor_id="agent")
        self.assertEqual(denied.exception.code, "source_quarantined")
        self.assertEqual(self.actions.get_action(action_id)["state"], "cancelled")
        self.transport.exec.assert_not_called()
        self.assertTrue(self.incident()["need_human"])

    async def test_unsupported_profile_stops_agent_before_write(self):
        """verification contract 缺失时 agent 在写入前硬停（escalated_precondition）。"""
        self.db.execute("UPDATE incidents SET object_id='frps', title='nerv / frps: TargetDown'")
        self.seed_episode()
        with patch("ayana.verify_profiles.profile_for_action", return_value=None):
            result = await self.agent.handle_incident("inc1")
        self.assertEqual(result["action"], "escalated_precondition")
        pre = next(step for step in result["steps"] if step["step"] == "preconditions")
        self.assertIn("verification_contract", ";".join(pre["reasons"]))
        self.assertTrue(self.incident()["need_human"])
        self.transport.exec.assert_not_called()
        self.assertEqual(self.db.query_one("SELECT COUNT(*) AS n FROM actions")["n"], 0)

    async def test_final_gate_rejects_existing_auto_action_without_contract(self):
        self.db.execute("UPDATE incidents SET object_id='frps'")
        action_id = self.proposal(object_id="frps")
        self.actions.approve(action_id, approver_id="admin")
        # 模拟旧版本已经产生的 auto 提案，验证最终派发门而不是创建入口。
        self.db.execute("UPDATE actions SET mode='auto',runbook_id='rb_frps_down_restart' WHERE id=?",
                        (action_id,))
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="*", allow=True, require_approval=False, auto_allowed=True,
        )
        with patch("ayana.verify_profiles.profile_for_action", return_value=None):
            with self.assertRaises(ActionError) as denied:
                await self.actions.execute(action_id, actor_id="admin")
        self.assertEqual(denied.exception.code, "unsupported_verification_profile")
        self.transport.exec.assert_not_called()
        self.assertTrue(self.incident()["need_human"])

    async def test_contract_removed_during_identity_wait_blocks_write(self):
        action_id = self.proposal(mode="auto")
        self.actions.approve(action_id, approver_type="auto_rule", approver_id="agent")
        with patch("ayana.verify_profiles.profile_for_action", return_value=None):
            with self.assertRaises(ActionError) as denied:
                await self.actions.execute(action_id, actor_type="auto_rule", actor_id="agent")
        self.assertEqual(denied.exception.code, "unsupported_verification_profile")
        self.transport.exec.assert_not_called()

    async def test_transport_exception_converges_and_retains_no_replay_lock(self):
        action_id = self.proposal()
        self.actions.approve(action_id, approver_id="admin")
        self.transport.exec.side_effect = ConnectionResetError("connection reset by peer")
        with self.assertLogs("ayana.actions", level="ERROR"):
            result = await self.actions.execute(action_id, actor_id="admin")
        self.assertEqual(result["state"], "unknown")
        self.assertIn("exec_exception", self.actions.get_action(action_id)["result_detail"])
        self.assertEqual(self.db.query_one(
            "SELECT COUNT(*) AS n FROM audit_log WHERE action_id=? AND entry='action_unknown'",
            (action_id,),
        )["n"], 1)
        self.assertIn(action_id, self.incident()["need_human_reason"])
        self.assertTrue(self.actions._object_locked("nerv", "nerv:service:frps"))
        with self.assertRaises(ActionError) as no_replay:
            await self.actions.execute(action_id, actor_id="admin")
        self.assertEqual(no_replay.exception.code, "no_replay_unknown")
        self.assertEqual(self.transport.exec.await_count, 1)

    async def test_approval_and_passed_verification_complete_recovery(self):
        result = self.agent._propose_for_human(
            self.incident(), get_runbook_rule("rb_frps_down_restart"), {"steps": []},
            {"decision": "approval_required"}, {"status": "satisfied"}, None, "",
        )
        action_id = result["action_id"]
        self.assertTrue(self.incident()["need_human"])
        self.actions.approve(action_id, approver_id="admin")
        self.assertFalse(self.incident()["need_human"])
        with patch.object(self.actions, "_run_verification", new=AsyncMock(return_value={})): 
            executed = await self.actions.execute(action_id, actor_id="admin")
            await asyncio.sleep(0)
        self.assertEqual(executed["state"], "success")
        v = self.db.query_one("SELECT * FROM verifications WHERE action_id=?", (action_id,))
        criteria = json.loads(v["criteria_json"])
        criteria["baseline_finished_at"] = now() - 5
        self.db.execute("UPDATE verifications SET criteria_json=? WHERE id=?",
                        (json.dumps(criteria), v["id"]))
        self.samples = [{"metric": {"asset": "nerv", "service": "frps"}, "value": 1,
                         "sample_at": now() - offset} for offset in (3, 1)]
        fast = dataclasses.replace(PROFILES["svc.recover"], warmup_sec=0, continuous_success_sec=1)
        with patch.dict(PROFILES, {"svc.recover": fast}):
            verified = await self.actions._run_verification(v["id"], action_id)
        self.assertEqual(verified["status"], "passed")
        self.assertEqual(self.incident()["status"], "resolved")
        self.assertEqual(self.incident()["outcome"], "recovered")

    async def test_approval_clears_only_exact_action_obligation(self):
        action_id = self.proposal()
        self.incidents.set_need_human("inc1", "inspect_remote_disk")
        self.incidents.set_need_human("inc1", f"awaiting_approval:{action_id} decision=approval_required")
        self.incidents.set_need_human("inc1", f"awaiting_approval:{action_id}0 decision=approval_required")
        self.actions.approve(action_id, approver_id="admin")
        remaining = self.incident()["need_human_reason"]
        self.assertTrue(self.incident()["need_human"])
        self.assertIn("inspect_remote_disk", remaining)
        self.assertIn(f"awaiting_approval:{action_id}0", remaining)
        self.assertNotIn(f"awaiting_approval:{action_id} decision", remaining)

    async def test_reconcile_cleans_legacy_passed_action_obligation(self):
        action_id = self.proposal()
        self.db.execute("UPDATE actions SET state='success' WHERE id=?", (action_id,))
        self.db.execute(
            "INSERT INTO verifications(id,action_id,incident_id,status,started_at,generation)"
            " VALUES('ver-old',?,'inc1','passed',?,1)", (action_id, now()),
        )
        self.incidents.set_need_human("inc1", f"awaiting_approval:{action_id} rule=frps")
        result = self.incidents.reconcile("inc1")
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["outcome"], "recovered")
        self.assertFalse(self.incident()["need_human"])

    async def test_reconcile_preserves_old_generation_and_other_obligations(self):
        action_id = self.proposal()
        self.actions.approve(action_id, approver_id="admin")
        self.db.execute("UPDATE incidents SET generation=2 WHERE id='inc1'")
        self.db.event("generation_bumped", incident_id="inc1")
        self.incidents.set_need_human("inc1", f"awaiting_approval:{action_id} rule=frps")
        self.incidents.set_need_human("inc1", "inspect_remote_disk")
        self.incidents.reconcile("inc1")
        self.assertTrue(self.incident()["need_human"])
        self.assertIn(f"awaiting_approval:{action_id}", self.incident()["need_human_reason"])
        self.assertIn("inspect_remote_disk", self.incident()["need_human_reason"])

    async def test_late_passed_verification_preserves_current_generation_obligation(self):
        action_id = self.proposal()
        baseline = now() - 5
        self.db.execute("UPDATE actions SET state='success', finished_at=? WHERE id=?", (baseline, action_id))
        self.db.execute(
            "INSERT INTO verifications(id,action_id,incident_id,status,started_at,generation,"
            " profile_id,criteria_json) VALUES('ver-late',?,'inc1','pending',?,1,'svc.recover',?)",
            (action_id, baseline, json.dumps({"baseline_finished_at": baseline, "service": "frps"})),
        )
        self.db.execute("UPDATE incidents SET generation=2 WHERE id='inc1'")
        self.db.event("generation_bumped", incident_id="inc1")
        self.incidents.set_need_human("inc1", f"awaiting_approval:{action_id}")
        self.samples = [{"metric": {"asset": "nerv", "service": "frps"}, "value": 1,
                         "sample_at": now() - offset} for offset in (3, 1)]
        fast = dataclasses.replace(PROFILES["svc.recover"], warmup_sec=0, continuous_success_sec=1)
        with patch.dict(PROFILES, {"svc.recover": fast}):
            verified = await self.actions._run_verification("ver-late", action_id)
        self.assertEqual(verified["status"], "passed")
        self.assertTrue(self.incident()["need_human"])
        self.assertIn(f"awaiting_approval:{action_id}", self.incident()["need_human_reason"])
        self.assertEqual(self.incident()["status"], "open")

    async def test_executed_unit_mismatch_cannot_borrow_frps_contract(self):
        """v0.7.3+ 通用 profile 按 capability 解析；unit 不再影响 contract 解析。"""
        # 通用 svc.recover 对任意 service.restart 都可用
        p = profile_for_action(
            capability="service.restart", asset_id="nerv", object_id="nerv:service:frps",
        )
        self.assertIsNotNone(p)
        self.assertEqual(p.id, "svc.recover")
        # 不在 CAP_PROFILE 的 capability 仍然无 contract
        self.assertIsNone(profile_for_action(
            capability="container.restart", asset_id="nerv", object_id="nerv:service:frps",
        ))

    async def test_expiry_preserves_unrelated_human_obligation(self):
        action_id = self.proposal()
        self.incidents.set_need_human("inc1", "inspect_remote_disk")
        self.incidents.set_need_human("inc1", f"awaiting_approval:{action_id}")
        self.db.execute("UPDATE actions SET approval_deadline=? WHERE id=?", (now() - 1, action_id))
        self.actions.expire_stale_proposals()
        reason = self.incident()["need_human_reason"]
        self.assertIn("inspect_remote_disk", reason)
        self.assertIn(f"approval_expired:{action_id}", reason)
        self.assertNotIn(f"awaiting_approval:{action_id}", reason)

    async def test_unsupported_manual_verification_creates_human_obligation(self):
        """无 verification contract 的手工验证 → unknown + need_human。"""
        self.db.execute("UPDATE incidents SET object_id='frps'")
        action_id = self.proposal(object_id="frps")
        self.db.execute("UPDATE actions SET state='success', finished_at=? WHERE id=?", (now(), action_id))
        with patch("ayana.verify_profiles.profile_for_action", return_value=None):
            result = await self.actions.verify(action_id)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(self.incident()["need_human"])
        self.assertIn(f"unsupported_verification_profile:{action_id}", self.incident()["need_human_reason"])

    async def test_reject_requires_permission_on_actual_target(self):
        action_id = self.proposal()
        with self.assertRaises(ActionError) as denied:
            self.actions.reject(action_id, actor_id="limited")
        self.assertEqual(denied.exception.code, "reject_denied")
        self.assertEqual(self.actions.get_action(action_id)["state"], "proposed")
        self.actions.reject(action_id, actor_id="admin")
        with self.assertRaises(ActionError):
            self.actions.reject(action_id, actor_id="limited")
        self.transport.exec.assert_not_called()

    async def test_incident_close_checks_service_boundary(self):
        denied = self.incidents.close_manual("inc1", "close", "limited", policy=self.policy)
        self.assertEqual(denied["error"], "permission_denied")
        hidden_admin = self.incidents.close_manual(
            "inc1", "close", "limited", policy=self.policy, is_admin=True,
        )
        self.assertEqual(hidden_admin["error"], "permission_denied")
        self.assertEqual(self.incident()["status"], "open")
        closed = self.incidents.close_manual("inc1", "close", "admin", policy=self.policy, is_admin=True)
        self.assertTrue(closed["ok"])

    async def test_profile_matching_is_capability_based(self):
        """v0.7.3+ profile 按 capability 解析，不做对象名子串匹配。"""
        # service.restart → svc.recover，与对象名无关
        p = profile_for_action(capability="service.restart", asset_id="nerv", object_id="evil-frps")
        self.assertIsNotNone(p)
        self.assertEqual(p.id, "svc.recover")
        # 未知 capability 不返回 profile（即使对象名含 frps）
        self.assertIsNone(profile_for_action(capability="container.restart", asset_id="nerv", object_id="frps"))


class TestAibotBackground(unittest.IsolatedAsyncioTestCase):
    async def test_app_start_schedules_aibot_without_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            app = App({
                "db_path": str(Path(directory) / "test.db"), "base_dir": directory,
                "onewbot_token": "test", "webhook_token": "test", "ssh_credential_key": "test",
                "prometheus_config": {"local_dir": str(Path(directory) / "prom")},
            })
            try:
                app.channel_store.create(
                    name="bot", kind="wecom_aibot", config={"targets": []},
                    secret={"bot_id": "test-bot", "secret": "test-secret"},
                )
                scheduled = []

                def schedule(coro):
                    scheduled.append(coro.cr_code.co_name)
                    coro.close()
                    return Mock()

                runner = SimpleNamespace(setup=AsyncMock(), cleanup=AsyncMock())
                app._stop.set()
                with patch("ayana.main.web.AppRunner", return_value=runner), \
                     patch("ayana.main.web.TCPSite", return_value=SimpleNamespace(start=AsyncMock())), \
                     patch.object(app.auth, "ensure_bootstrap_admin", return_value=None), \
                     patch("ayana.main.asyncio.create_task", side_effect=schedule):
                    await app.start()
                self.assertIn("_bg_aibot", scheduled)
                self.assertEqual(scheduled.count("_bg_aibot"), 1)
            finally:
                app.db.close()

    async def test_worker_connects_targetless_bot_and_disconnects_disabled(self):
        stop = asyncio.Event()
        manager = SimpleNamespace(
            _clients={"disabled": object()}, ensure=AsyncMock(), stop=AsyncMock(),
        )
        worker = SimpleNamespace(
            _stop=stop, aibot_manager=manager,
            channel_store=SimpleNamespace(
                list_enabled=lambda: [{"id": "new", "kind": "wecom_aibot"}],
                reveal_for_send=lambda identity: {"secret": {"bot_id": "bot", "secret": "secret"},
                                                   "config": {"targets": []}},
            ),
        )

        async def tick_end(_):
            stop.set()

        with patch("ayana.main.asyncio.sleep", new=tick_end):
            await App._bg_aibot(worker)
        manager.ensure.assert_awaited_once_with("new", bot_id="bot", secret="secret", ws_url="")
        manager.stop.assert_awaited_once_with("disabled")


if __name__ == "__main__":
    unittest.main()
