"""Incident 统一收敛（P0-04）。

唯一入口：IncidentService.reconcile(inc_id)。
- verification passed 不能单独 recovered
- firing / unknown Action / need_human 阻塞 recovered
- manual closed ≠ recovered
- generation：复发递增；旧 generation 结果只进历史
"""

from __future__ import annotations

import json
from typing import Any

from .db import Database, new_id, now

RECURRENCE_WINDOW = 3600.0


class IncidentService:
    def __init__(self, db: Database):
        self.db = db
        self.session_bridge = None  # P2 薄桥，可选注入；不引入新自治

    def _touch_session(self, inc_id: str, generation: int | None = None) -> None:
        """挂上调查 Session（P2）。桥缺失/失败不影响事件主流程。"""
        if not self.session_bridge or not inc_id:
            return
        try:
            self.session_bridge.ensure_session(inc_id, generation=generation)
        except Exception:
            pass

    def upsert_from_episode(self, episode_id: str) -> str:
        ep = self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (episode_id,))
        if not ep:
            return ""
        # 服务边界也拒绝隔离来源，不能依赖告警入站或后台调用者过滤。
        if ep["source_state"] == "quarantine" or ep["source_health"] == "quarantine":
            return ""
        if ep["incident_id"]:
            return ep["incident_id"]
        asset_id = ep["asset_id"] or ""
        object_id = ep["object_id"] or ""
        alertname = ep["alertname"] or ""
        # P1-03：可解释关联 —— asset + canonical object + problem family
        problem_family = (ep["problem_family"] if "problem_family" in ep.keys() else "") or ""
        canonical = (ep["canonical_object"] if "canonical_object" in ep.keys() else "") or object_id
        rows = self.db.query(
            "SELECT * FROM incidents WHERE asset_id=? AND status='open'"
            " ORDER BY updated_at DESC LIMIT 20",
            (asset_id,),
        )
        chosen = None
        for r in rows:
            same_obj = (r["object_id"] or "") == object_id
            recent = (now() - (r["updated_at"] or 0)) < RECURRENCE_WINDOW
            if same_obj and (recent or r["status"] == "open"):
                chosen = r
                break
        if not chosen:
            # 复发：按 asset + object 精确查（不用先 LIMIT 1 再比 object）
            r2 = self.db.query_one(
                "SELECT * FROM incidents WHERE asset_id=? AND object_id=?"
                " AND status IN ('resolved','closed') AND updated_at>?"
                " ORDER BY updated_at DESC LIMIT 1",
                (asset_id, object_id, now() - RECURRENCE_WINDOW),
            )
            if r2:
                chosen = r2
        if chosen and chosen["status"] == "open":
            inc_id = chosen["id"]
            self.db.execute(
                "UPDATE alert_episodes SET incident_id=? WHERE id=?", (inc_id, episode_id)
            )
            self.db.event(
                "episode_attached", f"{alertname} → incident",
                incident_id=inc_id,
                episode_id=episode_id,
                payload={
                    "episode_id": episode_id,
                    "alertname": alertname,
                    "problem_family": problem_family,
                    "canonical_object": canonical,
                    "relation": "merged_open",
                },
            )
            self._bind_event_episode(episode_id, inc_id)
            self._touch_session(inc_id)
            return inc_id
        if chosen and chosen["status"] in ("resolved", "closed"):
            # 复发 → 新 generation
            inc_id = chosen["id"]
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE alert_episodes SET incident_id=? WHERE id=?", (inc_id, episode_id)
                )
                conn.execute(
                    "UPDATE incidents SET status='open', resolved_at=NULL, updated_at=?,"
                    " stage='pending', generation=generation+1, outcome='',"
                    " resolution_basis='', closed_at=NULL, close_reason='',"
                    " need_human=0, need_human_reason=''"
                    " WHERE id=?",
                    (now(), inc_id),
                )
                row = conn.execute(
                    "SELECT generation FROM incidents WHERE id=?", (inc_id,)
                ).fetchone()
                gen = int(row["generation"] if row else 1)
                try:
                    from .fmt import fmt_incident_open

                    body = fmt_incident_open(
                        {
                            "title": f"{asset_id or 'unknown'} / {object_id or alertname}: {alertname}",
                            "asset_id": asset_id,
                            "object_id": object_id,
                            "created_at": now(),
                        },
                        at=now(),
                        refire=True,
                    )
                except Exception:
                    body = f"告警复发\n{asset_id}/{object_id}: {alertname}"
                conn.execute(
                    "INSERT INTO events(incident_id, episode_id, at, type, title, payload_json)"
                    " VALUES(?,?,?,?,?,?)",
                    (inc_id, episode_id, now(), "incident_reopened",
                     f"告警复发 {alertname}",
                     json.dumps(
                         {
                             "episode_id": episode_id,
                             "generation": gen,
                             "problem_family": problem_family,
                             "canonical_object": canonical,
                             "body": body,
                         },
                         ensure_ascii=False,
                     )),
                )
            self._bind_event_episode(episode_id, inc_id)
            self._touch_session(inc_id)
            return inc_id
        inc_id = new_id("inc")
        title = f"{asset_id or 'unknown'} / {object_id or alertname}: {alertname}"
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
                " need_human, summary, generation, outcome, created_at, updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (inc_id, title, asset_id, object_id, "warning", "open", "pending",
                 0, "", 1, "", now(), now()),
            )
            conn.execute(
                "UPDATE alert_episodes SET incident_id=? WHERE id=?", (inc_id, episode_id)
            )
            conn.execute(
                "INSERT INTO events(incident_id, episode_id, at, type, title, payload_json)"
                " VALUES(?,?,?,?,?,?)",
                (inc_id, episode_id, now(), "incident_opened", title,
                 json.dumps(
                     {
                         "episode_id": episode_id,
                         "alertname": alertname,
                         "problem_family": problem_family,
                         "canonical_object": canonical,
                     },
                     ensure_ascii=False,
                 )),
            )
        self._bind_event_episode(episode_id, inc_id)
        self._touch_session(inc_id)
        return inc_id

    def _bind_event_episode(self, episode_id: str, inc_id: str) -> None:
        """Event 必须能关联 episode_id / incident_id，不丢失归属。"""
        self.db.execute(
            "UPDATE events SET incident_id=? WHERE episode_id=? AND (incident_id IS NULL OR incident_id='')",
            (inc_id, episode_id),
        )

    def on_episode_resolved(self, episode_id: str) -> None:
        ep = self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (episode_id,))
        if not ep or not ep["incident_id"]:
            return
        inc_id = ep["incident_id"]
        if not self.episode_is_current(inc_id, dict(ep)):
            return
        # AM 明确 resolved 同一问题时，收敛仍挂在事件上的 not_seen 僵尸，
        # 否则旧 not_seen 会一直占着 status=firing，把真实恢复卡住。
        self.db.execute(
            "UPDATE alert_episodes SET status='resolved', source_state='resolved', last_seen=?"
            " WHERE incident_id=? AND status='firing' AND source_state='not_seen'"
            " AND alertname=? AND asset_id=? AND COALESCE(object_id,'')=? AND first_seen<=?",
            (now(), inc_id, ep["alertname"] or "", ep["asset_id"] or "", ep["object_id"] or "", ep["first_seen"]),
        )
        remaining = self.db.query_one(
            "SELECT COUNT(*) AS n FROM alert_episodes WHERE incident_id=? AND status='firing'",
            (inc_id,),
        )
        n_firing = int(remaining["n"] if remaining else 0)
        if n_firing > 0:
            # 同事件还有别的问题在响，先别闭环。
            # 不要把 stage 打成 watching：那会把事件踢出 Agent 捞取窗口。
            return
        # 目标已恢复：直接闭环，理由=目标已恢复（不再被 need_human / 缺验证卡住）
        self._force_recovered(inc_id, episode_id=episode_id)

    def episode_is_current(self, inc_id: str, episode: dict) -> bool:
        """旧代恢复补偿不能清理当前故障；首条 episode 由代次事件明确绑定。"""
        generation = self.db.query_one(
            "SELECT id,at,payload_json FROM events WHERE incident_id=? AND type IN"
            " ('generation_bumped','incident_reopened','incident_opened') ORDER BY id DESC LIMIT 1",
            (inc_id,),
        )
        if not generation:
            return True  # 兼容尚未记录代次事件的旧库/人工事件。
        payload = json.loads(generation["payload_json"] or "{}")
        if payload.get("episode_id") == episode["id"]:
            return True
        attached = self.db.query_one(
            "SELECT 1 FROM events WHERE incident_id=? AND episode_id=? AND type='episode_attached' AND id>?",
            (inc_id, episode["id"], generation["id"]),
        )
        if attached:
            return True
        # 兼容旧版关联事件只在 payload 中记录 episode_id 的历史。
        for event in self.db.query(
            "SELECT payload_json FROM events WHERE incident_id=? AND type='episode_attached' AND id>?",
            (inc_id, generation["id"]),
        ):
            if json.loads(event["payload_json"] or "{}").get("episode_id") == episode["id"]:
                return True
        return float(episode["first_seen"] or 0) >= float(generation["at"])

    def ensure_recovery_event(self, inc_id: str, *, episode_id: str = "") -> int | None:
        """已确认的恢复每代只记录一次；状态与事件应在同一外层事务提交。"""
        with self.db.tx() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
            if not row or row["status"] != "resolved" or row["outcome"] != "recovered":
                return None
            generation = conn.execute(
                "SELECT id,at FROM events WHERE incident_id=? AND type IN"
                " ('generation_bumped','incident_reopened','incident_opened') ORDER BY id DESC LIMIT 1",
                (inc_id,),
            ).fetchone()
            previous = conn.execute(
                "SELECT id,payload_json FROM events WHERE incident_id=? AND type='incident_resolved' AND id>?",
                (inc_id, generation["id"] if generation else 0),
            ).fetchall()
            for event in previous:
                payload = json.loads(event["payload_json"] or "{}")
                if int(payload.get("generation") or row["generation"] or 1) == int(row["generation"] or 1):
                    return event["id"]
            from .fmt import fmt_incident_resolved
            snapshot = dict(row)
            if generation:
                snapshot["created_at"] = generation["at"]
            return self.db.event(
                "incident_resolved", "目标已恢复", incident_id=inc_id, episode_id=episode_id,
                payload={"episode_id": episode_id, "generation": int(row["generation"] or 1),
                         "reason": "目标已恢复", "resolution_basis": row["resolution_basis"],
                         "body": fmt_incident_resolved(snapshot)},
            )

    def _force_recovered(self, inc_id: str, *, episode_id: str = "") -> dict[str, Any]:
        """目标已恢复即闭环：outcome=recovered，理由=目标已恢复。"""
        t = now()
        gen = 1
        with self.db.tx() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
            if not row:
                return {"ok": False, "error": "not_found"}
            if row["status"] in ("resolved", "closed"):
                if row["status"] == "resolved":
                    self.ensure_recovery_event(inc_id, episode_id=episode_id)
                return {"ok": True, "status": row["status"], "outcome": row["outcome"] or ""}
            gen = int(row["generation"] or 1)
            conn.execute(
                "UPDATE incidents SET status='resolved', stage='done', outcome='recovered',"
                " resolution_basis='target_recovered', resolved_at=?, updated_at=?,"
                " need_human=0, need_human_reason='', close_reason='目标已恢复'"
                " WHERE id=?",
                (t, t, inc_id),
            )
            self.ensure_recovery_event(inc_id, episode_id=episode_id)
        self._cancel_pending_proposals(inc_id, "target_recovered")
        return {"ok": True, "status": "resolved", "outcome": "recovered", "generation": gen}

    def _cancel_pending_proposals(self, inc_id: str, reason: str) -> int:
        """终态撤销尚未派发的操作；已批准也不能在恢复后继续执行。"""
        t = now()
        n = 0
        rows = self.db.query(
            "SELECT id FROM actions WHERE incident_id=? AND state IN ('proposed','approved')", (inc_id,)
        )
        for r in rows:
            cur = self.db.execute(
                "UPDATE actions SET state='cancelled', finished_at=?, result_detail=?"
                " WHERE id=? AND state IN ('proposed','approved')",
                (t, f"stale:{reason}", r["id"]),
            )
            if cur and cur.rowcount:
                n += 1
                self.db.event(
                    "action_cancelled",
                    f"stale proposal cancelled {r['id']}",
                    incident_id=inc_id,
                    payload={"action_id": r["id"], "reason": reason},
                )
        return n

    def bump_generation(self, inc_id: str) -> int:
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE incidents SET generation=generation+1, updated_at=? WHERE id=?",
                (now(), inc_id),
            )
            row = conn.execute("SELECT generation FROM incidents WHERE id=?", (inc_id,)).fetchone()
            gen = int(row["generation"] if row else 1)
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    inc_id,
                    now(),
                    "generation_bumped",
                    f"generation={gen}",
                    json.dumps({"generation": gen}, ensure_ascii=False),
                ),
            )
        self._touch_session(inc_id, generation=gen)
        return gen

    def close_manual(
        self, inc_id: str, reason: str, actor: str = "web_user", *,
        policy=None, actor_type: str = "web_user", is_admin: bool = False,
    ) -> dict[str, Any]:
        """人工关闭：closed_at/reason；不伪造 resolved_at；outcome=closed_unverified。"""
        t = now()
        with self.db.tx() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
            if not row:
                return {"ok": False, "error": "not_found"}
            if policy is not None:
                visible = policy.check(
                    subject_type=actor_type, subject_id=actor,
                    capability="asset.summary", asset_id=row["asset_id"], object_id="*",
                )
                if not is_admin or not visible.get("allowed"):
                    return {"ok": False, "error": "permission_denied"}
            conn.execute(
                "UPDATE incidents SET status='closed', stage='done',"
                " closed_at=?, close_reason=?, outcome='closed_unverified',"
                " resolution_basis='manual_close', updated_at=? WHERE id=?",
                (t, reason or "manual close", t, inc_id),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (inc_id, t, "incident_closed", f"manual close: {reason}",
                 json.dumps({"reason": reason, "outcome": "closed_unverified"}, ensure_ascii=False)),
            )
        self._cancel_pending_proposals(inc_id, "manual_close")
        self._close_session_quiet(inc_id)
        return {"ok": True, "outcome": "closed_unverified"}

    def _close_session_quiet(self, inc_id: str) -> None:
        if not self.session_bridge:
            return
        try:
            self.session_bridge.close_session(inc_id, reason="incident_closed")
        except Exception:
            pass

    def set_need_human(self, inc_id: str, reason: str) -> None:
        # 兼容旧字段，同时保存并行义务；一次新的等待批准不能覆盖别的人工任务。
        with self.db.tx() as conn:
            row = conn.execute(
                "SELECT status, need_human, need_human_reason FROM incidents WHERE id=?", (inc_id,)
            ).fetchone()
            if not row or row["status"] != "open":
                return
            reasons = [s for s in (row["need_human_reason"] or "").splitlines() if s]
            if row["need_human"] and not reasons:
                reasons.append("manual_review")
            if reason and reason not in reasons:
                reasons.append(reason)
            conn.execute(
                "UPDATE incidents SET need_human=1, need_human_reason=?, stage='need_human', updated_at=? WHERE id=?",
                ("\n".join(reasons), now(), inc_id),
            )
        self.db.event("need_human", reason, incident_id=inc_id)

    need_human = set_need_human

    def clear_need_human(self, inc_id: str) -> None:
        self.db.execute(
            "UPDATE incidents SET need_human=0, need_human_reason='', updated_at=? WHERE id=?",
            (now(), inc_id),
        )

    def clear_awaiting_approval(self, inc_id: str, action_id: str) -> None:
        self.clear_action_obligation(inc_id, action_id)

    def clear_action_obligation(self, inc_id: str, action_id: str, kind: str = "awaiting_approval") -> None:
        """只清除已经决定的这个提案的义务，保留其他人工处理原因。"""
        if not inc_id:
            return
        prefix = f"{kind}:{action_id}"
        with self.db.tx() as conn:
            row = conn.execute(
                "SELECT need_human_reason, stage FROM incidents WHERE id=?", (inc_id,)
            ).fetchone()
            if not row:
                return
            reasons = [s for s in (row["need_human_reason"] or "").splitlines() if s]
            remaining = [s for s in reasons if s.split(maxsplit=1)[0] != prefix]
            if remaining == reasons:
                return
            stage = row["stage"]
            if stage in ("awaiting_approval", "need_human"):
                stage = "need_human" if remaining else "pending"
            conn.execute(
                "UPDATE incidents SET need_human=?, need_human_reason=?, stage=?, updated_at=?"
                " WHERE id=?",
                (int(bool(remaining)), "\n".join(remaining), stage, now(), inc_id),
            )

    def source_block_reason(self, inc_id: str) -> str:
        """自动恢复的来源闸；无告警来源的人工事件仍可由其他契约约束。"""
        row = self.db.query_one(
            "SELECT id, source_state, source_health FROM alert_episodes WHERE incident_id=?"
            " AND (source_state='quarantine' OR source_health!='ok')"
            " ORDER BY (source_state='quarantine' OR source_health='quarantine') DESC LIMIT 1",
            (inc_id,),
        )
        if not row:
            return ""
        if row["source_state"] == "quarantine" or row["source_health"] == "quarantine":
            return f"quarantined_source:{row['id']}"
        return f"unhealthy_source:{row['id']}:{row['source_health']}"

    def has_blocking_obligations(self, inc_id: str, *, include_proposed: bool = False) -> bool:
        """自动恢复阻塞判定单点（P1-2）。

        以 incidents.reconcile 的阻塞集合为准：
        - firing episodes
        - actions: unknown/dispatched 或 success 且有待验证
        - pending verifications
        - need_human

        include_proposed=True 时（exttx 语义）额外把 proposed/approved 也视为阻塞。
        """
        if not inc_id:
            return False
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM alert_episodes WHERE incident_id=? AND status='firing'",
            (inc_id,),
        )
        if row and int(row["n"] or 0) > 0:
            return True
        if include_proposed:
            row = self.db.query_one(
                "SELECT COUNT(*) AS n FROM actions WHERE incident_id=?"
                " AND state IN ('unknown','dispatched','proposed','approved')",
                (inc_id,),
            )
        else:
            row = self.db.query_one(
                "SELECT COUNT(*) AS n FROM actions WHERE incident_id=?"
                " AND (state IN ('unknown','dispatched')"
                "  OR (state='success' AND id IN (SELECT action_id FROM verifications"
                "      WHERE status='pending')))",
                (inc_id,),
            )
        if row and int(row["n"] or 0) > 0:
            return True
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM verifications WHERE incident_id=? AND status='pending'",
            (inc_id,),
        )
        if row and int(row["n"] or 0) > 0:
            return True
        inc = self.db.query_one("SELECT need_human FROM incidents WHERE id=?", (inc_id,))
        return bool(inc and inc["need_human"])

    def object_actions_locked(self, asset_id: str, object_id: str, *, exclude: str = "") -> bool:
        """对象上是否存在未了结写操作（object lock / no-replay）。"""
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM actions"
            " WHERE asset_id=? AND object_id=? AND id != ?"
            " AND (state IN ('unknown','dispatched')"
            "  OR (state='success' AND id IN (SELECT action_id FROM verifications"
            "      WHERE status='pending')))",
            (asset_id, object_id, exclude),
        )
        return bool(row and int(row["n"] or 0) > 0)

    def set_stage(self, inc_id: str, stage: str, note: str = "") -> None:
        self.db.execute(
            "UPDATE incidents SET stage=?, updated_at=? WHERE id=?", (stage, now(), inc_id)
        )
        self.db.event("stage_changed", note or stage, incident_id=inc_id, payload={"stage": stage})

    def on_verification_finished(
        self, inc_id: str, action_id: str, verification_id: str, generation: int, status: str,
        *, reason: str = "",
    ) -> dict[str, Any]:
        """验证只提交本代证据；生命周期统一在这里收敛。

        迟到结果保留在 verifications，不得污染新代次、人工关闭或来源确认的恢复。
        当前代验证不通过仍需人工，避免对同一故障无限重启。
        """
        row = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not row:
            return {"ok": False, "error": "not_found"}
        if int(row["generation"] or 1) != generation:
            return {"ok": True, "skipped": "stale_generation"}
        if row["status"] == "closed" or (
            row["status"] == "resolved" and row["resolution_basis"] == "target_recovered"
        ):
            return {"ok": True, "skipped": "terminal_incident"}
        if status in ("failed", "inconclusive", "unknown"):
            self.db.execute(
                "UPDATE incidents SET stage='need_human',"
                " status=CASE WHEN status='resolved' THEN 'open' ELSE status END,"
                " resolved_at=CASE WHEN status='resolved' THEN NULL ELSE resolved_at END,"
                " outcome=CASE WHEN status='resolved' THEN 'unrecovered' ELSE outcome END,"
                " updated_at=? WHERE id=?",
                (now(), inc_id),
            )
            self.set_need_human(inc_id, reason or f"verify_{status}:{verification_id}")
        elif status == "passed":
            self.clear_awaiting_approval(inc_id, action_id)
        return self.reconcile(inc_id, resolution_basis=f"verification:{verification_id}")

    # ---- 唯一收敛 ----

    def reconcile(self, inc_id: str, *, resolution_basis: str = "") -> dict[str, Any]:
        """计算并写入 lifecycle / stage / outcome。返回摘要。"""
        if not inc_id:
            return {"ok": False, "error": "no_incident"}
        row = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not row:
            return {"ok": False, "error": "not_found"}
        inc = dict(row)
        gen = int(inc.get("generation") or 1)
        # 来源明确恢复是终态事实；普通 reconcile 不能改写它的依据。
        # 新故障必须经 upsert_from_episode 进入新 generation。
        if inc["status"] == "resolved" and inc.get("resolution_basis") == "target_recovered":
            return {"ok": True, "status": "resolved", "stage": "done", "outcome": "recovered",
                    "generation": gen, "blocked": [], "resolution_basis": "target_recovered"}

        # 兼容修复前遗留的等待批准标志，只用当前代次的决定/通过证据核销对应义务。
        generation = self.db.query_one(
            "SELECT at FROM events WHERE incident_id=? AND type IN"
            " ('generation_bumped','incident_reopened','incident_opened')"
            " ORDER BY id DESC LIMIT 1", (inc_id,),
        )
        cutoff = float(generation["at"]) if generation else 0.0
        if (generation or gen == 1) and inc.get("need_human") and "awaiting_approval:" in (inc.get("need_human_reason") or ""):
            decided = self.db.query(
                "SELECT a.id FROM actions a WHERE a.incident_id=? AND a.created_at>=?"
                " AND a.state IN ('approved','dispatched','success','failure','unknown','cancelled','expired','rejected')"
                " AND (a.approved_at IS NOT NULL OR a.state IN ('cancelled','expired','rejected')"
                " OR EXISTS (SELECT 1 FROM verifications v WHERE v.action_id=a.id"
                " AND v.status='passed' AND (v.generation IS NULL OR v.generation=?)))",
                (inc_id, cutoff, gen),
            )
            for action in decided:
                self.clear_awaiting_approval(inc_id, action["id"])
            inc = dict(self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,)))

        firing = self.db.query_one(
            "SELECT COUNT(*) AS n FROM alert_episodes WHERE incident_id=? AND status='firing'",
            (inc_id,),
        )
        n_firing = int(firing["n"] if firing else 0)

        # 仅当前 generation 的 Action/Verification 参与恢复结论
        unknown = self.db.query_one(
            "SELECT COUNT(*) AS n FROM actions WHERE incident_id=? AND state IN ('unknown','dispatched')",
            (inc_id,),
        )
        n_unknown = int(unknown["n"] if unknown else 0)
        pending_ver = self.db.query_one(
            "SELECT COUNT(*) AS n FROM verifications WHERE incident_id=? AND status='pending'"
            " AND (generation IS NULL OR generation=?)",
            (inc_id, gen),
        )
        n_pending = int(pending_ver["n"] if pending_ver else 0)
        passed = self.db.query_one(
            "SELECT COUNT(*) AS n FROM verifications WHERE incident_id=? AND status='passed'"
            " AND (generation IS NULL OR generation=?)",
            (inc_id, gen),
        )
        n_passed = int(passed["n"] if passed else 0)

        need = bool(inc.get("need_human"))
        already = inc.get("status")

        # closed 不再被 verification 改成 recovered
        if already == "closed":
            return {
                "ok": True,
                "status": "closed",
                "outcome": inc.get("outcome") or "closed_unverified",
                "generation": gen,
                "blocked": [],
            }

        blocked: list[str] = []
        if n_firing > 0:
            blocked.append(f"firing:{n_firing}")
        if n_unknown > 0:
            blocked.append(f"unknown_or_dispatched:{n_unknown}")
        if n_pending > 0:
            blocked.append(f"verification_pending:{n_pending}")
        if need:
            blocked.append("need_human")

        # outcome 判定（不自动 recovered，除非满足全部条件）
        outcome = ""
        status = already
        stage = inc.get("stage") or "pending"
        resolved_at = inc.get("resolved_at")
        basis = resolution_basis or inc.get("resolution_basis") or ""

        can_recover = (
            not blocked
            and n_passed > 0
            and n_firing == 0
            and n_unknown == 0
            and n_pending == 0
            and not need
        )
        # 有 passed 证据且无阻塞 → recovered
        if can_recover and already == "open":
            status = "resolved"
            outcome = "recovered"
            stage = "done"
            resolved_at = resolved_at or now()
            if not basis:
                basis = "verification_passed"
            # 自然恢复：取消过时 proposal
            self._cancel_pending_proposals(inc_id, "verification_recovered")
        elif already == "open" and not blocked and n_passed == 0 and n_firing == 0:
            # 无阻塞也无恢复证据：保持 open/watching，outcome unknown
            outcome = "unknown"
            stage = "watching" if stage in ("pending", "verifying", "executing") else stage
        elif already == "open":
            outcome = "unrecovered" if n_firing else ("unknown" if n_unknown or n_pending else "unrecovered")
            if need:
                stage = "need_human"
        elif already == "resolved":
            # 已 resolved 但出现新阻塞/复发 → reopen handled by caller bumping generation
            outcome = inc.get("outcome") or "recovered"
        else:
            outcome = inc.get("outcome") or "unknown"

        # 展示阶段由当前义务/操作事实推导，不能在动作已执行后仍显示“待调查”。
        if status == "open":
            from .actions import action_incident_block
            current_states = {
                action["state"] for action in self.db.query(
                    "SELECT * FROM actions WHERE incident_id=? AND state IN"
                    " ('proposed','approved','dispatched','success','unknown')", (inc_id,),
                ) if not action_incident_block(self.db, action)
            }
            if need:
                obligations = [r for r in (inc.get("need_human_reason") or "").splitlines() if r]
                stage = "awaiting_approval" if (
                    "proposed" in current_states and obligations
                    and all(r.startswith("awaiting_approval:") for r in obligations)
                ) else "need_human"
            elif n_pending:
                stage = "verifying"
            elif "dispatched" in current_states or "approved" in current_states:
                stage = "executing"
            elif "proposed" in current_states:
                stage = "awaiting_approval"
            elif "success" in current_states or stage in ("executing", "verifying", "awaiting_approval"):
                stage = "watching"

        # 迟到的旧 generation passed：只记历史，不改 outcome
        stale_passed = self.db.query_one(
            "SELECT COUNT(*) AS n FROM verifications WHERE incident_id=? AND status='passed'"
            " AND generation IS NOT NULL AND generation<>?",
            (inc_id, gen),
        )

        with self.db.tx() as conn:
            conn.execute(
                "UPDATE incidents SET status=?, stage=?, outcome=?, resolution_basis=?,"
                " resolved_at=?, updated_at=? WHERE id=?",
                (status, stage, outcome, basis, resolved_at, now(), inc_id),
            )
            if status == "resolved" and outcome == "recovered":
                self.ensure_recovery_event(inc_id)
        return {
            "ok": True,
            "status": status,
            "stage": stage,
            "outcome": outcome,
            "generation": gen,
            "blocked": blocked,
            "n_passed_current_gen": n_passed,
            "stale_passed": int(stale_passed["n"] if stale_passed else 0),
            "resolved_at": resolved_at,
            "resolution_basis": basis,
        }

    # ---- 兼容旧调用 ----

    def reevaluate_after_action(self, inc_id: str) -> None:
        self.reconcile(inc_id, resolution_basis="after_action")

    def list_incidents(self, status: str = "", limit: int = 50) -> list[dict[str, Any]]:
        if status:
            rows = self.db.query(
                "SELECT * FROM incidents WHERE status=? ORDER BY updated_at DESC LIMIT ?",
                (status, limit),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in rows]

    def get_incident(
        self,
        inc_id: str,
        *,
        event_limit: int = 80,
        event_cursor: int | None = None,
    ) -> dict[str, Any] | None:
        """事件详情。

        timeline 默认取最新片段（desc 游标），保证最新事件可见；
        event_cursor 为上一页最小 event id，传入后继续向前加载历史。
        """
        row = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not row:
            return None
        data = dict(row)
        limit = max(1, min(int(event_limit or 80), 200))
        if event_cursor is not None:
            events = self.db.query(
                "SELECT * FROM events WHERE incident_id=? AND id < ?"
                " ORDER BY id DESC LIMIT ?",
                (inc_id, int(event_cursor), limit),
            )
        else:
            events = self.db.query(
                "SELECT * FROM events WHERE incident_id=? ORDER BY id DESC LIMIT ?",
                (inc_id, limit),
            )
        event_rows = [dict(r) for r in events]
        data["events"] = event_rows
        data["events_oldest_id"] = event_rows[-1]["id"] if event_rows else None
        data["events_has_more"] = len(event_rows) == limit
        data["episodes"] = [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM alert_episodes WHERE incident_id=? ORDER BY first_seen ASC",
                (inc_id,),
            )
        ]
        data["actions"] = [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM actions WHERE incident_id=? ORDER BY created_at ASC",
                (inc_id,),
            )
        ]
        for a in data["actions"]:
            a["verifications"] = [
                dict(r)
                for r in self.db.query(
                    "SELECT * FROM verifications WHERE action_id=? ORDER BY started_at ASC",
                    (a["id"],),
                )
            ]
        data["investigations"] = [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM investigations WHERE incident_id=? ORDER BY created_at ASC",
                (inc_id,),
            )
        ]
        data["verifications"] = [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM verifications WHERE incident_id=? ORDER BY started_at ASC",
                (inc_id,),
            )
        ]
        return data

    def list_closed_loops(self, limit: int = 50) -> list[dict[str, Any]]:
        out = []
        for r in self.db.query(
            "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
        ):
            full = self.get_incident(r["id"])
            if full:
                out.append(full)
        return out

    def summary_text(self, inc_id: str, *, for_qq: bool = False) -> str:
        from .fmt import ZH_STATUS

        inc = self.get_incident(inc_id)
        if not inc:
            return "未找到事件"
        title = inc.get("title") or ""
        status = ZH_STATUS.get(inc.get("status"), inc.get("status") or "")
        outcome = inc.get("outcome") or "-"
        gen = inc.get("generation") or 1
        if for_qq:
            return f"{title}\n状态: {status} outcome={outcome} gen={gen}"
        return f"Incident {inc_id} {title} status={status} outcome={outcome}"
