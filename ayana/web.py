"""Web 控制台：本地认证（密码+TOTP）、资产/事件/操作/权限/审计。"""

from __future__ import annotations

import hmac
import json
import logging
from pathlib import Path
from typing import Any

from aiohttp import web

from .actions import ActionError, ActionService
from .auth import AuthError, AuthService
from .db import Database, now
from .incidents import IncidentService
from .investigation import InvestigationService
from .policy import Policy, PolicyDeny
from .prom import PromClient, summarize_probe

log = logging.getLogger("ayana.web")

SESSION_COOKIE = "ayana_session"


def _json(data: Any, status: int = 200) -> web.Response:
    return web.json_response(data, status=status)


class WebApp:
    def __init__(
        self,
        db: Database,
        auth: AuthService,
        policy: Policy,
        incidents: IncidentService,
        investigation: InvestigationService,
        actions: ActionService,
        prom: PromClient,
        *,
        static_dir: Path,
        version: str = "0.2.0",
        webhook_token: str = "",
        alert_ingest=None,
        notifier=None,
        agent=None,
    ):
        self.db = db
        self.auth = auth
        self.policy = policy
        self.incidents = incidents
        self.investigation = investigation
        self.actions = actions
        self.prom = prom
        self.static_dir = static_dir
        self.version = version
        self.webhook_token = webhook_token
        self.alert_ingest = alert_ingest
        self.notifier = notifier
        self.agent = agent

    def build(self) -> web.Application:
        app = web.Application(client_max_size=2_000_000)
        app.router.add_get("/", self.page_index)
        app.router.add_get("/login", self.page_index)

        async def static_with_nocache(request: web.Request) -> web.Response:
            # 静态资源不缓存，避免每次都要无痕/强刷
            name = request.match_info.get("name", "")
            target = (self.static_dir / name).resolve()
            if not str(target).startswith(str(self.static_dir.resolve())) or not target.is_file():
                return web.Response(status=404, text="Not Found")
            resp = web.FileResponse(target)
            resp.headers["Cache-Control"] = "no-cache, must-revalidate"
            resp.headers["Pragma"] = "no-cache"
            return resp

        app.router.add_get("/static/{name}", static_with_nocache)
        app.router.add_get("/static/{name:.+}", static_with_nocache)
        app.router.add_get("/health", self.health)
        app.router.add_get("/ready", self.ready)
        app.router.add_get("/api/me", self.api_me)
        app.router.add_post("/api/login", self.api_login)
        app.router.add_post("/api/logout", self.api_logout)
        app.router.add_post("/api/totp/setup", self.api_totp_setup)
        app.router.add_post("/api/totp/confirm", self.api_totp_confirm)
        app.router.add_post("/api/totp/disable", self.api_totp_disable)
        app.router.add_post("/api/password", self.api_change_password)
        app.router.add_get("/api/overview", self.api_overview)
        app.router.add_get("/api/assets", self.api_assets)
        app.router.add_get("/api/assets/{asset_id}", self.api_asset_detail)
        app.router.add_post("/api/assets/{asset_id}/investigate", self.api_investigate)
        app.router.add_get("/api/incidents", self.api_incidents)
        app.router.add_get("/api/incidents/{inc_id}", self.api_incident_detail)
        app.router.add_get("/api/loops", self.api_loops)
        app.router.add_post("/api/incidents/{inc_id}/close", self.api_incident_close)
        app.router.add_get("/api/actions", self.api_actions)
        app.router.add_get("/api/actions/{aid}", self.api_action_detail)
        app.router.add_post("/api/actions", self.api_action_propose)
        app.router.add_post("/api/actions/{aid}/approve", self.api_action_approve)
        app.router.add_post("/api/actions/{aid}/reject", self.api_action_reject)
        app.router.add_post("/api/actions/{aid}/cancel", self.api_action_cancel)
        app.router.add_post("/api/actions/{aid}/execute", self.api_action_execute)
        app.router.add_post("/api/actions/{aid}/verify", self.api_action_verify)
        app.router.add_get("/api/permissions", self.api_permissions)
        app.router.add_post("/api/permissions", self.api_permission_upsert)
        app.router.add_post("/api/permissions/delete", self.api_permission_delete)
        app.router.add_get("/api/knowledge", self.api_knowledge)
        app.router.add_get("/api/audit", self.api_audit)
        app.router.add_get("/api/notifications", self.api_notifications)
        app.router.add_post("/api/notifications/retry", self.api_notifications_retry)
        app.router.add_get("/api/runbook", self.api_runbook)
        app.router.add_post("/api/agent/auto", self.api_agent_auto_toggle)
        app.router.add_get("/api/agent/status", self.api_agent_status)
        app.router.add_get("/api/capabilities", self.api_capabilities)
        app.router.add_get("/api/prom/probe", self.api_prom_probe)
        app.router.add_post("/hooks/alertmanager", self.hook_alertmanager)
        return app

    # ---- auth helpers ----

    def _session(self, request: web.Request) -> dict[str, Any] | None:
        sid = request.cookies.get(SESSION_COOKIE, "")
        return self.auth.get_session(sid)

    def _require_auth(self, request: web.Request) -> dict[str, Any] | None:
        sess = self._session(request)
        if not sess:
            raise web.HTTPUnauthorized(text=json.dumps({"error": "unauthorized"}))
        return sess

    def _require_admin(self, request: web.Request) -> dict[str, Any]:
        sess = self._require_auth(request)
        if not sess.get("is_admin"):
            raise web.HTTPForbidden(text=json.dumps({"error": "admin_required"}))
        return sess

    def _check_csrf(self, request: web.Request, sess: dict) -> None:
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return
        origin = request.headers.get("Origin", "")
        host = request.headers.get("Host", "")
        if origin and host and origin not in (
            f"http://{host}",
            f"https://{host}",
        ):
            # 允许同源或无 Origin（curl）
            if not origin.endswith(host):
                raise web.HTTPForbidden(text=json.dumps({"error": "bad_origin"}))
        token = request.headers.get("X-CSRF-Token", "") or (
            request.rel_url.query.get("csrf", "")
        )
        if not token or not hmac.compare_digest(token, sess.get("csrf_token", "")):
            raise web.HTTPForbidden(text=json.dumps({"error": "bad_csrf"}))

    # ---- pages ----

    async def page_index(self, request: web.Request) -> web.Response:
        index = self.static_dir / "index.html"
        if index.exists():
            resp = web.FileResponse(index)
            resp.headers["Cache-Control"] = "no-cache, must-revalidate"
            return resp
        return web.Response(text="Ayana", content_type="text/plain")

    async def health(self, request: web.Request) -> web.Response:
        return _json(
            {
                "ok": True,
                "service": "ayana",
                "version": self.version,
                "uptime_ok": True,
            }
        )

    async def ready(self, request: web.Request) -> web.Response:
        try:
            self.db.query_one("SELECT 1 AS x")
            db_ok = True
        except Exception:
            db_ok = False
        return _json({"ok": db_ok, "db": db_ok, "version": self.version}, 200 if db_ok else 503)

    # ---- auth api ----

    async def api_me(self, request: web.Request) -> web.Response:
        sess = self._session(request)
        if not sess:
            return _json({"ok": False, "user": None})
        return _json(
            {
                "ok": True,
                "user": {
                    "username": sess["username"],
                    "is_admin": sess["is_admin"],
                    "user_id": sess["user_id"],
                },
                "csrf_token": sess["csrf_token"],
            }
        )

    async def api_login(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json"}, 400)
        ip = request.remote or ""
        try:
            sess = self.auth.login(
                body.get("username", ""),
                body.get("password", ""),
                body.get("totp", ""),
                body.get("recovery_code", ""),
                ip=ip,
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 401)
        resp = _json({"ok": True, "csrf_token": sess["csrf_token"]})
        resp.set_cookie(
            SESSION_COOKIE,
            sess["session_id"],
            httponly=True,
            samesite="Lax",
            max_age=self.auth.session_ttl,
            path="/",
        )
        self.db.audit("web_user", body.get("username", ""), "login_ok", detail={"ip": ip})
        return resp

    async def api_logout(self, request: web.Request) -> web.Response:
        sess = self._session(request)
        if sess:
            self.auth.logout(sess["session_id"])
        resp = _json({"ok": True})
        resp.del_cookie(SESSION_COOKIE)
        return resp

    async def api_totp_setup(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            data = self.auth.setup_totp(
                sess["user_id"], password=body.get("password", ""), totp_code=body.get("totp", "")
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        return _json({"ok": True, **data})

    async def api_totp_confirm(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            codes = self.auth.confirm_totp(
                sess["user_id"], body.get("code", ""), password=body.get("password", "")
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        # 旧会话已被撤销，给当前会话重新签发
        new_sess = self.auth._issue_session(sess["user_id"])
        self.db.audit("web_user", sess["username"], "totp_enabled")
        resp = _json({"ok": True, "recovery_codes": codes, "csrf_token": new_sess["csrf_token"]})
        resp.set_cookie(
            SESSION_COOKIE,
            new_sess["session_id"],
            httponly=True,
            samesite="Lax",
            max_age=self.auth.session_ttl,
            path="/",
        )
        return resp

    async def api_totp_disable(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            self.auth.disable_totp(
                sess["user_id"], password=body.get("password", ""), totp_code=body.get("totp", "")
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        new_sess = self.auth._issue_session(sess["user_id"])
        resp = _json({"ok": True, "csrf_token": new_sess["csrf_token"]})
        resp.set_cookie(
            SESSION_COOKIE,
            new_sess["session_id"],
            httponly=True,
            samesite="Lax",
            max_age=self.auth.session_ttl,
            path="/",
        )
        return resp

    async def api_change_password(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            self.auth.change_password(
                sess["user_id"], body.get("old_password", ""), body.get("new_password", "")
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        self.db.audit("web_user", sess["username"], "password_changed")
        return _json({"ok": True})

    # ---- business api ----

    async def api_overview(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        from .health import REQUIRED_CHECKS, asset_health

        assets_raw = self.db.query("SELECT * FROM assets ORDER BY id")
        assets = []
        open_inc = self.incidents.list_incidents(status="open", limit=50)
        open_by_asset = {}
        for i in open_inc:
            aid = i.get("asset_id") or ""
            open_by_asset[aid] = open_by_asset.get(aid, 0) + 1
        for a in assets_raw:
            d = dict(a)
            d["objects"] = [
                dict(o)
                for o in self.db.query("SELECT * FROM objects WHERE asset_id=?", (a["id"],))
            ]
            samples_by_metric = {}
            req = REQUIRED_CHECKS.get(a["id"], [])
            metrics = {c.get("metric") for c in req if c.get("metric")}
            for metric in metrics:
                try:
                    if metric == "hysteria_proxy_up":
                        hy = await self.prom.query("hysteria_proxy_up")
                        samples_by_metric[metric] = hy.get("result") or []
                    elif metric == "probe_success":
                        samples_by_metric[metric] = await self.prom.probe_success_since(
                            a["id"], "", start=now() - 300
                        )
                    else:
                        samples_by_metric[metric] = []
                except Exception:
                    samples_by_metric[metric] = []
            health = asset_health(
                asset_id=a["id"],
                objects=d["objects"],
                samples_by_metric=samples_by_metric,
                open_incidents=open_by_asset.get(a["id"], 0),
            )
            d["health"] = health
            d["probe"] = {"state": health.get("state", "unknown")}
            assets.append(d)
        need = [i for i in open_inc if i.get("need_human")]
        actions = self.actions.list_actions(limit=10)
        pending_actions = [x for x in actions if x.get("state") in ("proposed", "approved", "dispatched")]
        unknown_actions = [x for x in actions if x.get("state") == "unknown"]
        sources = {}
        try:
            targets = await self.prom.targets()
            sources["prometheus_targets"] = len(targets)
            sources["prometheus_unhealthy"] = sum(1 for t in targets if t.get("health") != "up")
        except Exception as e:
            sources["prometheus_error"] = str(e)
        quiet = not need and not open_inc and not pending_actions and not unknown_actions
        return _json(
            {
                "ok": True,
                "version": self.version,
                "assets": assets,
                "open_incidents": open_inc,
                "need_human": need,
                "recent_actions": actions,
                "pending_actions": len(pending_actions),
                "unknown_actions": len(unknown_actions),
                "sources": sources,
                "quiet": quiet,
            }
        )

    async def api_assets(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        rows = self.db.query("SELECT * FROM assets ORDER BY id")
        out = []
        for r in rows:
            d = dict(r)
            d["objects"] = [
                dict(o)
                for o in self.db.query("SELECT * FROM objects WHERE asset_id=?", (r["id"],))
            ]
            out.append(d)
        return _json({"ok": True, "assets": out})

    async def api_asset_detail(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        asset_id = request.match_info["asset_id"]
        row = self.db.query_one("SELECT * FROM assets WHERE id=?", (asset_id,))
        if not row:
            return _json({"ok": False, "error": "not_found"}, 404)
        data = dict(row)
        data["objects"] = [
            dict(o) for o in self.db.query("SELECT * FROM objects WHERE asset_id=?", (asset_id,))
        ]
        sess = self._session(request)
        probe_allowed = False
        if sess:
            d = self.policy.check(
                subject_type="web_user",
                subject_id=sess["username"],
                capability="probe.status",
                asset_id=asset_id,
                object_id="*",
            )
            probe_allowed = bool(d["allowed"])
        if probe_allowed:
            try:
                probe = await self.prom.probe_success(asset_id, "")
                data["probe"] = summarize_probe(probe)
            except Exception as e:
                data["probe"] = {"state": "unavailable", "reason": str(e)}
        else:
            data["probe"] = {"state": "denied", "reason": "policy"}
        data["incidents"] = self.incidents.list_incidents(limit=5)
        return _json({"ok": True, "asset": data})

    async def api_investigate(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        asset_id = request.match_info["asset_id"]
        body = await request.json()
        res = await self.investigation.run(
            asset_id=asset_id,
            object_id=body.get("object_id", ""),
            capability=body.get("capability", "asset.summary"),
            params=body.get("params") or {},
            incident_id=body.get("incident_id", ""),
            actor_type="web_user",
            actor_id=sess["username"],
        )
        return _json(res)

    async def api_incidents(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        status = request.rel_url.query.get("status", "")
        return _json({"ok": True, "incidents": self.incidents.list_incidents(status=status)})

    async def api_loops(self, request: web.Request) -> web.Response:
        """故障闭环：Incident 关联 Investigation / Action / Verification。"""
        self._require_auth(request)
        limit = int(request.rel_url.query.get("limit", "50"))
        loops = self.incidents.list_closed_loops(limit=limit)
        return _json({"ok": True, "loops": loops})

    async def api_incident_detail(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        inc_id = request.match_info["inc_id"]
        inc = self.incidents.get_incident(inc_id)
        if not inc:
            return _json({"ok": False, "error": "not_found"}, 404)
        # 附加人话摘要
        from .fmt import alert_name

        actions_list = inc.get("actions") or []
        last_action = actions_list[-1] if actions_list else None
        summary = self._incident_human_summary(inc, last_action)
        disposition = self._incident_disposition(inc)
        return _json({
            "ok": True,
            "incident": inc,
            "summary": summary,
            "disposition": disposition,
        })

    def _incident_disposition(self, inc: dict) -> dict:
        """P1-01：事件详情处置上下文（服务端求值，前端不重算 Policy）。"""
        from .fmt import ZH_CAP

        actions_list = inc.get("actions") or []
        pending = [a for a in actions_list if a.get("state") in ("proposed", "approved")]
        invs = inc.get("investigations") or []
        last_inv = invs[-1] if invs else None
        evidence_summary = ""
        if last_inv:
            ev = last_inv.get("evidence") or []
            if isinstance(ev, str):
                try:
                    ev = json.loads(ev or "[]")
                except Exception:
                    ev = []
            parts = []
            for e in (ev or [])[:4]:
                if isinstance(e, dict):
                    parts.append(
                        (e.get("summary") or e.get("output") or e.get("source") or "")[:160]
                    )
            evidence_summary = "\n".join(p for p in parts if p)[:600]

        items = []
        for a in pending:
            payload = {}
            try:
                payload = json.loads(a.get("params_json") or "{}")
            except Exception:
                payload = {}
            eff = {}
            try:
                eff = json.loads(a.get("decision_snapshot_json") or a.get("policy_snapshot_json") or "{}")
            except Exception:
                eff = {}
            vers = a.get("verifications") or []
            ver_target = ""
            if vers:
                v = vers[-1]
                ver_target = v.get("note") or v.get("profile_id") or v.get("status") or ""
            items.append({
                "action_id": a.get("id"),
                "state": a.get("state"),
                "capability": a.get("capability"),
                "capability_zh": ZH_CAP.get(a.get("capability", ""), a.get("capability", "")),
                "asset_id": a.get("asset_id"),
                "object_id": a.get("object_id"),
                "reason": a.get("reason", ""),
                "mode": a.get("mode", ""),
                "runbook_id": a.get("runbook_id", ""),
                "runbook_rev": a.get("runbook_rev", ""),
                "template_id": a.get("template_id", ""),
                "approval_deadline": a.get("approval_deadline"),
                "created_at": a.get("created_at"),
                "decision": eff.get("decision", ""),
                "decision_reason": eff.get("reason", ""),
                "matched_rule": eff.get("matched_rule") or (eff.get("rule") or {}),
                "readable": eff.get("readable", ""),
                "verification_target": ver_target,
                "tokens": payload.get("tokens") or [],
                "proposer_type": a.get("proposer_type", ""),
                "proposer_id": a.get("proposer_id", ""),
            })

        policy_view = None
        ref = items[0] if items else (actions_list[-1] if actions_list else None)
        if ref:
            asset_id = ref.get("asset_id") or ""
            object_id = ref.get("object_id") or ""
            capability = ref.get("capability") or ""
            obj_row = self.db.query_one(
                "SELECT id FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                (asset_id, object_id, object_id),
            )
            policy_obj = (obj_row["id"] if obj_row else object_id) or "*"
            subject_type = ref.get("proposer_type") or "web_user"
            subject_id = ref.get("proposer_id") or "system"
            try:
                policy_view = self.policy.effective_decision(
                    subject_type=subject_type,
                    subject_id=subject_id,
                    capability=capability,
                    asset_id=asset_id,
                    object_id=policy_obj,
                )
            except Exception:
                policy_view = None

        return {
            "evidence_summary": evidence_summary,
            "investigation_id": (last_inv or {}).get("id", ""),
            "proposals": items,
            "policy": policy_view,
        }

    def _incident_human_summary(self, inc: dict, action: dict | None) -> dict:
        from .fmt import ZH_CAP, ZH_STAGE, ZH_STATE, alert_name

        timeline = []
        zh_event = {
            "incident_opened": "发现异常",
            "alert_fired": "告警触发",
            "alert_resolved": "告警恢复",
            "alert_resolved_hold": "告警恢复但义务未清",
            "episode_attached": "告警并入事件",
            "investigation": "完成调查",
            "action_proposed": "提出处置",
            "proposal_waiting": "等待人工确认",
            "action_approved": "批准处置",
            "action_rejected": "拒绝处置",
            "action_cancelled": "取消处置",
            "action_expired": "提案过期",
            "action_dispatched": "派发执行",
            "action_success": "处置完成",
            "action_failure": "处置失败",
            "action_unknown": "处置结果未知",
            "verified_recovered": "验证通过",
            "verify_not_passed": "验证未通过",
            "agent_auto_exec": "自动处置",
            "agent_escalated": "转人工",
            "incident_resolved": "事件解决",
            "incident_reopened": "事件复发",
            "incident_closed": "事件关闭",
            "reconcile_not_seen": "对账未见",
            "reconcile_observed": "对账观察",
            "generation_bumped": "轮次递增",
        }
        # 默认优先保证最新事件可见（接口 desc 返回，此处取最新 8 条再正序展示）
        events = list(inc.get("events") or [])
        latest = events[:8] if events else []
        for e in reversed(latest):
            timeline.append({
                "time": e.get("at"),
                "label": zh_event.get(e.get("type", ""), e.get("title", "")),
                "type": e.get("type", ""),
            })

        what = alert_name(inc.get("title", ""))
        why_human = inc.get("need_human_reason", "")
        zh_reason = why_human
        for en, cn in (
            ("no_runbook_match", "没有匹配的自动处置规则"),
            ("policy_denied", "没有自动处置权限"),
            ("budget_exhausted", "自动处置次数已用完"),
            ("auto_remediation_disabled", "自动处置未开启"),
            ("exec_unknown", "执行结果未知，无法确认是否生效"),
            ("exec_failure", "执行失败"),
            ("verify_failed", "恢复验证未通过"),
            ("verify_inconclusive", "恢复验证不充分"),
        ):
            if en in why_human:
                zh_reason = cn
                break

        suggestion = ""
        cap = (action or {}).get("capability", "")
        if inc.get("need_human"):
            if "verify" in why_human or "exec_unknown" in why_human:
                suggestion = "手动检查服务状态，确认后可重新发起处置"
            elif "no_runbook" in why_human or "policy" in why_human:
                suggestion = "手动处理或添加处置规则/权限"
            elif "budget" in why_human:
                suggestion = "等待冷却期结束或手动处置"
            else:
                suggestion = "查看详情后决定下一步"
        elif inc.get("status") == "open":
            suggestion = "系统正在处理，稍候刷新"

        return {
            "title": what,
            "status_zh": {"open": "处理中", "resolved": "已解决", "closed": "已关闭"}.get(inc.get("status"), inc.get("status")),
            "stage_zh": ZH_STAGE.get(inc.get("stage"), inc.get("stage")),
            "why_human": zh_reason if inc.get("need_human") else "",
            "suggestion": suggestion,
            "timeline": timeline,
            "last_action": {
                "capability_zh": ZH_CAP.get(cap, cap),
                "state_zh": ZH_STATE.get((action or {}).get("state", ""), ""),
            } if action else None,
        }

    async def api_incident_close(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        inc_id = request.match_info["inc_id"]
        body = await request.json()
        reason = body.get("reason", "人工关闭")
        # P0-04：closed ≠ recovered，不伪造 resolved_at
        res = self.incidents.close_manual(inc_id, reason, actor=sess["username"])
        if not res.get("ok"):
            return _json({"ok": False, "error": res.get("error", "not_found")}, 404)
        self.db.audit(
            "web_user", sess["username"], "incident_closed",
            asset_id="", object_id=inc_id,
            detail={"reason": reason, "outcome": res.get("outcome")},
        )
        return _json({"ok": True, "outcome": res.get("outcome")})

    async def api_actions(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        q = request.rel_url.query
        manual_only = q.get("manual", "") in ("1", "true", "yes")
        return _json({
            "ok": True,
            "actions": self.actions.list_actions(manual_only=manual_only),
        })

    async def api_action_detail(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        data = self.actions.get_action(request.match_info["aid"])
        if not data:
            return _json({"ok": False, "error": "not_found"}, 404)
        return _json({"ok": True, "action": data})

    async def api_action_propose(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            res = self.actions.propose(
                asset_id=body["asset_id"],
                object_id=body["object_id"],
                capability=body["capability"],
                params=body.get("params") or {},
                reason=body.get("reason", ""),
                incident_id=body.get("incident_id", ""),
                proposer_type="web_user",
                proposer_id=sess["username"],
            )
        except (ActionError, KeyError, ValueError) as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_action_approve(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        execute = bool(body.get("execute", True))
        reason = body.get("reason", "") or ""
        try:
            if execute:
                res = await self.actions.approve_and_execute(
                    request.match_info["aid"],
                    actor_type="web_user",
                    actor_id=sess["username"],
                    channel="web",
                    reason=reason,
                    is_admin=bool(sess.get("is_admin")),
                )
            else:
                res = self.actions.approve(
                    request.match_info["aid"],
                    approver_type="web_user",
                    approver_id=sess["username"],
                    channel="web",
                    reason=reason,
                )
        except ActionError as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_action_reject(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        reason = body.get("reason", "") or ""
        try:
            res = self.actions.reject(
                request.match_info["aid"],
                actor_type="web_user",
                actor_id=sess["username"],
                channel="web",
                reason=reason,
            )
        except ActionError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_action_cancel(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        try:
            self.actions.cancel(
                request.match_info["aid"],
                actor_type="web_user",
                actor_id=sess["username"],
                is_admin=bool(sess.get("is_admin")),
            )
        except ActionError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        return _json({"ok": True})

    async def api_action_execute(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        try:
            res = await self.actions.execute(
                request.match_info["aid"],
                actor_type="web_user",
                actor_id=sess["username"],
                is_admin=bool(sess.get("is_admin")),
            )
        except ActionError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_action_verify(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        try:
            res = await self.actions.verify(request.match_info["aid"])
        except ActionError as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_permissions(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        data = self.policy.effective_summary()
        # 服务端附带三态，前端不自行求优先级
        for p in data.get("permissions") or []:
            try:
                cap_kind = "write"
                from .capabilities import get_capability

                cap_kind = get_capability(p.get("capability") or "").kind
            except Exception:
                cap_kind = "write"
            decision = Policy._three_state(
                allow=bool(p.get("allow")),
                require_approval=bool(p.get("require_approval")),
                auto_allowed=bool(p.get("auto_allowed")),
            )
            if cap_kind != "write":
                decision = "automatic" if p.get("allow") else "forbidden"
            p["decision"] = decision
            p["readable"] = {
                "forbidden": "禁止",
                "approval_required": "需要我确认",
                "automatic": "自动执行" if cap_kind == "write" else "允许读取",
            }.get(decision, decision)
        return _json({"ok": True, **data})

    async def api_permission_upsert(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            res = self.policy.upsert_permission(
                subject_type=body["subject_type"],
                subject_id=body["subject_id"],
                capability=body["capability"],
                allow=bool(body.get("allow", True)),
                asset_id=body.get("asset_id", "*"),
                object_id=body.get("object_id", "*"),
                require_approval=bool(body.get("require_approval", True)),
                auto_allowed=bool(body.get("auto_allowed", False)),
                actor=sess["username"],
            )
        except (PolicyDeny, KeyError) as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json(res)

    async def api_permission_delete(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            self.policy.delete_permission(int(body["id"]), actor=sess["username"])
        except (PolicyDeny, KeyError, ValueError) as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True})

    async def api_knowledge(self, request: web.Request) -> web.Response:
        """运维知识库只读：Markdown 主题（front matter + 正文）。"""
        self._require_auth(request)
        from .knowledge import KnowledgeBase

        kb = KnowledgeBase(self.db)
        q = request.rel_url.query
        doc_id = q.get("id", "")
        if doc_id:
            doc = kb.get(doc_id)
            if not doc:
                return _json({"ok": False, "error": "not_found"}, 404)
            return _json({"ok": True, "knowledge": doc.to_public()})
        items = kb.list_docs(
            status=q.get("status", ""),
            typ=q.get("type", ""),
            q=q.get("q", ""),
        )
        return _json({
            "ok": True,
            "knowledge": [d.to_public() for d in items],
            "note": "Markdown 为知识正文事实源；仅 active 可作为当前调查依据。",
        })

    async def api_audit(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        limit = min(500, int(request.rel_url.query.get("limit", "50")))
        q = request.rel_url.query.get("q", "").strip()
        ts_from = request.rel_url.query.get("from", "")
        ts_to = request.rel_url.query.get("to", "")

        where = []
        params: list[Any] = []
        if q:
            where.append("(entry LIKE ? OR actor_id LIKE ? OR asset_id LIKE ? OR object_id LIKE ? OR detail_json LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like, like, like, like])
        if ts_from:
            try:
                where.append("at>=?")
                params.append(float(ts_from))
            except ValueError:
                pass
        if ts_to:
            try:
                where.append("at<=?")
                params.append(float(ts_to))
            except ValueError:
                pass

        sql = "SELECT * FROM audit_log"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY at DESC LIMIT ?"
        params.append(limit)
        rows = self.db.query(sql, tuple(params))
        return _json({"ok": True, "audit": [dict(r) for r in rows]})

    async def api_notifications(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        failed = self.notifier.failed_summary() if self.notifier else []
        return _json({"ok": True, "failed": failed})

    async def api_notifications_retry(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        n = self.notifier.retry_failed(body.get("id", "")) if self.notifier else 0
        self.db.audit("web_user", sess["username"], "notifications_retry", detail={"count": n})
        return _json({"ok": True, "retried": n})

    async def api_runbook(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        from .runbook import list_runbook

        return _json({"ok": True, "runbook": list_runbook()})

    async def api_agent_auto_toggle(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        enabled = bool(body.get("enabled"))
        if self.agent:
            self.agent.set_auto_enabled(enabled)
        self.db.audit("web_user", sess["username"], f"agent_auto_{enabled}")
        return _json({"ok": True, "auto_enabled": enabled})

    async def api_agent_status(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        from .runbook import list_runbook

        auto = self.agent.auto_enabled if self.agent else False
        llm_ok = getattr(self.agent, "llm", None) and self.agent.llm.enabled
        return _json({
            "ok": True,
            "auto_enabled": auto,
            "llm_enabled": bool(llm_ok),
            "runbook_count": len(list_runbook()),
        })

    async def api_capabilities(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        from .capabilities import list_capabilities

        return _json({"ok": True, "capabilities": list_capabilities()})

    async def api_prom_probe(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        asset = request.rel_url.query.get("asset", "")
        service = request.rel_url.query.get("service", "")
        # 授权用登记对象 ID；查询用登记名称
        object_id = service or "*"
        service_label = service
        if service:
            row = self.db.query_one(
                "SELECT id, name FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                (asset, service, service),
            )
            if row:
                object_id = row["id"]
                service_label = row["name"]
        decision = self.policy.check(
            subject_type="web_user",
            subject_id=sess["username"],
            capability="probe.status",
            asset_id=asset or "*",
            object_id=object_id,
        )
        if not decision["allowed"]:
            return _json({"ok": False, "error": "denied"}, 403)
        try:
            data = await self.prom.probe_success(asset, service_label)
            return _json({"ok": True, "summary": summarize_probe(data), "raw": data})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    # ---- alertmanager ----

    async def hook_alertmanager(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        supplied = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not self.webhook_token or not hmac.compare_digest(supplied, self.webhook_token):
            return _json({"ok": False, "error": "unauthorized"}, 401)
        try:
            payload = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json"}, 400)
        if not self.alert_ingest:
            return _json({"ok": False, "error": "ingest_unavailable"}, 503)
        try:
            res = self.alert_ingest.ingest_webhook(payload)
        except ValueError as e:
            return _json({"ok": False, "error": str(e)}, 400)
        # 接收成功以 DB 为准；QQ 失败不改变接收事实
        return _json({"ok": True, **res})
