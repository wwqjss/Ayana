"""Web 控制台：本地认证（密码+TOTP）、资产/事件/操作/权限/审计。"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
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
        permission_changes=None,
        ssh_store=None,
        cred_store=None,
        transport=None,
        terminal=None,
        channel_store=None,
        host_monitor=None,
        aibot_manager=None,
        mlog=None,
        promconfig=None,
        checks=None,
        llm=None,
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
        self.permission_changes = permission_changes
        self.ssh_store = ssh_store
        self.cred_store = cred_store
        self.transport = transport
        self.terminal = terminal
        self.channel_store = channel_store
        self.host_monitor = host_monitor
        self.aibot_manager = aibot_manager
        self.mlog = mlog
        self.llm = llm
        self.promconfig = promconfig
        self.checks = checks

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
        app.router.add_post("/api/login/step", self.api_login_step)
        app.router.add_post("/api/login/totp", self.api_login_totp)
        app.router.add_post("/api/logout", self.api_logout)
        app.router.add_post("/api/totp/setup", self.api_totp_setup)
        app.router.add_post("/api/totp/confirm", self.api_totp_confirm)
        app.router.add_post("/api/totp/disable", self.api_totp_disable)
        app.router.add_post("/api/password", self.api_change_password)
        app.router.add_get("/api/overview", self.api_overview)
        app.router.add_get("/api/assets", self.api_assets)
        app.router.add_get("/api/assets/{asset_id}", self.api_asset_detail)
        app.router.add_post("/api/assets", self.api_asset_create)
        app.router.add_post("/api/assets/{asset_id}/update", self.api_asset_update)
        app.router.add_delete("/api/assets/{asset_id}", self.api_asset_delete)
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
        app.router.add_get("/api/permissions/model", self.api_permissions_model)
        app.router.add_get("/api/permissions/effective", self.api_permissions_effective)
        app.router.add_post("/api/permissions", self.api_permission_upsert)
        app.router.add_post("/api/permissions/delete", self.api_permission_delete)
        app.router.add_post("/api/permissions/preview", self.api_permission_preview)
        app.router.add_get("/api/permissions/history", self.api_permission_history)
        app.router.add_get("/api/agent-ceiling", self.api_agent_ceiling_list)
        app.router.add_post("/api/agent-ceiling", self.api_agent_ceiling_set)
        # SSH 资产 / 凭据
        app.router.add_get("/api/ssh/endpoints", self.api_ssh_endpoints)
        app.router.add_post("/api/ssh/endpoints", self.api_ssh_endpoint_upsert)
        app.router.add_post("/api/ssh/endpoints/trust", self.api_ssh_trust_host_key)
        app.router.add_delete("/api/ssh/endpoints", self.api_ssh_endpoint_delete)
        app.router.add_get("/api/ssh/roles", self.api_ssh_roles)
        app.router.add_post("/api/ssh/roles", self.api_ssh_role_add)
        app.router.add_get("/api/ssh/credentials", self.api_ssh_credentials)
        app.router.add_post("/api/ssh/credentials", self.api_ssh_credential_create)
        app.router.add_post("/api/ssh/credentials/generate", self.api_ssh_credential_generate)
        app.router.add_post("/api/ssh/credentials/rotate", self.api_ssh_credential_rotate)
        app.router.add_post("/api/ssh/credentials/deploy-pubkey", self.api_ssh_deploy_pubkey)
        app.router.add_delete("/api/ssh/credentials", self.api_ssh_credential_delete)
        app.router.add_post("/api/ssh/test", self.api_ssh_test)
        app.router.add_post("/api/assets/{asset_id}/test", self.api_asset_channel_test)
        app.router.add_post("/api/ssh/switch-to-key", self.api_ssh_switch_to_key)
        app.router.add_post("/api/ssh/hostkey/fetch", self.api_ssh_hostkey_fetch)
        # 人工 Web 终端（仅登录管理员；Agent 不注册）
        app.router.add_get("/api/terminal/check", self.api_terminal_check)
        app.router.add_get("/ws/terminal", self.ws_terminal)
        app.router.add_get("/api/permission-changes", self.api_permission_changes)
        app.router.add_post("/api/permission-changes", self.api_permission_change_propose)
        app.router.add_get("/api/permission-changes/{cid}", self.api_permission_change_present)
        app.router.add_post("/api/permission-changes/{cid}/authorize", self.api_permission_change_authorize)
        app.router.add_post("/api/permission-changes/{cid}/reject", self.api_permission_change_reject)
        app.router.add_get("/api/knowledge", self.api_knowledge)
        app.router.add_get("/api/audit", self.api_audit)
        app.router.add_get("/api/notifications", self.api_notifications)
        app.router.add_post("/api/notifications/retry", self.api_notifications_retry)
        # 多消息渠道
        app.router.add_get("/api/notify/channels", self.api_notify_channels)
        app.router.add_get("/api/notify/kinds", self.api_notify_kinds)
        app.router.add_get("/api/notify/platforms", self.api_notify_platforms)
        app.router.add_get("/api/notify/aibot/status", self.api_notify_aibot_status)
        app.router.add_get("/api/notify/aibot/targets", self.api_notify_aibot_targets)
        app.router.add_post("/api/notify/aibot/targets", self.api_notify_aibot_targets_save)
        app.router.add_get("/api/messages", self.api_messages)
        app.router.add_get("/api/messages/{mid}", self.api_message_detail)
        app.router.add_post("/api/notify/channels", self.api_notify_channel_create)
        app.router.add_post("/api/notify/channels/update", self.api_notify_channel_update)
        app.router.add_post("/api/notify/channels/delete", self.api_notify_channel_delete)
        app.router.add_post("/api/notify/channels/enabled", self.api_notify_channel_enabled)
        app.router.add_post("/api/notify/channels/test", self.api_notify_channel_test)
        app.router.add_get("/api/notify/outbox", self.api_notify_outbox)
        # 主机资源监控
        app.router.add_get("/api/monitor/hosts", self.api_monitor_hosts)
        app.router.add_get("/api/monitor/host/{asset_id}", self.api_monitor_host)
        app.router.add_get("/api/runbook", self.api_runbook)
        app.router.add_post("/api/agent/auto", self.api_agent_auto_toggle)
        app.router.add_get("/api/agent/status", self.api_agent_status)
        app.router.add_get("/api/capabilities", self.api_capabilities)
        app.router.add_get("/api/prom/probe", self.api_prom_probe)
        app.router.add_get("/api/checks", self.api_checks_list)
        app.router.add_post("/api/checks", self.api_checks_create)
        app.router.add_post("/api/assist/configure", self.api_assist_configure)
        app.router.add_get("/api/assist/form", self.api_assist_form)
        app.router.add_post("/api/checks/update", self.api_checks_update)
        app.router.add_post("/api/checks/delete", self.api_checks_delete)
        app.router.add_post("/api/checks/run", self.api_checks_run)
        app.router.add_get("/api/checks/activity", self.api_checks_activity)
        app.router.add_get("/api/promconfig/overview", self.api_promconfig_overview)
        app.router.add_get("/api/promconfig/config", self.api_promconfig_config)
        app.router.add_get("/api/promconfig/targets", self.api_promconfig_targets)
        app.router.add_post("/api/promconfig/targets", self.api_promconfig_target_add)
        app.router.add_post("/api/promconfig/targets/update", self.api_promconfig_target_update)
        app.router.add_post("/api/promconfig/targets/delete", self.api_promconfig_target_delete)
        app.router.add_get("/api/promconfig/rules", self.api_promconfig_rules)
        app.router.add_get("/api/promconfig/rules/templates", self.api_promconfig_rule_templates)
        app.router.add_post("/api/promconfig/rules/template", self.api_promconfig_rule_apply_template)
        app.router.add_post("/api/promconfig/rules/update", self.api_promconfig_rule_update)
        app.router.add_get("/api/promconfig/node-exporter", self.api_promconfig_node_status)
        app.router.add_post("/api/promconfig/node-exporter", self.api_promconfig_node_control)
        app.router.add_post("/api/promconfig/node-exporter/register", self.api_promconfig_node_register)
        app.router.add_post("/api/promconfig/node-exporter/adopt", self.api_promconfig_node_adopt)
        app.router.add_post("/api/promconfig/node-exporter/detect", self.api_promconfig_node_detect)
        app.router.add_post("/api/promconfig/node-exporter/install", self.api_promconfig_node_install)
        app.router.add_post("/api/promconfig/validate", self.api_promconfig_validate)
        app.router.add_post("/api/promconfig/rollback", self.api_promconfig_rollback)
        app.router.add_post("/hooks/alertmanager", self.hook_alertmanager)
        return app

    async def api_assist_form(self, request: web.Request) -> web.Response:
        """返回真实表单结构化定义（单一来源）。"""
        self._require_auth(request)
        from . import formspec

        domain = request.rel_url.query.get("domain", "checks")
        try:
            form = formspec.get_form(domain)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "form": form})

    async def api_assist_configure(self, request: web.Request) -> web.Response:
        """自然语言 → 填表意图。只读查询 + 字段草稿；不保存。"""
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json"}, 400)
        domain = str(body.get("domain") or "").strip()
        text = str(body.get("text") or "").strip()
        ctx = body.get("context") or {}
        if domain not in ("checks", "permissions"):
            return _json({"ok": False, "error": "bad_domain"}, 400)

        assets = [r["id"] for r in self.db.query("SELECT id FROM assets ORDER BY id")]
        caps: list[str] = []
        try:
            from .capabilities import list_capabilities

            caps = [c["name"] for c in list_capabilities()]
        except Exception:
            caps = []
        names: list[str] = []
        if domain == "checks":
            try:
                names = [c["name"] for c in self._checks().list_checks("")]
            except Exception:
                names = []

        from . import assist

        res = await assist.configure(
            domain=domain,
            text=text,
            context=ctx,
            llm=self.llm,
            assets=assets,
            capabilities=caps,
            existing_names=names,
        )
        try:
            self.db.audit(
                "web_user",
                sess.get("username") or "",
                "assist_configure",
                detail={"domain": domain, "source": res.get("source"), "route": res.get("route")},
            )
        except Exception:
            pass
        return _json(res)

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
        """进程活着。不因外部依赖不可用而 503。"""
        return _json(
            {
                "ok": True,
                "service": "ayana",
                "version": self.version,
                "uptime_ok": True,
            }
        )

    async def ready(self, request: web.Request) -> web.Response:
        """是否具备可信处理工作的条件。

        - DB / schema 必须可用，否则 503
        - 外部依赖（Prom/AM/NT/LLM）降级展示，不拖死全局
        - worker 最近成功时间 / backlog 可见
        """
        checks: dict[str, Any] = {}
        reasons: list[str] = []

        # DB
        try:
            self.db.query_one("SELECT 1 AS x")
            checks["db"] = "available"
        except Exception as e:
            checks["db"] = f"unavailable:{e}"
            reasons.append("db")

        # schema
        try:
            ver = self.db.schema_version()
            from .db import SCHEMA_VERSION

            checks["schema"] = "current" if ver == SCHEMA_VERSION else f"mismatch:{ver}"
            if ver != SCHEMA_VERSION:
                reasons.append("schema")
        except Exception as e:
            checks["schema"] = f"error:{e}"
            reasons.append("schema")

        # durable work backlog
        try:
            n = self.db.query_one(
                "SELECT COUNT(*) AS n FROM work_items WHERE state='pending'"
            )
            checks["work_backlog"] = int(n["n"] if n else 0)
        except Exception:
            checks["work_backlog"] = -1

        # outbox backlog
        try:
            n = self.db.query_one(
                "SELECT COUNT(*) AS n FROM notification_outbox"
                " WHERE state IN ('pending','retry')"
            )
            checks["outbox_backlog"] = int(n["n"] if n else 0)
        except Exception:
            checks["outbox_backlog"] = -1

        # worker 心跳（main 后台任务写入 meta）
        for key, label in (
            ("worker_outbox_last_ok", "outbox"),
            ("worker_reconcile_last_ok", "reconcile"),
            ("worker_agent_last_ok", "agent"),
        ):
            try:
                row = self.db.query_one("SELECT value FROM meta WHERE key=?", (key,))
                last = float(row["value"]) if row and row["value"] else 0.0
                age = time.time() - last if last else -1
                checks[f"{label}_age_sec"] = round(age, 1) if age >= 0 else None
                checks[label] = "ok" if 0 <= age < 300 else ("stale" if last else "unknown")
                if last and age > 600:
                    checks[label] = "dead"
                    reasons.append(label)
            except Exception:
                checks[label] = "unknown"

        # 外部依赖：degraded 不阻塞 ready
        try:
            from .db import SCHEMA_VERSION as _sv

            checks["prometheus"] = getattr(self.prom, "last_status", "unknown")
            checks["alertmanager"] = getattr(self.alert_ingest, "last_status", "unknown")
        except Exception:
            pass

        ok = not reasons
        return _json(
            {
                "ok": ok,
                "version": self.version,
                "checks": checks,
                "reasons": reasons,
                "note": "外部依赖降级不影响 ready；DB/schema 不可用则 not ready",
            },
            200 if ok else 503,
        )

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

    async def api_login_step(self, request: web.Request) -> web.Response:
        """两阶段登录第一步：密码。未 2FA 直接建会话；2FA 返回 need_totp。"""
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json"}, 400)
        ip = request.remote or ""
        try:
            res = self.auth.begin_login(
                body.get("username", ""), body.get("password", ""), ip=ip
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 401)
        if res.get("complete"):
            sess = res["session"]
            resp = _json({"ok": True, "complete": True, "csrf_token": sess["csrf_token"]})
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
        return _json(
            {
                "ok": True,
                "complete": False,
                "need_totp": True,
                "pending_id": res.get("pending_id", ""),
                "username": res.get("username", ""),
            }
        )

    async def api_login_totp(self, request: web.Request) -> web.Response:
        """两阶段登录第二步：TOTP / 恢复码。通过后才建完整会话。"""
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json"}, 400)
        ip = request.remote or ""
        try:
            sess = self.auth.complete_login(
                body.get("pending_id", ""),
                totp_code=body.get("totp", "") or body.get("code", ""),
                recovery_code=body.get("recovery_code", ""),
                ip=ip,
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 401)
        resp = _json({"ok": True, "complete": True, "csrf_token": sess["csrf_token"]})
        resp.set_cookie(
            SESSION_COOKIE,
            sess["session_id"],
            httponly=True,
            samesite="Lax",
            max_age=self.auth.session_ttl,
            path="/",
        )
        self.db.audit("web_user", "", "login_ok", detail={"ip": ip, "stage": "totp"})
        return resp

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

        # 短缓存：避免前端连点/轮询把 Prom 探测打满（Windows 连接拒绝约 2s/次）
        now_ts = time.time()
        cache = getattr(self, "_overview_cache", None)
        if cache and (now_ts - cache["at"]) < 5.0:
            return _json(cache["data"])

        assets_raw = self.db.query("SELECT * FROM assets ORDER BY id")
        open_inc = self.incidents.list_incidents(status="open", limit=50)
        open_by_asset = {}
        for i in open_inc:
            aid = i.get("asset_id") or ""
            open_by_asset[aid] = open_by_asset.get(aid, 0) + 1

        async def _fetch_metric(asset_id: str, metric: str):
            try:
                if metric == "hysteria_proxy_up":
                    hy = await self.prom.query("hysteria_proxy_up")
                    return metric, hy.get("result") or []
                if metric == "probe_success":
                    return metric, await self.prom.probe_success_since(
                        asset_id, "", start=now() - 300
                    )
            except Exception:
                return metric, []
            return metric, []

        # 先并行收集各资产需要的指标，再组装
        tasks = []
        for a in assets_raw:
            req = REQUIRED_CHECKS.get(a["id"], [])
            metrics = {c.get("metric") for c in req if c.get("metric")}
            for metric in metrics:
                tasks.append(_fetch_metric(a["id"], metric))
        results = await asyncio.gather(*tasks) if tasks else []
        # (asset_id, metric) 顺序与 tasks 构建顺序一致
        idx = 0
        metric_map: dict[str, dict[str, list]] = {}
        for a in assets_raw:
            req = REQUIRED_CHECKS.get(a["id"], [])
            metrics = {c.get("metric") for c in req if c.get("metric")}
            metric_map[a["id"]] = {}
            for metric in metrics:
                _m, samples = results[idx]
                metric_map[a["id"]][metric] = samples
                idx += 1

        assets = []
        for a in assets_raw:
            d = dict(a)
            d["objects"] = [
                dict(o)
                for o in self.db.query("SELECT * FROM objects WHERE asset_id=?", (a["id"],))
            ]
            health = asset_health(
                asset_id=a["id"],
                objects=d["objects"],
                samples_by_metric=metric_map.get(a["id"], {}),
                open_incidents=open_by_asset.get(a["id"], 0),
            )
            # 小圆点结论：与资源页同一套 host_health（不吸收历史未结案）
            from .health import host_health as _hh
            d["health"] = health
            d["health_dot"] = _hh(
                required_state=health.get("state", "unknown"),
            )
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
            sources["prometheus_error"] = str(e)[:200]

        # 系统健康度：唯一分数 + MAGI 分项拆解（真实数据）
        from .health import system_health_ratio

        metric_items: list[dict] = []
        for a in assets_raw:
            for c in REQUIRED_CHECKS.get(a["id"], []):
                samples = (metric_map.get(a["id"]) or {}).get(c.get("metric") or "", [])
                # 按 selector 过滤
                sel = c.get("selector") or {}
                matched = []
                for s in samples:
                    m = s.get("metric") or {}
                    if all(m.get(k) == v for k, v in sel.items()):
                        matched.append(s)
                latest = max(matched, key=lambda x: x.get("sample_at") or 0) if matched else None
                fres = float(c.get("freshness_sec") or 120)
                if latest is None:
                    st = "unknown"
                else:
                    age = time.time() - float(latest.get("sample_at") or 0)
                    val = latest.get("value")
                    if age > fres:
                        st = "stale"
                    elif val is None:
                        st = "unknown"
                    elif val == 1:
                        st = "healthy"
                    else:
                        st = "unhealthy"
                metric_items.append({"state": st, "object": c.get("object"), "asset": a["id"]})

        check_items: list[dict] = []
        try:
            for row in self.db.query("SELECT last_state FROM checks WHERE enabled=1"):
                check_items.append({"state": row["last_state"] or "unknown"})
        except Exception:
            pass

        # 告警状态：单项状态（当前有 firing → 0/1；无 → 1/1）
        # 不把每条历史未结案事件算进来；只反映「此刻告警面是否干净」
        alert_items: list[dict] = []
        try:
            n_firing = 0
            for _row in self.db.query(
                "SELECT COUNT(*) AS n FROM alert_episodes WHERE status='firing'"
                " AND (source_state IS NULL OR source_state='firing')"
            ):
                n_firing = int(_row["n"] or 0)
            alert_items.append({"state": "unhealthy" if n_firing else "healthy"})
        except Exception:
            pass

        health_ratio = system_health_ratio(
            metric_items=metric_items,
            check_items=check_items,
            alert_items=alert_items,
        )
        quiet = not need and not open_inc and not pending_actions and not unknown_actions
        data = {
            "ok": True,
            "version": self.version,
            "assets": assets,
            "open_incidents": open_inc,
            "need_human": need,
            "recent_actions": actions,
            "pending_actions": len(pending_actions),
            "unknown_actions": len(unknown_actions),
            "sources": sources,
            "health_ratio": health_ratio,
            "quiet": quiet,
        }
        self._overview_cache = {"at": time.time(), "data": data}
        return _json(data)

    def _visible_asset_ids(self, sess: dict) -> set[str]:
        """S10: 返回调用者有 asset.summary 权限的资产 ID 集合。admin 见全部。"""
        if not sess:
            return set()
        username = sess.get("username") or ""
        if username == "admin":
            return {r["id"] for r in self.db.query("SELECT id FROM assets")}
        rows = self.db.query("SELECT id FROM assets")
        out = set()
        for r in rows:
            decision = self.policy.check(
                subject_type="web_user",
                subject_id=username,
                capability="asset.summary",
                asset_id=r["id"],
                object_id="*",
            )
            if decision.get("allowed"):
                out.add(r["id"])
        return out

    def _asset_monitor_host(self, asset: dict, endpoints: list[dict] | None = None) -> str:
        """Resolve the monitoring host from current asset/connection configuration."""
        for key in ("monitor_host", "host"):
            host = str(asset.get(key) or "").strip()
            if host:
                return host
        store = self.ssh_store or self._ssh_store()
        if endpoints is None:
            endpoints = store.list_endpoints(asset["id"]) if store else []
        preference = {"write": 0, "read": 1}
        candidates = []
        for ep in endpoints:
            if not ep.get("enabled") or not str(ep.get("host") or "").strip():
                continue
            priority = preference.get(ep.get("role"))
            if priority is None and store:
                try:
                    priority = {"write": 2, "read": 3}.get(store.role_kind(ep.get("role")))
                except Exception:
                    continue
            if priority is not None:
                candidates.append((priority, ep))
        candidates.sort(key=lambda item: item[0])
        return str(candidates[0][1]["host"]).strip() if candidates else ""

    async def api_assets(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        visible = self._visible_asset_ids(sess)
        rows = self.db.query("SELECT * FROM assets ORDER BY id")
        out = []
        for r in rows:
            # S10: 只返回调用者有权看到的资产
            if r["id"] not in visible:
                continue
            d = dict(r)
            d["objects"] = [
                dict(o)
                for o in self.db.query("SELECT * FROM objects WHERE asset_id=?", (r["id"],))
            ]
            # 附带 SSH 端点（主机连接信息）
            eps = []
            store = self.ssh_store or self._ssh_store()
            if store:
                try:
                    eps = store.list_endpoints(r["id"])
                except Exception:
                    eps = []
            d["ssh_endpoints"] = eps
            # 自动主地址：assets.host 优先，否则 SSH 端点 host
            host = self._asset_monitor_host(d, eps)
            d["host"] = host
            d["monitor_host"] = host
            out.append(d)
        return _json({"ok": True, "assets": out})

    def _asset_payload(self, body: dict) -> dict:
        aid = str(body.get("id") or "").strip()
        if not aid or not aid.replace("_", "").replace("-", "").isalnum() or len(aid) > 32:
            raise ValueError("bad_asset_id")
        host = str(body.get("host") or "").strip()
        port = int(body.get("port") or 22)
        user = str(body.get("username") or "").strip() or "root"
        if not host:
            raise ValueError("host_required")
        return {
            "id": aid.lower(),
            "display_name": str(body.get("display_name") or aid).strip(),
            "host": host,
            "port": port,
            "username": user,
            "role": str(body.get("role") or "write").strip(),
            "credential_id": body.get("credential_id") or "",
            "prom_asset": str(body.get("prom_asset") or aid).strip(),
            "notes": str(body.get("notes") or "").strip(),
        }

    async def api_asset_create(self, request: web.Request) -> web.Response:
        """添加主机：创建资产 + 可选 SSH 端点（一表完成）。"""
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            p = self._asset_payload(body)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        existing = self.db.query_one("SELECT id FROM assets WHERE id=?", (p["id"],))
        if existing:
            return _json({"ok": False, "error": "asset_exists"}, 409)
        t = now()
        # NT 别名约定：asset / asset-exec（兼容旧通道）
        read_alias = p["id"]
        write_alias = f"{p['id']}-exec"
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
                " prom_asset, host, enabled, notes, created_at, updated_at)"
                " VALUES(?,?,?,?,? ,?,?,1,?,?,?)",
                (
                    p["id"], p["display_name"], read_alias, write_alias, "",
                    p["prom_asset"], p["host"], p["notes"], t, t,
                ),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, detail_json, channel)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    t, "web_user", sess["username"], "asset_created", p["id"],
                    __import__("json").dumps(
                        {"host": p["host"], "port": p["port"], "username": p["username"]},
                        ensure_ascii=False,
                    ),
                    "web",
                ),
            )
        ssh_ep = None
        cred_id = p.get("credential_id") or ""
        # 添加主机时可直接输入密码 / 私钥 → 自动建凭据
        secret = str(body.get("password") or body.get("private_key") or "").strip()
        if secret and not cred_id:
            try:
                kind = "private_key" if "BEGIN" in secret else "password"
                meta = self._cred_store().create(
                    name=f"{p['id']}-{p.get('role') or 'write'}",
                    kind=kind,
                    secret=secret,
                    actor=sess["username"],
                )
                cred_id = meta["id"]
            except Exception as e:
                return _json({"ok": False, "error": f"credential: {e}"}, 400)
        if self.ssh_store and p.get("host"):
            try:
                ssh_ep = self.ssh_store.upsert_endpoint(
                    asset_id=p["id"],
                    role=p["role"] or "write",
                    host=p["host"],
                    port=p["port"],
                    username=p["username"],
                    credential_id=cred_id,
                    actor=sess["username"],
                )
            except Exception as e:
                return _json({"ok": True, "asset_id": p["id"], "ssh_error": str(e)})
        return _json({"ok": True, "asset_id": p["id"], "ssh_endpoint": ssh_ep, "credential_id": cred_id})

    async def api_asset_update(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        aid = request.match_info["asset_id"]
        body = await request.json()
        row = self.db.query_one("SELECT * FROM assets WHERE id=?", (aid,))
        if not row:
            return _json({"ok": False, "error": "not_found"}, 404)
        t = now()
        display = str(body.get("display_name") or row["display_name"]).strip()
        notes = str(body.get("notes") or row["notes"]).strip()
        enabled = row["enabled"]
        if "enabled" in body:
            enabled = 1 if body.get("enabled") else 0
        self.db.execute(
            "UPDATE assets SET display_name=?, notes=?, enabled=?, updated_at=? WHERE id=?",
            (display, notes, enabled, t, aid),
        )
        ssh_ep = None
        role = str(body.get("role") or "write")
        # 凭据策略：空=保留原凭据；clear_credential=显式清空；新密文=rotate 或 create
        clear_cred = bool(body.get("clear_credential"))
        secret = str(body.get("password") or body.get("private_key") or "").strip()
        existing_ep = None
        if self.ssh_store:
            try:
                existing_ep = self.ssh_store.get_endpoint(aid, role) or (
                    self.ssh_store.list_endpoints(aid) or [None]
                )[0]
            except Exception:
                existing_ep = None
        cred_id = body.get("credential_id")
        if cred_id is None:
            cred_id = (existing_ep or {}).get("credential_id") or ""
        cred_id = str(cred_id or "").strip()
        if clear_cred:
            cred_id = ""
        elif secret and self.cred_store:
            try:
                kind = "private_key" if "BEGIN" in secret else "password"
                # 同端点已有凭据 → rotate，避免孤儿
                if cred_id:
                    meta = self._cred_store().rotate(
                        cred_id, secret=secret, actor=sess["username"]
                    )
                else:
                    meta = self._cred_store().create(
                        name=f"{aid}-{role}",
                        kind=kind,
                        secret=secret,
                        actor=sess["username"],
                    )
                    cred_id = meta["id"]
            except Exception as e:
                return _json({"ok": False, "error": f"credential: {e}"}, 400)
        if self.ssh_store and body.get("host"):
            try:
                ssh_ep = self.ssh_store.upsert_endpoint(
                    asset_id=aid,
                    role=role,
                    host=str(body["host"]).strip(),
                    port=int(body.get("port") or 22),
                    username=str(body.get("username") or "root").strip(),
                    credential_id=cred_id,
                    actor=sess["username"],
                )
            except Exception as e:
                return _json({"ok": False, "error": f"ssh: {e}"}, 400)
        self.db.audit(
            "web_user", sess["username"], "asset_updated",
            asset_id=aid,
            detail={
                "display_name": display,
                "enabled": enabled,
                "credential_cleared": clear_cred,
                "credential_rotated": bool(secret and not clear_cred),
            },
            channel="web",
        )
        return _json({"ok": True, "asset_id": aid, "ssh_endpoint": ssh_ep, "credential_id": cred_id})

    async def api_asset_delete(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        aid = request.match_info["asset_id"]
        row = self.db.query_one("SELECT * FROM assets WHERE id=?", (aid,))
        if not row:
            return _json({"ok": False, "error": "not_found"}, 404)
        # 有未完结操作时拒绝删除
        busy = self.db.query_one(
            "SELECT COUNT(*) AS n FROM actions WHERE asset_id=?"
            " AND state IN ('proposed','approved','dispatched','unknown')",
            (aid,),
        )
        if busy and busy["n"] > 0:
            return _json({"ok": False, "error": "asset_busy", "open_actions": int(busy["n"])}, 409)
        with self.db.tx() as conn:
            conn.execute("DELETE FROM ssh_endpoints WHERE asset_id=?", (aid,))
            conn.execute("DELETE FROM objects WHERE asset_id=?", (aid,))
            conn.execute("DELETE FROM assets WHERE id=?", (aid,))
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, detail_json, channel)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    now(), "web_user", sess["username"], "asset_deleted", aid,
                    __import__("json").dumps({"display_name": row["display_name"]}, ensure_ascii=False),
                    "web",
                ),
            )
        return _json({"ok": True})

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
        sess = self._require_auth(request)
        status = request.rel_url.query.get("status", "")
        visible = self._visible_asset_ids(sess)
        all_incs = self.incidents.list_incidents(status=status)
        # S10: 只返回调用者有权资产关联的事件
        filtered = [i for i in all_incs if i.get("asset_id") in visible] if visible else []
        return _json({"ok": True, "incidents": filtered})

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
        sess = self._require_auth(request)
        q = request.rel_url.query
        manual_only = q.get("manual", "") in ("1", "true", "yes")
        visible = self._visible_asset_ids(sess)
        all_actions = self.actions.list_actions(manual_only=manual_only)
        # S10: 只返回调用者有权资产关联的操作
        filtered = [a for a in all_actions if a.get("asset_id") in visible] if visible else []
        return _json({
            "ok": True,
            "actions": filtered,
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

    def _sensitive_totp(self, sess: dict, body: dict) -> dict[str, Any] | None:
        """敏感操作二次确认：已启用 TOTP 的用户必须提供有效验证码。

        验证码不落日志、不进事件正文。未启用 TOTP 的用户不强制（与登录一致）。
        """
        username = sess["username"]
        code = str(body.get("totp") or body.get("totp_code") or "").strip()
        if not self.auth.totp_enabled(username):
            return None
        if not code:
            self.db.audit(
                "web_user", username, "sensitive_totp_required", detail={"missing": True}
            )
            return {"ok": False, "error": "totp_required"}
        if not self.auth.verify_totp(username, code):
            self.db.audit("web_user", username, "sensitive_totp_failed")
            return {"ok": False, "error": "totp_invalid"}
        self.db.audit("web_user", username, "sensitive_totp_ok")
        return None

    async def api_action_approve(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        mfa_err = self._sensitive_totp(sess, body)
        if mfa_err:
            return _json(mfa_err, 401)
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
        body = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        mfa_err = self._sensitive_totp(sess, body)
        if mfa_err:
            return _json(mfa_err, 401)
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

    async def api_permissions_model(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        return _json({"ok": True, **self.policy.model_view()})

    async def api_permissions_effective(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        q = request.rel_url.query
        try:
            data = self.policy.effective_for(
                capability=q.get("capability", ""),
                asset_id=q.get("asset_id", ""),
                object_id=q.get("object_id", ""),
                subject_type=q.get("subject_type", "auto_rule"),
                subject_id=q.get("subject_id", "agent"),
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "effective": data})

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

    async def api_permission_preview(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        body = await request.json()
        try:
            data = self.policy.preview(
                subject_type=body["subject_type"],
                subject_id=body["subject_id"],
                capability=body["capability"],
                asset_id=body.get("asset_id") or "",
                object_id=body.get("object_id") or "",
                auto=bool(body.get("auto", False)),
            )
        except (PolicyDeny, KeyError) as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "preview": data})

    async def api_permission_history(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        limit = min(200, int(request.rel_url.query.get("limit", "50")))
        return _json({
            "ok": True,
            "history": self.policy.list_config_history(limit=limit),
        })

    async def api_permission_delete(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            self.policy.delete_permission(int(body["id"]), actor=sess["username"])
        except (PolicyDeny, KeyError, ValueError) as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True})

    # ---- Agent ceiling（用户可配上限，后端强制 ⊆ 源码能力目录）----

    async def api_agent_ceiling_list(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        return _json({"ok": True, "agent_ceiling": self.policy.agent_ceiling.list()})

    async def api_agent_ceiling_set(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            eff = self.policy.agent_ceiling.set(
                body["capability"],
                allowed=bool(body.get("allowed", True)),
                allow_auto=bool(body.get("allow_auto", False)),
                actor=sess["username"],
            )
        except Exception as e:
            # 含 ObjectBindingError：能力不在源码目录 → 400，不得发明
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "agent_ceiling": eff})

    # ---- Permission Change（0.4：TOTP 只签一笔）----

    def _pcsvc(self):
        if not self.permission_changes:
            return None
        return self.permission_changes

    async def api_permission_changes(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        svc = self._pcsvc()
        if not svc:
            return _json({"ok": False, "error": "unavailable"}, 503)
        state = request.rel_url.query.get("state", "")
        return _json({"ok": True, "changes": svc.list_changes(state=state)})

    async def api_permission_change_propose(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        svc = self._pcsvc()
        if not svc:
            return _json({"ok": False, "error": "unavailable"}, 503)
        body = await request.json()
        try:
            res = svc.propose(
                subject_type=body.get("subject_type") or "auto_rule",
                subject_id=body.get("subject_id") or "",
                capability=body.get("capability") or "",
                asset_id=body.get("asset_id") or "*",
                object_id=body.get("object_id") or "*",
                to_allow=bool(body.get("to_allow", True)),
                to_require_approval=bool(body.get("to_require_approval", True)),
                to_auto_allowed=bool(body.get("to_auto_allowed", False)),
                reason=body.get("reason", ""),
                incident_id=body.get("incident_id", ""),
                created_by=sess["username"],
                created_channel="web",
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_permission_change_present(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        svc = self._pcsvc()
        if not svc:
            return _json({"ok": False, "error": "unavailable"}, 503)
        try:
            return _json({"ok": True, "change": svc.present(request.match_info["cid"])})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 404)

    async def api_permission_change_authorize(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        svc = self._pcsvc()
        if not svc:
            return _json({"ok": False, "error": "unavailable"}, 503)
        body = await request.json()
        try:
            res = svc.authorize(
                request.match_info["cid"],
                actor_id=sess["username"],
                totp_code=body.get("totp") or body.get("totp_code") or "",
                channel="web",
                is_admin=bool(sess.get("is_admin")),
            )
        except Exception as e:
            code = getattr(e, "code", "error")
            return _json({"ok": False, "error": code, "message": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_permission_change_reject(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        svc = self._pcsvc()
        if not svc:
            return _json({"ok": False, "error": "unavailable"}, 503)
        body = await request.json()
        try:
            res = svc.reject(
                request.match_info["cid"],
                actor_id=sess["username"],
                reason=body.get("reason", ""),
                channel="web",
                is_admin=bool(sess.get("is_admin")),
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_knowledge(self, request: web.Request) -> web.Response:
        """运维知识库只读：Markdown 主题（front matter + 正文）。"""
        self._require_auth(request)
        # 与 Agent/Investigation 共用同一 KnowledgeBase，保证 revision 一致
        kb = getattr(self.investigation, "knowledge", None)
        if kb is None:
            from .knowledge import KnowledgeBase

            kb = KnowledgeBase(self.db)
        q = request.rel_url.query
        doc_id = q.get("id", "")
        if doc_id:
            doc = kb.get(doc_id)
            if not doc:
                return _json({"ok": False, "error": "not_found"}, 404)
            return _json({"ok": True, "knowledge": doc.to_public(), "revision": kb.revision})
        items = kb.list_docs(
            status=q.get("status", ""),
            typ=q.get("type", ""),
            q=q.get("q", ""),
        )
        return _json({
            "ok": True,
            "knowledge": [d.to_public() for d in items],
            "revision": kb.revision,
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

    # ---- 多消息渠道 ----

    def _channels(self):
        if not self.channel_store:
            raise web.HTTPNotFound(text="channel_store not configured")
        return self.channel_store

    async def api_notify_channels(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        try:
            channels = self._channels().list_meta()
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 500)
        return _json({"ok": True, "channels": channels})

    async def api_notify_kinds(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        from .notify_channels import list_channel_kinds

        return _json({"ok": True, "kinds": list_channel_kinds()})

    async def api_notify_platforms(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        from .notify_channels import list_platforms

        return _json({"ok": True, "platforms": list_platforms()})

    async def api_notify_aibot_status(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        if not self.aibot_manager:
            return _json({"ok": True, "status": {}})
        return _json({"ok": True, "status": self.aibot_manager.status_all()})

    async def api_notify_aibot_targets(self, request: web.Request) -> web.Response:
        """已发现的推送目标（群 chatid / 单聊 userid）。"""
        self._require_admin(request)
        cid = request.rel_url.query.get("channel_id", "")
        if not cid:
            return _json({"ok": False, "error": "missing_channel_id"}, 400)
        if not self.channel_store:
            return _json({"ok": True, "targets": []})
        meta = self.channel_store.get_meta(cid) or {}
        cfg = meta.get("config") or {}
        return _json(
            {
                "ok": True,
                "targets": self.channel_store.list_seen_targets(cid),
                "selected": list(cfg.get("targets") or []),
            }
        )

    async def api_notify_aibot_targets_save(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        cid = str(body.get("id") or "")
        if not cid:
            return _json({"ok": False, "error": "missing_id"}, 400)
        targets = body.get("targets") or []
        if not isinstance(targets, list):
            return _json({"ok": False, "error": "bad_targets"}, 400)
        try:
            ch = self._channels().set_targets(
                cid, [str(t) for t in targets], actor=sess["username"]
            )
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", str(e))}, 400)
        return _json({"ok": True, "channel": ch})

    # ---- 消息记录 ----

    async def api_messages(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        if not self.mlog:
            return _json({"ok": True, "total": 0, "items": [], "limit": 50, "offset": 0})
        q = request.rel_url.query

        def _f(name: str) -> str:
            return str(q.get(name) or "").strip()

        def _t(name: str):
            v = q.get(name)
            if v is None or str(v).strip() == "":
                return None
            try:
                return float(v)
            except Exception:
                return None

        try:
            limit = int(q.get("limit") or 50)
            offset = int(q.get("offset") or 0)
        except Exception:
            limit, offset = 50, 0
        res = self.mlog.list_messages(
            platform=_f("platform"),
            channel_kind=_f("channel_kind"),
            channel_id=_f("channel_id"),
            direction=_f("direction"),
            state=_f("state"),
            q=_f("q"),
            start=_t("start"),
            end=_t("end"),
            limit=limit,
            offset=offset,
        )
        return _json({"ok": True, **res})

    async def api_message_detail(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        if not self.mlog:
            raise web.HTTPNotFound(text="mlog not configured")
        mid = request.match_info["mid"]
        item = self.mlog.get(mid)
        if not item:
            return _json({"ok": False, "error": "not_found"}, 404)
        related = []
        if item.get("reply_log_id"):
            r = self.mlog.get(item["reply_log_id"])
            if r:
                related.append(r)
        if item.get("direction") == "in":
            rows = self.db.query(
                "SELECT id FROM message_log WHERE reply_to=? ORDER BY at ASC LIMIT 5",
                (item["id"],),
            )
            for r in rows:
                if r["id"] != item.get("reply_log_id"):
                    rr = self.mlog.get(r["id"])
                    if rr:
                        related.append(rr)
        return _json({"ok": True, "message": item, "related": related})

    async def api_notify_channel_create(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            ch = self._channels().create(
                name=body.get("name") or "",
                kind=body.get("kind") or "",
                config=body.get("config") or {},
                secret=body.get("secret") or {},
                enabled=bool(body.get("enabled", True)),
                actor=sess["username"],
            )
        except Exception as e:
            code = getattr(e, "code", "error")
            return _json({"ok": False, "error": code, "detail": str(e)}, 400)
        return _json({"ok": True, "channel": ch})

    async def api_notify_channel_update(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        cid = str(body.get("id") or "")
        if not cid:
            return _json({"ok": False, "error": "missing_id"}, 400)
        try:
            ch = self._channels().update(
                cid,
                name=body.get("name"),
                config=body.get("config"),
                secret=body.get("secret"),
                clear_secret=bool(body.get("clear_secret")),
                enabled=body.get("enabled") if "enabled" in body else None,
                actor=sess["username"],
            )
        except Exception as e:
            code = getattr(e, "code", "error")
            return _json({"ok": False, "error": code, "detail": str(e)}, 400)
        return _json({"ok": True, "channel": ch})

    async def api_notify_channel_delete(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        cid = str(body.get("id") or "")
        if not cid:
            return _json({"ok": False, "error": "missing_id"}, 400)
        try:
            self._channels().delete(cid, actor=sess["username"])
            # S06: 删除渠道立即停止客户端
            if self.aibot_manager:
                try:
                    await self.aibot_manager.stop(cid)
                except Exception:
                    pass
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True})

    async def api_notify_channel_enabled(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        cid = str(body.get("id") or "")
        if not cid:
            return _json({"ok": False, "error": "missing_id"}, 400)
        try:
            ch = self._channels().set_enabled(
                cid, bool(body.get("enabled")), actor=sess["username"]
            )
            # S06: 停用渠道立即停止客户端，不等下轮扫描
            if not body.get("enabled") and self.aibot_manager:
                try:
                    await self.aibot_manager.stop(cid)
                except Exception:
                    pass
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "channel": ch})

    async def api_notify_channel_test(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        cid = str(body.get("id") or "")
        if not cid:
            return _json({"ok": False, "error": "missing_id"}, 400)
        try:
            res = await self._channels().test(cid, actor=sess["username"])
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "result": res})

    async def api_notify_outbox(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        state = request.rel_url.query.get("state", "")
        limit = min(200, int(request.rel_url.query.get("limit", "50") or 50))
        rows = (
            self.notifier.outbox_summary(limit=limit, state=state)
            if self.notifier
            else []
        )
        failed = self.notifier.failed_summary() if self.notifier else []
        return _json({"ok": True, "outbox": rows, "failed": failed})

    # ---- 主机资源监控 ----

    def _monitor(self):
        if not self.host_monitor:
            raise web.HTTPNotFound(text="host_monitor not configured")
        return self.host_monitor

    async def api_monitor_hosts(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        from .health import REQUIRED_CHECKS, host_health, object_health

        rows = self.db.query(
            "SELECT id, display_name, prom_asset, enabled FROM assets ORDER BY id ASC"
        )
        assets = [dict(r) for r in rows]
        try:
            status = await self._monitor().hosts_status(assets)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

        # 统一健康：指标 + required checks + 业务检查 + 当前 firing（不吸收历史未结案）
        by_id = {s.get("asset_id"): s for s in status}
        try:
            firing = self.db.query(
                "SELECT asset_id, labels_json FROM alert_episodes"
                " WHERE status='firing' AND (source_state IS NULL OR source_state='firing')"
                " LIMIT 200"
            )
        except Exception:
            firing = []
        firing_by_asset: dict[str, list[str]] = {}
        for ep in firing or []:
            aid = str(ep["asset_id"] or "")
            try:
                labels = json.loads(ep["labels_json"] or "{}")
            except Exception:
                labels = {}
            sev = str(labels.get("severity") or "warning").lower()
            firing_by_asset.setdefault(aid, []).append(sev)

        out = []
        for a in assets:
            aid = a["id"]
            item = dict(by_id.get(aid) or {
                "asset_id": aid,
                "display_name": a.get("display_name") or aid,
                "prom_asset": a.get("prom_asset") or aid,
                "state": "no_data",
                "error": "",
                "summary": {},
            })
            metric_state = item.get("state") or ""
            metric_error = item.get("error") or ""

            # required checks（无样本 → unknown → no_data）
            req = REQUIRED_CHECKS.get(aid, [])
            req_states: list[str] = []
            if req:
                for c in req:
                    try:
                        samples = await self.prom.probe_success_since(
                            aid, c.get("object") or "", start=now() - 300
                        ) if c.get("metric") == "probe_success" else []
                    except Exception:
                        samples = []
                    h = object_health(
                        asset_id=aid,
                        object_name=c.get("object") or "",
                        samples=samples,
                        required=[c],
                    )
                    req_states.append(h.get("state") or "unknown")
                if "unhealthy" in req_states:
                    required_state = "unhealthy"
                elif "stale" in req_states:
                    required_state = "stale"
                elif "unknown" in req_states:
                    required_state = "unknown"
                elif all(s == "healthy" for s in req_states):
                    required_state = "healthy"
                else:
                    required_state = "degraded"
            else:
                required_state = ""

            # 业务检查
            check_states: list[str] = []
            try:
                for c in self.db.query(
                    "SELECT last_state FROM checks WHERE asset_id=? AND enabled=1", (aid,)
                ):
                    check_states.append(c["last_state"] or "no_data")
            except Exception:
                pass

            hh = host_health(
                metric_state=metric_state,
                metric_error=metric_error,
                required_state=required_state,
                check_states=check_states,
                firing_severities=firing_by_asset.get(aid, []),
                collect_error=metric_error if metric_state == "collect_error" else "",
            )
            item["health"] = hh
            item["state"] = hh["state"]  # 对外五态
            item["firing"] = firing_by_asset.get(aid, [])
            out.append(item)
        return _json({"ok": True, "hosts": out})

    async def api_monitor_host(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        asset_id = request.match_info["asset_id"]
        range_key = request.rel_url.query.get("range", "1h")
        decision = self.policy.check(
            subject_type="web_user",
            subject_id=sess["username"],
            capability="asset.summary",
            asset_id=asset_id,
            object_id="*",
        )
        if not decision["allowed"]:
            return _json({"ok": False, "error": "denied"}, 403)
        row = self.db.query_one(
            "SELECT id, display_name, prom_asset FROM assets WHERE id=?", (asset_id,)
        )
        if not row:
            return _json({"ok": False, "error": "not_found"}, 404)
        prom_asset = row["prom_asset"] or asset_id
        try:
            overview = await self._monitor().host_overview(prom_asset)
            history = await self._monitor().host_history(prom_asset, range_key)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)
        return _json(
            {
                "ok": True,
                "asset": dict(row),
                "overview": overview,
                "history": history,
            }
        )

    # ---- SSH 资产 / 凭据（v0.4.1）----

    def _ssh_store(self):
        if not self.ssh_store:
            raise web.HTTPNotFound(text="ssh_store not configured")
        return self.ssh_store

    def _cred_store(self):
        if not self.cred_store:
            raise web.HTTPNotFound(text="cred_store not configured")
        return self.cred_store

    async def api_ssh_roles(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        return _json({"ok": True, "roles": self._ssh_store().list_roles()})

    async def api_ssh_role_add(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            role = self._ssh_store().add_role(
                name=body["name"],
                kind=body.get("kind") or "read",
                label=body.get("label") or "",
                actor=sess["username"],
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "role": role})

    async def api_ssh_endpoints(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        asset_id = request.rel_url.query.get("asset_id", "")
        return _json({"ok": True, "endpoints": self._ssh_store().list_endpoints(asset_id)})

    async def api_ssh_endpoint_upsert(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            ep = self._ssh_store().upsert_endpoint(
                asset_id=body["asset_id"],
                role=body.get("role") or "read",
                host=body["host"],
                port=int(body.get("port") or 22),
                username=body["username"],
                credential_id=body.get("credential_id") or "",
                actor=sess["username"],
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "endpoint": ep})

    async def api_ssh_hostkey_fetch(self, request: web.Request) -> web.Response:
        """自动获取主机指纹（ssh-keyscan），供「信任并连接」弹窗展示。"""
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            from .transport import fetch_host_key
            res = await fetch_host_key(
                str(body.get("host") or "").strip(),
                int(body.get("port") or 22),
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)[:200]}, 400)
        return _json(res)

    async def api_ssh_trust_host_key(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            ep = self._ssh_store().trust_host_key(
                body["asset_id"],
                body.get("role") or "read",
                body["host_key_sha256"],
                actor=sess["username"],
                key_line=body.get("host_key_line") or "",
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "endpoint": ep})

    async def api_ssh_endpoint_delete(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            self._ssh_store().delete_endpoint(
                body["asset_id"], body.get("role") or "read", actor=sess["username"]
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True})

    async def api_ssh_credentials(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        # 只返回元数据，永不返回明文
        return _json({"ok": True, "credentials": self._cred_store().list_meta()})

    async def api_ssh_credential_create(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            meta = self._cred_store().create(
                name=body.get("name") or "",
                kind=body["kind"],
                secret=body["secret"],
                public_key=body.get("public_key") or "",
                actor=sess["username"],
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "credential": meta})

    async def api_ssh_credential_delete(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            self._cred_store().delete(body["id"], actor=sess["username"])
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True})

    async def api_ssh_credential_generate(self, request: web.Request) -> web.Response:
        from .credentials import generate_and_store_keypair

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            meta = generate_and_store_keypair(
                self._cred_store(), name=body.get("name") or "ayana", actor=sess["username"]
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "credential": meta})

    async def api_ssh_credential_rotate(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            meta = self._cred_store().rotate(
                body["id"],
                secret=body["secret"],
                public_key=body.get("public_key") or "",
                actor=sess["username"],
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "credential": meta})

    async def api_ssh_deploy_pubkey(self, request: web.Request) -> web.Response:
        from .credentials import deploy_public_key

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            res = await deploy_public_key(
                host=body["host"],
                port=int(body.get("port") or 22),
                username=body["username"],
                public_key=body["public_key"],
                credential_id=body["credential_id"],
                store=self._cred_store(),
            )
            self.db.audit(
                "web_user",
                sess["username"],
                "ssh_pubkey_deployed",
                detail={"ok": res.get("ok"), "host": body.get("host")},
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, **res})

    async def api_asset_channel_test(self, request: web.Request) -> web.Response:
        """测当前实际使用的通道：SSH 或 NT，并明确通/不通与原因。"""
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        asset_id = request.match_info["asset_id"]
        body = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        role = str(body.get("role") or "write")
        want_write = role not in ("read",)

        eps = []
        if self.ssh_store:
            try:
                eps = [e for e in self.ssh_store.list_endpoints(asset_id) if e.get("enabled")]
            except Exception:
                eps = []
        ssh_ep = None
        for e in eps:
            if want_write and e.get("role") not in ("read",):
                ssh_ep = e
                break
            if not want_write:
                ssh_ep = e
                break
        if not ssh_ep and eps:
            ssh_ep = eps[0]

        has_credential = bool(ssh_ep and ssh_ep.get("credential_id"))
        auth_method = "none"
        if ssh_ep and ssh_ep.get("credential_id") and self.cred_store:
            try:
                cm = self.cred_store.get_meta(ssh_ep["credential_id"])
                auth_method = "key" if (cm or {}).get("kind") == "private_key" else "password"
            except Exception:
                auth_method = "unknown"
        result: dict[str, Any] = {
            "asset_id": asset_id,
            "channel": "none",
            "ok": False,
            "ssh_configured": bool(ssh_ep),
            "has_credential": has_credential,
            "auth_method": auth_method,
            "host_key_trusted": bool(ssh_ep and ssh_ep.get("host_key_trusted_at") and ssh_ep.get("host_key_sha256")),
            "detail": "",
            "hint": "",
        }

        # 1) 有 SSH 端点 → 测 SSH
        if ssh_ep:
            result["channel"] = "ssh"
            if not has_credential:
                result["detail"] = "endpoint_without_credential"
                result["hint"] = "已配置 SSH 地址，但未配置密码或密钥。请配置密码登录后再改用密钥。"
                self.db.audit("web_user", sess["username"], "channel_test", asset_id=asset_id,
                              detail=result, channel="web")
                return _json(result)

            # 自动取当前主机指纹，供信任/变更判断与弹窗
            from .transport import fetch_host_key
            scanned = await fetch_host_key(ssh_ep.get("host") or "", int(ssh_ep.get("port") or 22))
            result["host_key_scan"] = {
                k: scanned.get(k) for k in ("ok", "fingerprint", "key_type", "key_line", "error")
            } if scanned else {}
            stored_fp = ssh_ep.get("host_key_sha256") or ""
            stored_line = ssh_ep.get("host_key_line") or ""

            if stored_fp and scanned.get("ok") and scanned.get("fingerprint") and scanned["fingerprint"] != stored_fp:
                result["detail"] = "host_key_changed"
                result["ok"] = False
                result["hint"] = (
                    "主机密钥已变更！为安全起见已阻止连接，不会自动覆盖。"
                    "请确认服务器是否重装/换机；确认无误后可在界面上重新信任新指纹。"
                )
                result["host_key_info"] = {
                    "host": ssh_ep.get("host"),
                    "port": ssh_ep.get("port"),
                    "stored_fingerprint": stored_fp,
                    "current_fingerprint": scanned.get("fingerprint"),
                    "changed": True,
                }
                self.db.audit("web_user", sess["username"], "channel_test", asset_id=asset_id,
                              detail=result, channel="web")
                return _json(result)

            if not result["host_key_trusted"]:
                result["detail"] = "host_key_untrusted"
                result["ok"] = False
                if scanned.get("ok"):
                    result["hint"] = "首次连接该主机，需要你确认主机指纹后才能继续。"
                    result["host_key_info"] = {
                        "host": ssh_ep.get("host"),
                        "port": ssh_ep.get("port"),
                        "fingerprint": scanned.get("fingerprint"),
                        "key_type": scanned.get("key_type"),
                        "key_line": scanned.get("key_line"),
                        "changed": False,
                    }
                else:
                    result["hint"] = f"无法获取主机指纹：{scanned.get('error') or 'keyscan_failed'}。请检查地址/端口是否可达。"
                self.db.audit("web_user", sess["username"], "channel_test", asset_id=asset_id,
                              detail=result, channel="web")
                return _json(result)

            # 有信任且指纹未变 → 真连接：执行 hostname / whoami / uname -s
            try:
                from .terminal import run_cmd_probe

                cm = self.cred_store.get_meta(ssh_ep.get("credential_id") or "") if self.cred_store else None
                cred_kind = (cm or {}).get("kind") or "password"
                secret = self.cred_store.reveal_secret(ssh_ep["credential_id"]) if (self.cred_store and ssh_ep.get("credential_id")) else ""
                probe = await run_cmd_probe(
                    host=ssh_ep.get("host") or "",
                    port=int(ssh_ep.get("port") or 22),
                    username=ssh_ep.get("username") or "",
                    cred_kind=cred_kind,
                    secret=secret,
                    host_key_line=ssh_ep.get("host_key_line") or "",
                    cmds=["hostname", "whoami", "uname -s"],
                )
                secret = ""
                result["ok"] = bool(probe.get("ok"))
                result["probe_cmds"] = probe.get("results") or []
                if probe.get("ok"):
                    outs = {r["cmd"]: r.get("stdout") for r in probe.get("results") or []}
                    result["detail"] = "ssh_ok"
                    result["hint"] = (
                        f"连接正常：{outs.get('hostname') or ''} · "
                        f"{outs.get('whoami') or ''} · {outs.get('uname -s') or ''}"
                    )
                else:
                    result["detail"] = "ssh_failed"
                    result["hint"] = f"SSH 连接或命令失败：{probe.get('error') or ''}"
                    result["raw_error"] = probe.get("error") or ""
                    for r in probe.get("results") or []:
                        if not r.get("ok"):
                            result["hint"] = f"命令失败：{r.get('cmd')} → {r.get('stderr') or r.get('stdout') or r.get('returncode')}"
                            break
            except Exception as e:
                result["detail"] = "ssh_error"
                result["hint"] = f"SSH 测试异常：{e}"
            self.db.audit("web_user", sess["username"], "channel_test", asset_id=asset_id,
                          detail=result, channel="web")
            return _json(result)

        # 2) 无 SSH 端点 → 提示配置 SSH
        result["channel"] = "none"
        result["ok"] = False
        result["detail"] = "ssh_not_configured"
        result["hint"] = (
            "未配置 SSH（需要地址 + 密码或密钥）。"
            "需配置 SSH 后才能远程连接与执行。"
        )
        self.db.audit("web_user", sess["username"], "channel_test", asset_id=asset_id,
                      detail=result, channel="web")
        return _json(result)

    async def api_ssh_switch_to_key(self, request: web.Request) -> web.Response:
        """密码登录 → 生成密钥 → 部署公钥 → 切换密钥认证 →（可选）删除密码。"""
        from .credentials import deploy_public_key, generate_and_store_keypair

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        asset_id = str(body.get("asset_id") or "").strip()
        role = str(body.get("role") or "write")
        delete_password = bool(body.get("delete_password", True))
        # 明确「信任并更换」：未信任也可一步完成；未勾选则仍拒绝（安全边界）
        trust_and_rotate = bool(body.get("trust_host_key", False))
        if not asset_id:
            return _json({"ok": False, "error": "asset_id_required"}, 400)

        steps: list[str] = []
        try:
            eps = self._ssh_store().list_endpoints(asset_id)
        except Exception as e:
            return _json({"ok": False, "error": f"endpoints: {e}"}, 400)
        ep = next((e for e in eps if e.get("role") == role and e.get("enabled")), None)
        if not ep and eps:
            ep = next((e for e in eps if e.get("enabled")), None)
        if not ep:
            return _json({
                "ok": False,
                "error": "no_ssh_endpoint",
                "hint": "请先「配置 SSH 连接」填地址和密码，再切换密钥。",
            }, 400)

        cred_id = ep.get("credential_id") or ""
        if not cred_id:
            return _json({
                "ok": False,
                "error": "no_credential",
                "hint": "当前主机没有绑定密码/密钥。请先配置密码登录。",
            }, 400)
        meta = self.cred_store.get_meta(cred_id)
        kind = (meta or {}).get("kind") or ""
        if kind == "private_key":
            return _json({
                "ok": True,
                "already_key": True,
                "credential_id": cred_id,
                "hint": "已经在用密钥认证，无需切换。",
            })

        # host key：未信任且用户未点「信任并更换」→ 拒绝
        trusted = bool(ep.get("host_key_trusted_at") and ep.get("host_key_sha256"))
        if not trusted:
            if not trust_and_rotate:
                from .transport import fetch_host_key

                scanned = await fetch_host_key(ep.get("host") or "", int(ep.get("port") or 22))
                return _json({
                    "ok": False,
                    "error": "host_key_untrusted",
                    "host_key_info": {
                        "fingerprint": scanned.get("fingerprint") or "",
                        "key_line": scanned.get("key_line") or "",
                        "host": ep.get("host"),
                        "port": ep.get("port"),
                    },
                    "hint": "安全边界：须先信任主机指纹才能更换密钥。请点「信任并更换密钥」。",
                })
            # 一步信任
            from .transport import fetch_host_key

            scanned = await fetch_host_key(ep.get("host") or "", int(ep.get("port") or 22))
            if not scanned.get("ok"):
                return _json({
                    "ok": False,
                    "error": "host_key_scan_failed",
                    "hint": "无法获取主机指纹，已拒绝更换密钥。",
                })
            self.ssh_store.trust_host_key(
                asset_id,
                role,
                scanned.get("fingerprint") or "",
                actor=sess["username"],
                key_line=scanned.get("key_line") or "",
            )
            ep = self._ssh_store().get_endpoint(asset_id, role) or ep
            steps.append("host_key_trusted")
            trusted = True

        steps.append(f"use_password_credential:{cred_id[:10]}")

        # 1) 生成密钥对并入库
        try:
            key_meta = generate_and_store_keypair(
                self.cred_store,
                name=f"{asset_id}-key",
                actor=sess["username"],
            )
        except Exception as e:
            return _json({"ok": False, "error": f"keygen: {e}", "steps": steps}, 500)
        steps.append(f"generated_key:{key_meta['id'][:10]}")

        # 2) 用现有密码把公钥装到目标机
        try:
            dep = await deploy_public_key(
                host=ep["host"],
                port=int(ep.get("port") or 22),
                username=ep["username"],
                public_key=key_meta.get("public_key") or "",
                credential_id=cred_id,
                store=self.cred_store,
                host_key_line=(ep.get("host_key_line") or "") if "host_key_line" in ep.keys() else "",
            )
        except Exception as e:
            return _json({
                "ok": False,
                "error": f"deploy_pubkey: {e}",
                "steps": steps,
                "hint": "部署公钥失败，请确认密码正确且用户可写 ~/.ssh/authorized_keys。",
            }, 500)
        steps.append(f"deployed_pubkey:ok={dep.get('ok')}")
        if not dep.get("ok"):
            return _json({
                "ok": False,
                "error": "deploy_pubkey_failed",
                "deploy": dep,
                "steps": steps,
                "hint": "公钥未装上，仍保留密码认证。错误见 deploy.output。",
            }, 400)

        # 3) 先用新密钥验证，通过后才切换端点（避免半路改掉认证）
        verify = {"ok": False}
        try:
            from .transport import SSHTransport
            # 临时把密钥绑到端点上做验证，失败则回滚 credential_id
            old_cred = ep.get("credential_id") or ""
            self.ssh_store.upsert_endpoint(
                asset_id=ep["asset_id"],
                role=ep["role"],
                host=ep["host"],
                port=int(ep.get("port") or 22),
                username=ep["username"],
                credential_id=key_meta["id"],
                actor=sess["username"],
            )
            try:
                tr = SSHTransport(self._ssh_store(), self._cred_store())
                verify = await tr.test_connection(ep["asset_id"], "write")
            except Exception as e:
                verify = {"ok": False, "error": str(e)[:300]}
            if not verify.get("ok"):
                # 回滚：仍用原密码凭据
                self.ssh_store.upsert_endpoint(
                    asset_id=ep["asset_id"],
                    role=ep["role"],
                    host=ep["host"],
                    port=int(ep.get("port") or 22),
                    username=ep["username"],
                    credential_id=old_cred,
                    actor=sess["username"],
                )
                steps.append(f"key_verify:ok=False;rolled_back_to_password")
                return _json({
                    "ok": False,
                    "error": "key_verify_failed",
                    "verify": verify,
                    "steps": steps,
                    "rolled_back": True,
                    "hint": (
                        "密钥验证未通过，已回退为密码认证，未改动登录方式。"
                        "请检查服务器 authorized_keys 或重试。"
                    ),
                })
            steps.append("key_verify:ok=True")
            steps.append("switched_to_key_confirmed")
        except Exception as e:
            verify = {"ok": False, "error": str(e)[:300]}
            steps.append(f"key_verify_error:{str(e)[:120]}")
            return _json({
                "ok": False,
                "error": "key_verify_error",
                "verify": verify,
                "steps": steps,
                "rolled_back": True,
                "hint": f"密钥验证异常，已保持密码认证：{e}",
            })

        # 4) 验证通过后再问是否删密码（取消则保留密码，但登录已用密钥）
        deleted = False
        if delete_password:
            try:
                self._cred_store().delete(cred_id, actor=sess["username"])
                deleted = True
                steps.append(f"deleted_password:{cred_id[:10]}")
            except Exception as e:
                steps.append(f"delete_password_failed:{e}")
        else:
            steps.append("password_kept")

        self.db.audit(
            "web_user", sess["username"], "ssh_switch_to_key",
            asset_id=asset_id,
            detail={
                "ok": bool(verify.get("ok")),
                "deleted_password": deleted,
                "key_credential_id": key_meta["id"],
                "steps": steps,
            },
            channel="web",
        )
        return _json({
            "ok": True,
            "already_key": False,
            "credential_id": key_meta["id"],
            "public_key": key_meta.get("public_key") or "",
            "verify": verify,
            "deleted_password": deleted,
            "auth_method": "key",
            "steps": steps,
            "hint": (
                "已切换为密钥登录，密码已删除。" if deleted
                else "已切换为密钥登录（密码仍保留，可稍后在凭据库删除）。"
            ),
        })

    # ---- 人工 Web 终端（Agent 不可达）----

    def _terminal_ok(self, sess: dict, asset_id: str = "") -> dict | None:
        """需登录 + shell.interactive（按目标资产核权）。S02/S03: 不再用通配资产授权。"""
        if not sess:
            return {"ok": False, "error": "unauthorized"}
        username = sess.get("username") or ""
        # 仅 admin 可开人工终端（S02: 取消 web_user:* 通配恢复）
        if username != "admin":
            return {"ok": False, "error": "permission_denied", "hint": "需要管理员权限"}
        # 若指定资产，核对对该资产的 shell.interactive；未指定时仅允许已有全局 admin 规则
        check_asset = asset_id or "*"
        decision = self.policy.check(
            subject_type="web_user",
            subject_id=username,
            capability="shell.interactive",
            asset_id=check_asset,
            object_id="*",
        )
        if not decision.get("allowed"):
            return {"ok": False, "error": "permission_denied", "hint": "需要 shell.interactive 权限"}
        return None

    async def api_terminal_check(self, request: web.Request) -> web.Response:
        """打开终端前检查：权限、SSH 配置、host key。不建会话。"""
        sess = self._session(request)
        asset_id = request.rel_url.query.get("asset_id", "")
        err = self._terminal_ok(sess, asset_id)
        if err:
            return _json(err, 403)
        if not asset_id:
            return _json({"ok": False, "error": "asset_id_required"}, 400)
        if not self.terminal:
            return _json({"ok": False, "error": "terminal_unavailable"}, 503)

        eps = self.ssh_store.list_endpoints(asset_id) if self.ssh_store else []
        ep = next((e for e in eps if e.get("enabled")), None)
        if not ep:
            return _json({
                "ok": False,
                "can_open": False,
                "detail": "no_ssh_endpoint",
                "hint": "未配置 SSH，请先在连接页配置地址与密码/密钥。",
            })
        if not ep.get("credential_id"):
            return _json({
                "ok": False,
                "can_open": False,
                "detail": "no_credential",
                "hint": "未配置密码或密钥，无法打开终端。",
            })

        from .transport import fetch_host_key

        scanned = await fetch_host_key(ep.get("host") or "", int(ep.get("port") or 22))
        stored_fp = ep.get("host_key_sha256") or ""
        trusted = bool(stored_fp and ep.get("host_key_trusted_at"))
        auth_method = "none"
        try:
            cm = self.cred_store.get_meta(ep["credential_id"]) if self.cred_store else None
            auth_method = "key" if (cm or {}).get("kind") == "private_key" else "password"
        except Exception:
            pass

        base = {
            "asset_id": asset_id,
            "host": ep.get("host"),
            "port": ep.get("port"),
            "remote_user": ep.get("username"),
            "auth_method": auth_method,
            "host_key_trusted": trusted,
        }
        if trusted and scanned.get("ok") and scanned.get("fingerprint") != stored_fp:
            return _json({
                **base,
                "ok": False,
                "can_open": False,
                "detail": "host_key_changed",
                "hint": "主机密钥已变更，已阻止连接。请确认服务器身份后重新信任。",
                "host_key_info": {
                    "host": ep.get("host"),
                    "port": ep.get("port"),
                    "stored_fingerprint": stored_fp,
                    "current_fingerprint": scanned.get("fingerprint"),
                    "changed": True,
                },
            })
        if not trusted:
            info = {
                "host": ep.get("host"),
                "port": ep.get("port"),
                "fingerprint": scanned.get("fingerprint") if scanned.get("ok") else "",
                "key_type": scanned.get("key_type") if scanned.get("ok") else "",
                "key_line": scanned.get("key_line") if scanned.get("ok") else "",
                "changed": False,
            }
            return _json({
                **base,
                "ok": False,
                "can_open": False,
                "detail": "host_key_untrusted",
                "hint": "首次连接，需要确认主机指纹后才能打开终端。",
                "host_key_info": info,
            })
        return _json({
            **base,
            "ok": True,
            "can_open": True,
            "detail": "ready",
            "hint": "可以打开终端。",
            "sessions": self.terminal.stats() if self.terminal else {},
        })

    async def ws_terminal(self, request: web.Request) -> web.WebSocketResponse:
        """WebSocket 交互终端。仅人工 Web 会话；Agent 无此入口。"""
        # S03: Upgrade 前校验 Origin；非法来源直接 HTTP 拒绝，不升级
        origin = request.headers.get("Origin", "")
        host_hdr = request.headers.get("Host", "")
        if origin and host_hdr:
            allowed = {f"http://{host_hdr}", f"https://{host_hdr}"}
            if origin.rstrip("/") not in allowed:
                return web.Response(status=403, text="origin rejected")
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        sess = self._session(request)
        asset_id = request.rel_url.query.get("asset_id", "")
        err = self._terminal_ok(sess, asset_id)
        if err:
            await ws.send_json({"type": "error", "error": err.get("error"), "hint": err.get("hint")})
            await ws.close(code=4403, message=b"forbidden")
            return ws
        if not self.terminal:
            await ws.send_json({"type": "error", "error": "terminal_unavailable"})
            await ws.close(code=1011)
            return ws

        asset_id = request.rel_url.query.get("asset_id", "")
        cols = int(request.rel_url.query.get("cols") or 80)
        rows = int(request.rel_url.query.get("rows") or 24)
        username = sess["username"]

        tsess = None
        try:
            tsess, info = await self.terminal.create(
                asset_id=asset_id,
                role=request.rel_url.query.get("role") or "write",
                username=username,
                cols=cols,
                rows=rows,
            )
            await ws.send_json({"type": "ready", **info})
        except Exception as e:
            code = getattr(e, "code", "error")
            detail = getattr(e, "detail", "") or str(e)
            hint = "连接失败"
            host_key_info = None
            if code == "host_key_untrusted":
                hint = "首次连接，需要确认主机指纹"
                try:
                    host_key_info = json.loads(detail) if detail.startswith("{") else None
                except Exception:
                    host_key_info = None
            elif code == "host_key_changed":
                hint = "主机密钥已变更，已阻止连接"
                try:
                    host_key_info = json.loads(detail) if detail.startswith("{") else None
                except Exception:
                    host_key_info = None
            elif code == "no_credential":
                hint = "未配置密码或密钥"
            elif code == "no_ssh_endpoint":
                hint = "未配置 SSH 连接"
            elif code == "too_many_sessions":
                hint = "终端会话过多，请关闭其他终端后重试"
            await ws.send_json({
                "type": "error",
                "error": code,
                "hint": hint,
                "detail": detail[:300] if code not in ("host_key_untrusted", "host_key_changed") else "",
                "host_key_info": host_key_info,
            })
            await ws.close(code=1011)
            return ws

        sid = tsess.session_id

        async def pump_out():
            loop = asyncio.get_event_loop()
            while not ws.closed and tsess.alive():
                data = await loop.run_in_executor(None, tsess.read)
                if data:
                    try:
                        await ws.send_bytes(data)
                    except Exception:
                        break
                else:
                    await asyncio.sleep(0.05)
            # S03: 超时/SSH 断开时强制关闭 WebSocket，不只发 closed 消息
            if not ws.closed:
                reason = tsess.close_reason or ("timeout" if not tsess.alive() else "ssh_closed")
                try:
                    await ws.send_json({"type": "closed", "reason": reason})
                except Exception:
                    pass
                try:
                    await ws.close(code=1000, message=b"session ended")
                except Exception:
                    pass

        out_task = asyncio.create_task(pump_out())
        try:
            async for msg in ws:
                # S03: 输入期间复查会话有效性（注销/改密/撤权后拒绝）
                cur = self._session(request)
                if not cur or cur.get("username") != username:
                    await ws.send_json({"type": "error", "error": "session_revoked", "hint": "登录已失效"})
                    break
                if msg.type == web.WSMsgType.BINARY:
                    try:
                        tsess.write(msg.data)
                    except Exception as e:
                        await ws.send_json({"type": "error", "error": "write_failed", "hint": str(e)[:120]})
                        break
                elif msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except Exception:
                        continue
                    typ = data.get("type")
                    if typ == "resize":
                        tsess.resize(int(data.get("cols") or 80), int(data.get("rows") or 24))
                    elif typ == "close":
                        break
                elif msg.type in (web.WSMsgType.ERROR, web.WSMsgType.CLOSE):
                    break
        finally:
            out_task.cancel()
            self.terminal.close(sid, username=username, reason="user_or_disconnect")
        return ws

    async def api_ssh_test(self, request: web.Request) -> web.Response:
        from .transport import SSHTransport

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            tr = SSHTransport(self._ssh_store(), self._cred_store())
            res = await tr.test_connection(body["asset_id"], body.get("role") or "read")
            self.db.audit(
                "web_user",
                sess["username"],
                "ssh_test",
                asset_id=body.get("asset_id") or "",
                detail={"ok": res.get("ok"), "role": body.get("role") or "read"},
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, **res})

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

    # ---- 业务检查（轻量）----

    def _checks(self):
        if not self.checks:
            raise web.HTTPNotFound(text=json.dumps({"error": "checks_not_configured"}))
        return self.checks

    def _check_read(self, request: web.Request) -> dict[str, Any]:
        sess = self._require_auth(request)
        d = self.policy.effective_decision(
            subject_type="web_user",
            subject_id=sess["username"],
            capability="checks.read",
            asset_id="*",
            object_id="*",
        )
        # admin 拥有管理台读权限；其余用户需显式 checks.read
        if not d["allowed"] and not sess.get("is_admin"):
            raise web.HTTPForbidden(
                text=json.dumps({"ok": False, "error": "denied", "detail": "checks.read not granted"}),
                content_type="application/json",
            )
        return sess

    def _check_write(self, request: web.Request) -> dict[str, Any]:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        if not sess.get("is_admin"):
            raise web.HTTPForbidden(text=json.dumps({"error": "admin_required"}))
        d = self.policy.effective_decision(
            subject_type="web_user",
            subject_id=sess["username"],
            capability="checks.write",
            asset_id="*",
            object_id="*",
        )
        if not d["allowed"]:
            raise web.HTTPForbidden(text=json.dumps({"error": "denied"}))
        if d.get("require_approval"):
            raise web.HTTPForbidden(text=json.dumps({"error": "approval_required"}))
        return sess

    async def api_checks_list(self, request: web.Request) -> web.Response:
        self._check_read(request)
        asset_id = request.rel_url.query.get("asset_id", "")
        try:
            return _json({"ok": True, "checks": self._checks().list_checks(asset_id)})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_checks_create(self, request: web.Request) -> web.Response:
        sess = self._check_write(request)
        body = await request.json()
        try:
            item = self._checks().create_check(
                asset_id=body.get("asset_id") or "",
                kind=body.get("kind") or "",
                name=body.get("name") or "",
                params=body.get("params") or {},
                expect=body.get("expect") or {},
                interval_sec=body.get("interval_sec") or 60,
                fail_threshold=body.get("fail_threshold") or 2,
                severity=body.get("severity") or "warning",
                actor=sess["username"],
            )
            return _json({"ok": True, "check": item})
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_checks_update(self, request: web.Request) -> web.Response:
        sess = self._check_write(request)
        body = await request.json()
        try:
            fields = {k: body[k] for k in ("name", "params", "expect", "interval_sec", "fail_threshold", "severity", "enabled") if k in body}
            item = self._checks().update_check(body.get("id") or "", actor=sess["username"], **fields)
            return _json({"ok": True, "check": item})
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_checks_delete(self, request: web.Request) -> web.Response:
        sess = self._check_write(request)
        body = await request.json()
        try:
            self._checks().delete_check(body.get("id") or "", actor=sess["username"])
            return _json({"ok": True})
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_checks_run(self, request: web.Request) -> web.Response:
        sess = self._check_write(request)
        body = await request.json()
        cid = body.get("id") or ""
        try:
            item = self._checks().get_check(cid)
            if not item:
                return _json({"ok": False, "error": "not_found"}, 404)
            if not self.transport:
                return _json({"ok": False, "error": "transport_required"}, 400)
            item["was_failing"] = (item.get("fail_streak") or 0) > 0
            res = await self._checks().run_one(item)
            return _json({"ok": True, "result": res})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_checks_activity(self, request: web.Request) -> web.Response:
        self._check_read(request)
        try:
            return _json({"ok": True, "activity": self._checks().activity(50)})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    # ---- Prometheus 配置管理（v0.6.x）----

    def _promconfig(self):
        if not self.promconfig:
            raise web.HTTPNotFound(text=json.dumps({"error": "promconfig_not_configured"}))
        return self.promconfig

    def _require_asset(self, asset_id: str) -> dict[str, Any]:
        """资产必须存在且启用；禁止任意字符串进入执行链。"""
        asset_id = (asset_id or "").strip()
        if not asset_id:
            raise web.HTTPBadRequest(text=json.dumps({"error": "asset_id_required"}))
        row = self.db.query_one(
            "SELECT id, display_name, prom_asset, enabled FROM assets WHERE id=?", (asset_id,)
        )
        if not row:
            raise web.HTTPNotFound(text=json.dumps({"error": "asset_not_found"}))
        if not row["enabled"]:
            raise web.HTTPForbidden(text=json.dumps({"error": "asset_disabled"}))
        return dict(row)

    def _policy_for(self, sess: dict, capability: str, asset_id: str = "*", object_id: str = "*") -> dict[str, Any]:
        return self.policy.effective_decision(
            subject_type="web_user",
            subject_id=sess["username"],
            capability=capability,
            asset_id=asset_id,
            object_id=object_id,
        )

    def _check_prom_write(self, request: web.Request, *, asset_id: str = "*") -> dict[str, Any]:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        if not sess.get("is_admin"):
            raise web.HTTPForbidden(text=json.dumps({"error": "admin_required"}))
        decision = self._policy_for(sess, "promconfig.write", asset_id=asset_id)
        if not decision["allowed"]:
            raise web.HTTPForbidden(text=json.dumps({"error": "denied", "reason": decision.get("reason")}))
        if decision.get("require_approval"):
            raise web.HTTPForbidden(
                text=json.dumps({"error": "approval_required", "require_approval": True})
            )
        return sess

    def _check_prom_read(self, request: web.Request) -> dict[str, Any]:
        sess = self._require_auth(request)
        decision = self._policy_for(sess, "promconfig.read")
        if not decision["allowed"]:
            # 尊重显式 deny，不因 admin 绕过
            raise web.HTTPForbidden(text=json.dumps({"error": "denied", "reason": decision.get("reason")}))
        return sess

    async def api_promconfig_overview(self, request: web.Request) -> web.Response:
        self._check_prom_read(request)
        try:
            data = await self._promconfig().overview()
            return _json({"ok": True, **data})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_promconfig_config(self, request: web.Request) -> web.Response:
        self._check_prom_read(request)
        try:
            data = await self._promconfig().read_config()
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_promconfig_targets(self, request: web.Request) -> web.Response:
        self._check_prom_read(request)
        try:
            data = await self._promconfig().list_targets()
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_promconfig_target_add(self, request: web.Request) -> web.Response:
        sess = self._check_prom_write(request)
        body = await request.json()
        try:
            data = await self._promconfig().add_target(
                address=body.get("address") or "",
                labels=body.get("labels") or {},
                actor=sess["username"],
            )
            return _json(data)
        except Exception as e:
            from .promconfig import PromConfigError

            code = getattr(e, "code", "error")
            return _json({"ok": False, "error": code, "detail": str(e)}, 400)

    async def api_promconfig_target_update(self, request: web.Request) -> web.Response:
        sess = self._check_prom_write(request)
        body = await request.json()
        try:
            data = await self._promconfig().update_target(
                address=body.get("address") or "",
                new_address=body.get("new_address") or None,
                labels=body.get("labels"),
                actor=sess["username"],
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_promconfig_target_delete(self, request: web.Request) -> web.Response:
        sess = self._check_prom_write(request)
        body = await request.json()
        try:
            data = await self._promconfig().delete_target(
                address=body.get("address") or "", actor=sess["username"]
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_promconfig_rules(self, request: web.Request) -> web.Response:
        self._check_prom_read(request)
        try:
            data = await self._promconfig().read_rules()
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_promconfig_rule_templates(self, request: web.Request) -> web.Response:
        self._check_prom_read(request)
        try:
            return _json({"ok": True, "templates": await self._promconfig().list_templates()})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_promconfig_rule_apply_template(self, request: web.Request) -> web.Response:
        sess = self._check_prom_write(request)
        body = await request.json()
        try:
            data = await self._promconfig().apply_template(
                template_id=body.get("template_id") or "",
                enabled=bool(body.get("enabled", True)),
                threshold=body.get("threshold"),
                duration=body.get("duration"),
                severity=body.get("severity"),
                actor=sess["username"],
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_promconfig_rule_update(self, request: web.Request) -> web.Response:
        sess = self._check_prom_write(request)
        body = await request.json()
        try:
            data = await self._promconfig().update_rule(
                file_path=body.get("file_path") or "",
                alert=body.get("alert") or "",
                expr=body.get("expr"),
                duration=body.get("duration"),
                severity=body.get("severity"),
                enabled=body.get("enabled"),
                actor=sess["username"],
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_promconfig_node_status(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        asset_id = request.rel_url.query.get("asset_id", "")
        try:
            asset = self._require_asset(asset_id)
        except web.HTTPException as e:
            return e
        decision = self._policy_for(sess, "node_exporter.status", asset_id=asset["id"])
        if not decision["allowed"]:
            return _json({"ok": False, "error": "denied"}, 403)
        try:
            data = await self._promconfig().node_exporter_status(asset["id"], self._ne_transport(asset["id"]))
            return _json({"ok": True, "status": data})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    def _ssh_store(self):
        store = getattr(self.transport, "store", None)
        if store is None:
            store = getattr(self.transport, "_store", None)
        return store

    def _ne_transport(self, asset_id: str):
        """Node Exporter 通道：有 SSH 端点用 SSH；仅本机资产才允许 LocalExec。SSH 失败不得回退。"""
        from .promconfig import LocalExecTransport

        local_assets = set(
            str(x).strip()
            for x in (
                (self.promconfig.cfg_local_assets() if self.promconfig else []) or []
            )
            if str(x).strip()
        )
        # 也允许 config 显式登记的本机资产
        ssh = self.transport
        store = self._ssh_store() if ssh is not None else None
        ep = None
        if store is not None:
            try:
                ep = store.get_endpoint(asset_id, "read") or store.get_endpoint(asset_id, "write")
            except Exception:
                ep = None
        if ep:
            return ssh
        if asset_id in local_assets:
            return LocalExecTransport()
        raise web.HTTPForbidden(
            text=json.dumps({"error": "asset_channel_unavailable", "asset_id": asset_id})
        )

    def _json_bool(self, body: dict, key: str, default: bool = False) -> bool:
        v = body.get(key, default)
        if isinstance(v, bool):
            return v
        raise web.HTTPBadRequest(text=json.dumps({"error": "bad_boolean", "field": key}))

    async def api_promconfig_node_control(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        asset_id = body.get("asset_id") or ""
        action = body.get("action") or ""
        if not asset_id or action not in ("install", "start", "stop", "check"):
            return _json({"ok": False, "error": "bad_request"}, 400)
        try:
            asset = self._require_asset(asset_id)
        except web.HTTPException as e:
            return e
        decision = self._policy_for(sess, "node_exporter.manage", asset_id=asset["id"])
        if not decision["allowed"]:
            return _json({"ok": False, "error": "denied"}, 403)
        if decision.get("require_approval") and action in ("install", "start", "stop"):
            return _json({"ok": False, "error": "approval_required", "require_approval": True}, 403)
        try:
            allow_np = self._json_bool(body, "allow_non_private", False)
        except web.HTTPException as e:
            return e
        try:
            data = await self._promconfig().node_exporter_control(
                asset_id=asset["id"],
                action=action,
                transport=self._ne_transport(asset["id"]),
                actor=sess["username"],
                listen_address=body.get("listen_address") or "127.0.0.1:9100",
                allow_non_private=allow_np,
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_promconfig_node_adopt(self, request: web.Request) -> web.Response:
        """一键接入：检查 → 装/启 node_exporter → 注册目标。"""
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        asset_id = body.get("asset_id") or ""
        try:
            asset = self._require_asset(asset_id)
        except web.HTTPException as e:
            return e
        decision = self._policy_for(sess, "node_exporter.manage", asset_id=asset["id"])
        if not decision["allowed"]:
            return _json({"ok": False, "error": "denied"}, 403)
        if decision.get("require_approval"):
            return _json({"ok": False, "error": "approval_required"}, 403)
        # 写权限：注册目标
        d2 = self._policy_for(sess, "promconfig.write", asset_id=asset["id"])
        if not d2["allowed"] or d2.get("require_approval"):
            return _json({"ok": False, "error": "denied"}, 403)
        address = (body.get("address") or "").strip()
        if not address:
            host = self._asset_monitor_host(asset)
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            address = f"{host}:9100" if host else ""
        if not address:
            return _json({"ok": False, "error": "address_required", "hint": "未配置监控地址，请填写主机地址或添加启用的 SSH 连接。"}, 400)
        try:
            allow_np = self._json_bool(body, "allow_non_private", False)
        except web.HTTPException as e:
            return e
        try:
            data = await self._promconfig().adopt_node(
                asset_id=asset["id"],
                address=address,
                transport=self._ne_transport(asset["id"]),
                actor=sess["username"],
                listen_address=body.get("listen_address") or "127.0.0.1:9100",
                allow_non_private=allow_np,
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_promconfig_node_detect(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        asset_id = body.get("asset_id") or ""
        try:
            asset = self._require_asset(asset_id)
        except web.HTTPException as e:
            return e
        d = self._policy_for(sess, "node_exporter.status", asset_id=asset["id"])
        if not d["allowed"] and not sess.get("is_admin"):
            return _json({"ok": False, "error": "denied"}, 403)
        try:
            data = await self._promconfig().detect_exporter(asset["id"], self._ne_transport(asset["id"]))
            return _json({"ok": True, **data})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_promconfig_node_install(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        asset_id = body.get("asset_id") or ""
        method = body.get("method") or "auto"
        try:
            asset = self._require_asset(asset_id)
        except web.HTTPException as e:
            return e
        d = self._policy_for(sess, "node_exporter.manage", asset_id=asset["id"])
        if not d["allowed"] or d.get("require_approval"):
            return _json({"ok": False, "error": "denied"}, 403)
        try:
            allow_np = self._json_bool(body, "allow_non_private", True)
        except web.HTTPException as e:
            return e
        try:
            data = await self._promconfig().install_exporter(
                asset_id=asset["id"],
                method=method,
                transport=self._ne_transport(asset["id"]),
                actor=sess["username"],
                listen_address=body.get("listen_address") or "0.0.0.0:9100",
                allow_non_private=allow_np,
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_promconfig_node_register(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        body = await request.json()
        asset_id = body.get("asset_id") or ""
        try:
            asset = self._require_asset(asset_id)
        except web.HTTPException as e:
            return e
        sess_w = self._check_prom_write(request, asset_id=asset["id"])
        try:
            data = await self._promconfig().register_node_target(
                asset_id=asset["id"],
                address=body.get("address") or "",
                labels=body.get("labels") or {},
                actor=sess_w["username"],
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

    async def api_promconfig_validate(self, request: web.Request) -> web.Response:
        sess = self._check_prom_write(request)
        try:
            data = await self._promconfig().validate_and_reload(actor=sess["username"])
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_promconfig_rollback(self, request: web.Request) -> web.Response:
        sess = self._check_prom_write(request)
        body = await request.json()
        try:
            data = await self._promconfig().rollback_last(
                path=body.get("path") or "", actor=sess["username"]
            )
            return _json(data)
        except Exception as e:
            return _json({"ok": False, "error": getattr(e, "code", "error"), "detail": str(e)}, 400)

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
