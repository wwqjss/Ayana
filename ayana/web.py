"""Web 控制台：本地认证（密码+TOTP）、资产/事件/操作/权限/审计。"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aiohttp import web

from .actions import ActionError, ActionService
from .approval import ApprovalService
from .auth import AuthError, AuthService
from .db import Database, now
from .incidents import IncidentService
from .investigation import InvestigationService
from .policy import Policy, PolicyDeny
from .prom import PromClient, summarize_probe
from .agent_authority import resolve_authority

log = logging.getLogger("ayana.web")

SESSION_COOKIE = "ayana_session"


def _host_port(value: str, *, default_port: str = "") -> tuple[str, str]:
    """解析 Host / Origin 的 hostname 与 port（默认端口与 scheme 对齐）。"""
    raw = (value or "").strip()
    if not raw:
        return "", ""
    if "://" in raw:
        try:
            parts = urlsplit(raw)
            port = parts.port
        except ValueError:
            return "", ""
        host = (parts.hostname or "").lower()
        scheme = (parts.scheme or "http").lower()
        if port is None:
            port_s = {"https": "443", "wss": "443", "http": "80", "ws": "80"}.get(scheme, "")
        else:
            port_s = str(port)
        return host, port_s
    # Host 头：可带端口；IPv6 形如 [::1]:6200
    if raw.startswith("["):
        end = raw.find("]")
        host = raw[1:end] if end > 0 else ""
        rest = raw[end + 1 :] if end > 0 else ""
        port = rest[1:] if rest.startswith(":") else ""
        return host.lower(), port or default_port
    if raw.count(":") == 1:
        host, port = raw.split(":", 1)
        return host.lower(), port or default_port
    return raw.lower(), default_port


def _origin_allowed(origin: str, host_hdr: str) -> bool:
    """B3: Origin 必须与 Host 的 hostname[:port] 精确一致，禁止后缀匹配。"""
    if not origin:
        return True
    o_host, o_port = _host_port(origin)
    h_host, h_port = _host_port(host_hdr)
    if not o_host or not h_host:
        return False
    if o_host != h_host:
        return False
    # 端口：均空或相同；scheme 默认端口与 Host 显式默认端口等价
    if o_port and h_port:
        return o_port == h_port
    if o_port and not h_port:
        scheme = (urlsplit(origin).scheme or "http").lower()
        default = {"https": "443", "wss": "443"}.get(scheme, "80")
        return o_port == default
    if h_port and not o_port:
        return h_port in {"80", "443"}
    return True


def _json(data: Any, status: int = 200) -> web.Response:
    return web.json_response(data, status=status)


def _legacy_autonomy_retired() -> web.Response:
    return _json({
        "ok": False, "error": "legacy_autonomy_retired", "retired": True,
        "read_only": True, "enabled": False, "auto_enabled": False,
        "message": "旧自治流程已退役，仅保留历史只读查看；人工审批、手动调查和 Runbook 继续可用。",
    }, 410)


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
        nodewatch=None,
        exttx=None,
        autonomy=None,
        providers=None,
        ops_loop=None,
        ops_constraints=None,
        mimo_admin=None,
        duty=None,
        session_bridge=None,
        mimo_serve=None,
        agent_tui=None,
        mimo_events=None,
        alertmanager_webhook_path: str = "/hooks/alertmanager",
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
        self.nodewatch = nodewatch
        self.exttx = exttx
        self.ops_loop = ops_loop
        self.ops_constraints = ops_constraints
        self.mimo_admin = mimo_admin
        self.duty = duty
        self.session_bridge = session_bridge
        self.mimo_serve = mimo_serve
        self.agent_tui = agent_tui
        self.mimo_events = mimo_events
        # Legacy kwargs remain accepted for older callers, but no live service is retained.
        from .legacy_history import LegacyHistory

        self.autonomy = None
        self.providers = None
        self.legacy_history = LegacyHistory(db)
        # P2-4: 死键修复 — 路由读取 config.alertmanager_webhook_path
        self.alertmanager_webhook_path = alertmanager_webhook_path or "/hooks/alertmanager"

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
        app.router.add_get("/api/setup/status", self.api_setup_status)
        app.router.add_post("/api/setup/register", self.api_setup_register)
        app.router.add_get("/api/setup/monitor", self.api_setup_monitor_get)
        app.router.add_post("/api/setup/monitor", self.api_setup_monitor_post)
        app.router.add_get("/api/settings/global", self.api_settings_global_get)
        app.router.add_post("/api/settings/global", self.api_settings_global_post)
        app.router.add_get("/api/settings/prompts", self.api_settings_prompts_get)
        app.router.add_post("/api/settings/prompts", self.api_settings_prompts_save)
        app.router.add_post("/api/settings/prompts/restore", self.api_settings_prompts_restore)
        app.router.add_get("/api/settings/skills", self.api_settings_skills)
        app.router.add_get("/api/settings/about", self.api_settings_about)
        app.router.add_post("/api/settings/updates/check", self.api_settings_updates_check)
        # 最终架构：软约束 / 工单闭环 / MiMoCode 管理 / 统一台账
        app.router.add_get("/api/ops/constraints", self.api_ops_constraints_get)
        app.router.add_post("/api/ops/constraints", self.api_ops_constraints_save)
        app.router.add_post("/api/ops/constraints/activate", self.api_ops_constraints_activate)
        app.router.add_get("/api/ops/loop/{inc_id}", self.api_ops_loop_status)
        app.router.add_get("/api/mimo/status", self.api_mimo_status)
        app.router.add_post("/api/mimo/start", self.api_mimo_start)
        app.router.add_post("/api/mimo/stop", self.api_mimo_stop)
        app.router.add_post("/api/mimo/restart", self.api_mimo_restart)
        app.router.add_get("/api/mimo/logs", self.api_mimo_logs)
        app.router.add_get("/api/mimo/stats", self.api_mimo_stats)
        app.router.add_get("/api/mimo/providers", self.api_mimo_providers)
        app.router.add_get("/api/mimo/provider", self.api_mimo_provider_status)
        app.router.add_post("/api/mimo/provider/test", self.api_mimo_provider_test)
        app.router.add_post("/api/mimo/provider", self.api_mimo_provider_apply)
        app.router.add_post("/api/mimo/provider/clear", self.api_mimo_provider_clear)
        app.router.add_post("/api/mimo/chat", self.api_mimo_chat)
        # Agent 工作台：会话 / 消息 / 设置 / 待审批
        app.router.add_get("/api/agent/sessions", self.api_agent_sessions)
        app.router.add_post("/api/agent/sessions", self.api_agent_session_create)
        app.router.add_get("/api/agent/sessions/{sid}", self.api_agent_session_detail)
        app.router.add_delete("/api/agent/sessions/{sid}", self.api_agent_session_delete)
        app.router.add_get("/api/agent/sessions/{sid}/copy-text", self.api_agent_session_copy_text)
        app.router.add_post("/api/agent/sessions/{sid}/pause", self.api_agent_session_pause)
        app.router.add_post("/api/agent/sessions/{sid}/resume-duty", self.api_agent_session_resume_duty)
        app.router.add_post("/api/agent/sessions/{sid}/recover", self.api_agent_session_recover)
        app.router.add_post("/api/agent/sessions/{sid}/permissions", self.api_agent_session_permissions)
        app.router.add_post("/api/agent/sessions/{sid}/prompt", self.api_agent_session_prompt)
        app.router.add_post("/api/agent/sessions/{sid}/abort", self.api_agent_session_abort)
        app.router.add_get("/api/agent/events", self.api_agent_events)
        app.router.add_get("/api/agent/serve-status", self.api_agent_serve_status)
        app.router.add_post("/api/agent/sessions/{sid}/archive", self.api_agent_session_archive)
        app.router.add_post("/api/agent/sessions/{sid}/reopen", self.api_agent_session_reopen)
        app.router.add_post("/api/agent/sessions/{sid}/terminal", self.api_agent_terminal_prepare)
        app.router.add_get("/api/agent/sessions/{sid}/terminal", self.api_agent_terminal_status)
        app.router.add_post("/api/agent/sessions/{sid}/terminal/control", self.api_agent_terminal_control)
        app.router.add_get("/ws/agent-terminal", self.ws_agent_terminal)
        app.router.get("/api/agent/sessions/{sid}/events", self.api_agent_session_events)
        app.router.add_get("/api/agent/settings", self.api_agent_settings_get)
        app.router.add_post("/api/agent/settings", self.api_agent_settings_post)
        app.router.add_get("/api/agent/pending-writes", self.api_agent_pending_writes)
        app.router.add_post("/api/agent/pending-writes/approve", self.api_agent_pending_approve)
        app.router.add_post("/api/agent/pending-writes/reject", self.api_agent_pending_reject)
        app.router.add_get("/api/agent/pending-actions", self.api_agent_pending_actions)
        app.router.add_get("/api/executions", self.api_executions)
        app.router.add_get("/api/overview", self.api_overview)
        app.router.add_get("/api/assets", self.api_assets)
        app.router.add_get("/api/assets/{asset_id}", self.api_asset_detail)
        app.router.add_post("/api/assets", self.api_asset_create)
        app.router.add_post("/api/assets/{asset_id}/update", self.api_asset_update)
        app.router.add_delete("/api/assets/{asset_id}", self.api_asset_delete)
        app.router.add_post("/api/assets/{asset_id}/investigate", self.api_investigate)
        app.router.add_get("/api/incidents", self.api_incidents)
        app.router.add_get("/api/incidents/{inc_id}", self.api_incident_detail)
        app.router.add_get("/api/incidents/{inc_id}/council", self.api_incident_council)
        app.router.add_post("/api/incidents/{inc_id}/council/review", self.api_council_manual_review)
        app.router.add_get("/api/autonomy/providers", self.api_autonomy_providers)
        app.router.add_post("/api/autonomy/providers", self.api_autonomy_providers_save)
        app.router.add_post("/api/autonomy/providers/verify", self.api_autonomy_provider_verify)
        app.router.add_get("/api/autonomy/usage", self.api_autonomy_usage)
        app.router.add_get("/api/loops", self.api_loops)
        app.router.add_post("/api/incidents/{inc_id}/close", self.api_incident_close)
        app.router.add_get("/api/actions", self.api_actions)
        app.router.add_get("/api/actions/{aid}", self.api_action_detail)
        app.router.add_post("/api/actions", self.api_action_propose)
        app.router.add_post("/api/actions/{aid}/approve", self.api_action_approve)
        app.router.add_post("/api/actions/{aid}/decision", self.api_action_decision)
        app.router.add_post("/api/actions/{aid}/reject", self.api_action_reject)
        app.router.add_post("/api/actions/{aid}/cancel", self.api_action_cancel)
        app.router.add_post("/api/actions/{aid}/execute", self.api_action_execute)
        app.router.add_post("/api/actions/{aid}/verify", self.api_action_verify)
        app.router.add_get("/api/permissions", self.api_permissions)
        app.router.add_get("/api/permissions/model", self.api_permissions_model)
        app.router.add_get("/api/permissions/effective", self.api_permissions_effective)
        app.router.add_post("/api/permissions/validate", self.api_permission_validate)
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
        app.router.add_get("/api/notify/aibot/admins", self.api_notify_aibot_admins)
        app.router.add_post("/api/notify/aibot/admins", self.api_notify_aibot_admins_save)
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
        app.router.add_post("/api/node-watch/heartbeat", self.api_node_watch_heartbeat)
        app.router.add_get("/api/node-watch/status", self.api_node_watch_status)
        app.router.add_post("/api/node-watch/send-test", self.api_node_watch_send_test)
        app.router.add_post("/api/node-watch/invite/generate", self.api_node_watch_invite_generate)
        app.router.add_post("/api/node-watch/invite/parse", self.api_node_watch_invite_parse)
        app.router.add_post("/api/node-watch/invite/apply", self.api_node_watch_invite_apply)
        app.router.add_post("/api/node-watch/settings", self.api_node_watch_settings)
        # 主机资源监控
        app.router.add_get("/api/monitor/hosts", self.api_monitor_hosts)
        app.router.add_get("/api/monitor/host/{asset_id}", self.api_monitor_host)
        app.router.add_get("/api/monitor/business/{asset_id}", self.api_monitor_business)
        app.router.add_get("/api/runbook", self.api_runbook)
        app.router.add_post("/api/agent/auto", self.api_agent_auto_toggle)
        app.router.add_get("/api/agent/status", self.api_agent_status)
        app.router.add_get("/api/capabilities", self.api_capabilities)
        app.router.add_get("/api/prom/probe", self.api_prom_probe)
        app.router.add_get("/api/checks", self.api_checks_list)
        app.router.add_post("/api/checks", self.api_checks_create)
        app.router.add_post("/api/checks/validate", self.api_checks_validate)
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
        app.router.add_post(self.alertmanager_webhook_path, self.hook_alertmanager)
        # 外部事务
        app.router.add_post("/api/ext/report", self.api_ext_report)
        app.router.add_get("/api/ext/transactions", self.api_ext_transactions)
        app.router.add_post("/api/ext/transactions", self.api_ext_transaction_create)
        app.router.add_post("/api/ext/transactions/{tid}/update", self.api_ext_transaction_update)
        app.router.add_post("/api/ext/transactions/{tid}/enabled", self.api_ext_transaction_enabled)
        app.router.add_delete("/api/ext/transactions/{tid}", self.api_ext_transaction_delete)
        app.router.add_post("/api/ext/transactions/{tid}/tokens", self.api_ext_token_issue)
        app.router.add_post("/api/ext/transactions/{tid}/rotate", self.api_ext_token_rotate)
        app.router.add_post("/api/ext/tokens/{token_id}/revoke", self.api_ext_token_revoke)
        app.router.add_get("/api/ext/transactions/{tid}/runs", self.api_ext_runs)
        return app

    async def api_assist_form(self, request: web.Request) -> web.Response:
        """返回真实表单结构化定义（单一来源）。"""
        self._require_auth(request)
        from . import formspec

        domain = request.rel_url.query.get("domain", "checks")
        try:
            form = formspec.get_form(domain)
        except KeyError:
            return _json({"ok": False, "error": "bad_domain", "message": "当前页面尚不支持智能填表。"}, 400)
        return _json({"ok": True, "form": form})

    def _assist_assets(self, sess: dict) -> list[dict]:
        """Only enabled, visible inventory; no credentials or unrestricted client context."""
        visible = self._visible_asset_ids(sess)
        assets = []
        store = self.ssh_store or self._ssh_store()
        for row in self.db.query("SELECT id, display_name FROM assets WHERE enabled=1 ORDER BY id"):
            if row["id"] not in visible:
                continue
            asset = dict(row)
            asset["objects"] = [dict(obj) for obj in self.db.query(
                "SELECT id, kind, name, unit, container, port, protocol FROM objects WHERE asset_id=? ORDER BY id",
                (row["id"],),
            )]
            if store is not None:
                endpoints = store.list_endpoints(row["id"])
                asset["execution"] = {"channel": "registered_ssh",
                                      "connection_configured": any(ep.get("enabled") for ep in endpoints),
                                      "boundary": "仅现有只读探测命令；主机受限通道仍是最终边界。"}
            assets.append(asset)
        return assets

    async def api_assist_configure(self, request: web.Request) -> web.Response:
        """自然语言 → 填表意图。只读查询 + 字段草稿；不保存。"""
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json", "message": "提交内容无法读取，请重新填写。"}, 400)
        if not isinstance(body, dict) or not isinstance(body.get("text"), str):
            return _json({"ok": False, "error": "bad_input", "message": "请用文字描述要配置什么。"}, 400)
        domain = body.get("domain")
        text = body["text"].strip()
        ctx = body.get("context", {})
        if not isinstance(ctx, dict) or len(json.dumps(ctx, ensure_ascii=False)) > 20000:
            return _json({"ok": False, "error": "bad_context", "message": "补充内容格式不正确或过长，请重新填写。"}, 400)
        if domain not in ("checks", "permissions"):
            return _json({"ok": False, "error": "bad_domain", "message": "当前页面尚不支持智能填表。"}, 400)
        if not text or len(text) > 4000:
            return _json({"ok": False, "error": "bad_text", "message": "请输入不超过 4000 字的配置描述。"}, 400)
        if domain == "checks":
            self._check_read(request)

        assets = self._assist_assets(sess)
        from .capabilities import list_capabilities

        caps = list_capabilities() if domain == "permissions" else []
        names: list[str] = []
        if domain == "checks":
            visible_ids = {a["id"] for a in assets}
            names = [c["name"] for c in self._checks().list_checks("") if c["asset_id"] in visible_ids]

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
                detail={"domain": domain, "source": res.get("source"), "route": res.get("route"),
                        "status": res.get("status"), "error": res.get("error"),
                        "trace_id": (res.get("diagnostics") or {}).get("trace_id")},
            )
        except Exception:
            pass
        return _json(res)

    # ---- auth helpers ----

    def _session(self, request: web.Request) -> dict[str, Any] | None:
        cookies = getattr(request, "cookies", None) or {}
        sid = cookies.get(SESSION_COOKIE, "")
        headers = getattr(request, "headers", None) or {}
        return self.auth.get_session(
            sid,
            ip=getattr(request, "remote", "") or "",
            ua=headers.get("User-Agent", "") if hasattr(headers, "get") else "",
        )

    def _require_auth(self, request: web.Request) -> dict[str, Any] | None:
        sess = self._session(request)
        if not sess:
            raise web.HTTPUnauthorized(text=json.dumps({"error": "unauthorized"}))
        self._enforce_password_change(request, sess)
        return sess

    def _enforce_password_change(self, request: web.Request, sess: dict) -> None:
        """首登强制改密：仅放行 me/logout/password 与首登监控配置。"""
        if not sess.get("must_change_password"):
            return
        path = request.rel_url.path
        if path in ("/api/me", "/api/logout", "/api/password", "/api/setup/monitor"):
            return
        raise web.HTTPForbidden(
            text=json.dumps({
                "error": "password_change_required",
                "message": "首次登录或口令已重置，请先修改密码。",
            })
        )

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
        # 允许同源或无 Origin（curl）；非法 Origin 直接拒绝
        if origin and host and not _origin_allowed(origin, host):
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

        - 未登录：仅返回 ok/version（A2：不暴露 Worker/积压/依赖细节）
        - 已登录：DB / schema 必须可用，否则 503；外部依赖降级展示
        """
        sess = self._session(request)
        if not sess:
            try:
                self.db.query_one("SELECT 1 AS x")
                ver = self.db.schema_version()
                from .db import SCHEMA_VERSION

                ok = ver == SCHEMA_VERSION
            except Exception:
                ok = False
            return _json(
                {"ok": ok, "version": self.version, "detail": "auth_required"},
                200 if ok else 503,
            )

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
                    "must_change_password": bool(sess.get("must_change_password")),
                    "totp_enabled": bool(self.auth.totp_enabled(sess["username"])),
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
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json"}, 400)
        ip = request.remote or ""
        ua = request.headers.get("User-Agent", "")
        try:
            res = self.auth.begin_login(
                body.get("username", ""), body.get("password", ""), ip=ip, ua=ua
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
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json"}, 400)
        ip = request.remote or ""
        ua = request.headers.get("User-Agent", "")
        try:
            sess = self.auth.complete_login(
                body.get("pending_id", ""),
                totp_code=body.get("totp", "") or body.get("code", ""),
                recovery_code=body.get("recovery_code", ""),
                ip=ip,
                ua=ua,
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
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json"}, 400)
        ip = request.remote or ""
        ua = request.headers.get("User-Agent", "")
        try:
            sess = self.auth.login(
                body.get("username", ""),
                body.get("password", ""),
                body.get("totp", ""),
                body.get("recovery_code", ""),
                ip=ip,
                ua=ua,
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
            # A3: 已登录会话的注销需 CSRF，防跨站强制登出
            self._check_csrf(request, sess)
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
        new_sess = self.auth._issue_session(
            sess["user_id"],
            request.remote or "",
            request.headers.get("User-Agent", ""),
        )
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
        new_sess = self.auth._issue_session(
            sess["user_id"],
            request.remote or "",
            request.headers.get("User-Agent", ""),
        )
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
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json", "message": "请求体不是合法 JSON"}, 400)
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json", "message": "请求体不是合法 JSON"}, 400)

        old_password = body.get("old_password", "")
        new_password = body.get("new_password", "")
        confirm_password = body.get("confirm_password", "")
        if isinstance(confirm_password, str) and confirm_password != "" and confirm_password != new_password:
            return _json(
                {"ok": False, "error": "mismatch", "message": "两次输入的新密码不一致"},
                400,
            )

        must = bool(sess.get("must_change_password"))
        try:
            # 首登/强制改密：不要求旧密，保留当前会话；主动改密：验旧密并撤销全部会话
            self.auth.change_password(
                sess["user_id"],
                old_password if isinstance(old_password, str) else "",
                new_password if isinstance(new_password, str) else "",
                require_old=not must,
                keep_session_id=sess.get("session_id") if must else None,
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        self.db.audit(
            "web_user",
            sess["username"],
            "password_changed",
            detail={"forced": must},
        )
        return _json({"ok": True, "must_change_password": False, "session_kept": bool(must)})

    # ---- first-run setup token registration ----

    def _setup_token_hint(self) -> str:
        """告诉用户去哪里看 token 文件，不暴露 token 本身。"""
        try:
            from pathlib import Path as _P

            db_path = _P(self.db.path).resolve()
            return str(db_path.parent / "setup-admin.token")
        except Exception:
            return "与数据库同目录的 setup-admin.token"

    async def api_setup_status(self, request: web.Request) -> web.Response:
        """公开：是否可注册。仅 pending 且服务端状态明确时才 true。"""
        sess = self._session(request)
        if sess:
            return _json(
                {
                    "ok": True,
                    "setup_required": bool(sess.get("must_change_password")),
                    "register_open": False,
                    "state": self.auth.setup_state() if self.auth else "unknown",
                    "logged_in": True,
                }
            )
        state = self.auth.setup_state() if self.auth else "unknown"
        n = self.auth.user_count() if self.auth else 0
        # 双重条件：显式 pending + 空用户；缺一不可
        register_open = state == "pending" and n == 0
        return _json(
            {
                "ok": True,
                "setup_required": False,
                "register_open": register_open,
                "state": state,
                "logged_in": False,
                "token_hint": self._setup_token_hint() if register_open else "",
            }
        )

    async def api_setup_register(self, request: web.Request) -> web.Response:
        """Token 一次性注册管理员。无会话可访问；成功即建会话。"""
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json", "message": "请求体不是合法 JSON"}, 400)
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json", "message": "请求体不是合法 JSON"}, 400)
        token = body.get("token", "")
        username = body.get("username", "")
        password = body.get("password", "")
        confirm = body.get("confirm_password", "")
        if isinstance(confirm, str) and confirm and confirm != password:
            return _json(
                {"ok": False, "error": "mismatch", "message": "两次输入的密码不一致"},
                400,
            )
        ip = request.remote or ""
        ua = request.headers.get("User-Agent", "")
        try:
            sess = self.auth.register_admin(
                token if isinstance(token, str) else "",
                username if isinstance(username, str) else "",
                password if isinstance(password, str) else "",
                ip=ip,
                ua=ua,
            )
        except AuthError as e:
            return _json({"ok": False, "error": e.code, "message": str(e)}, 400)
        self.db.audit(
            "web_user",
            str(username),
            "admin_registered",
            detail={"ip": ip, "method": "setup_token"},
        )
        self._try_seed_admin_perms(str(username))
        resp = _json(
            {
                "ok": True,
                "csrf_token": sess["csrf_token"],
                "user": {"username": str(username), "is_admin": True, "must_change_password": False},
            }
        )
        resp.set_cookie(
            SESSION_COOKIE,
            sess["session_id"],
            httponly=True,
            samesite="Lax",
            max_age=self.auth.session_ttl,
            path="/",
        )
        return resp

    def _try_seed_admin_perms(self, username: str) -> None:
        """注册后补齐 admin 种子权限（只补缺失）。"""
        try:
            if not self.db.query_one(
                "SELECT id FROM users WHERE username=? AND is_admin=1", (username,)
            ):
                return
            from .policy import Policy as _P

            policy = _P(self.db)
            for cap in (
                "asset.summary",
                "probe.status",
                "checks.read",
                "checks.write",
                "promconfig.read",
                "promconfig.write",
                "node_exporter.status",
                "node_exporter.manage",
                "shell.interactive",
            ):
                row = self.db.query_one(
                    "SELECT id FROM permissions WHERE subject_type='web_user' AND subject_id=?"
                    " AND capability=? AND asset_id='*' AND object_id='*'",
                    (username, cap),
                )
                if row:
                    continue
                policy.upsert_permission(
                    subject_type="web_user",
                    subject_id=username,
                    capability=cap,
                    asset_id="*",
                    object_id="*",
                    allow=True,
                    require_approval=False,
                    auto_allowed=False,
                    actor="system",
                )
        except Exception as e:
            log.warning("seed admin perms after register failed: %s", e)

    # ---- monitoring setup (resource page; not on first-login) ----

    async def api_setup_monitor_get(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        prom_url = self._meta_get("prometheus_url") or getattr(self.prom, "base_url", "")
        am_url = self._meta_get("alertmanager_url") or str(
            (getattr(self, "cfg", None) or {}).get("alertmanager_url") or ""
        )
        if not hasattr(self, "cfg"):
            am_url = self._meta_get("alertmanager_url")
        prom_ok, prom_err = await self._probe_prometheus()
        return _json(
            {
                "ok": True,
                "prometheus_url": prom_url,
                "alertmanager_url": am_url,
                "prometheus_ok": prom_ok,
                "prometheus_error": prom_err,
                "prometheus_hint": (
                    ""
                    if prom_ok
                    else "未检测到可用的 Prometheus，请先安装并启动 Prometheus（或把 prometheus_url 指向已有实例）。"
                ),
                "is_admin": bool(sess.get("is_admin")),
            }
        )

    async def _probe_prometheus(self) -> tuple[bool, str]:
        """轻量探测 Prometheus 是否可用（供一键接入前置检查）。"""
        if not getattr(self, "prom", None):
            return False, "prom_client_missing"
        try:
            await self.prom.query("1")
            return True, ""
        except Exception as error:
            log.warning("Prometheus settings probe failed: %s", type(error).__name__)
            return False, "连接失败，请检查监控地址和服务状态后重试。"

    def _mask_secret(self, value: str) -> str:
        v = (value or "").strip()
        if not v:
            return ""
        if len(v) <= 8:
            return "****"
        return v[:4] + "****" + v[-2:]

    def _apply_llm_settings(self, base_url: str, model: str, api_key: str | None = None) -> None:
        llm = getattr(self, "llm", None)
        if not llm:
            return
        if base_url:
            llm.base_url = base_url.rstrip("/")
        if model:
            llm.model = model
        if api_key is not None and api_key != "":
            llm.api_key = api_key

    async def api_settings_global_get(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        llm = getattr(self, "llm", None)
        prom_url = self._meta_get("prometheus_url") or getattr(self.prom, "base_url", "")
        am_url = self._meta_get("alertmanager_url")
        prom_ok, prom_err = await self._probe_prometheus()
        return _json(
            {
                "ok": True,
                "llm_base_url": getattr(llm, "base_url", "") if llm else "",
                "llm_model": getattr(llm, "model", "") if llm else "",
                "llm_api_key_set": bool(getattr(llm, "api_key", "")) if llm else False,
                "llm_api_key_masked": self._mask_secret(getattr(llm, "api_key", "") if llm else ""),
                "prometheus_url": prom_url,
                "alertmanager_url": am_url,
                "prometheus_ok": prom_ok,
                "prometheus_error": prom_err,
            }
        )

    async def api_settings_global_post(self, request: web.Request) -> web.Response:
        """全局设置：AI 模型 / Prometheus。仅管理员；API Key 不回显。"""
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json", "message": "请求体不是合法 JSON"}, 400)
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json", "message": "请求体不是合法 JSON"}, 400)

        llm_base = str(body.get("llm_base_url") or "").strip()
        llm_model = str(body.get("llm_model") or "").strip()
        llm_key = body.get("llm_api_key", None)
        prom_url = str(body.get("prometheus_url") or "").strip()
        am_url = str(body.get("alertmanager_url") or "").strip()

        for label, url in (("prometheus_url", prom_url), ("alertmanager_url", am_url), ("llm_base_url", llm_base)):
            if url and not re.fullmatch(r"https?://[^\s]+", url):
                return _json(
                    {"ok": False, "error": "bad_url", "message": f"{label} 必须是 http(s) 地址"},
                    400,
                )
        if llm_key is not None and not isinstance(llm_key, str):
            return _json({"ok": False, "error": "bad_api_key", "message": "API Key 格式不正确"}, 400)

        # 持久化到 meta（不覆盖 secrets.json 文件，服务内生效）
        if llm_base:
            self._meta_set("llm_base_url", llm_base.rstrip("/"))
        if llm_model:
            self._meta_set("llm_model", llm_model)
        if isinstance(llm_key, str) and llm_key.strip():
            self._meta_set("llm_api_key", llm_key.strip())
        if prom_url:
            self._meta_set("prometheus_url", prom_url.rstrip("/"))
            if getattr(self, "prom", None):
                self.prom.base_url = prom_url.rstrip("/")
                self.prom._fail_streak = 0
                self.prom._open_until = 0.0
        if am_url:
            self._meta_set("alertmanager_url", am_url.rstrip("/"))

        self._apply_llm_settings(llm_base, llm_model, llm_key if isinstance(llm_key, str) else None)
        self.db.audit(
            "web_user",
            sess["username"],
            "settings_global_updated",
            detail={
                "llm_base_url": bool(llm_base),
                "llm_model": bool(llm_model),
                "llm_api_key": bool(isinstance(llm_key, str) and llm_key.strip()),
                "prometheus_url": bool(prom_url),
            },
        )
        prom_ok, prom_err = await self._probe_prometheus()
        llm = getattr(self, "llm", None)
        return _json(
            {
                "ok": True,
                "llm_base_url": getattr(llm, "base_url", "") if llm else "",
                "llm_model": getattr(llm, "model", "") if llm else "",
                "llm_api_key_set": bool(getattr(llm, "api_key", "")) if llm else False,
                "llm_api_key_masked": self._mask_secret(getattr(llm, "api_key", "") if llm else ""),
                "prometheus_url": getattr(self.prom, "base_url", "") if self.prom else "",
                "alertmanager_url": am_url or self._meta_get("alertmanager_url"),
                "prometheus_ok": prom_ok,
                "prometheus_error": prom_err,
            }
        )

    async def api_setup_monitor_post(self, request: web.Request) -> web.Response:
        """首次登录/独立部署：配置监控接入地址。写 DB meta 并立即生效。"""
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json", "message": "请求体不是合法 JSON"}, 400)
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json", "message": "请求体不是合法 JSON"}, 400)

        prom_url = str(body.get("prometheus_url") or "").strip()
        am_url = str(body.get("alertmanager_url") or "").strip()
        for label, url in (("prometheus_url", prom_url), ("alertmanager_url", am_url)):
            if not url:
                continue
            if not re.fullmatch(r"https?://[^\s]+", url):
                return _json(
                    {"ok": False, "error": "bad_url", "message": f"{label} 必须是 http(s) 地址"},
                    400,
                )
            if len(url) > 300:
                return _json(
                    {"ok": False, "error": "bad_url", "message": f"{label} 过长"},
                    400,
                )

        if prom_url:
            self._meta_set("prometheus_url", prom_url.rstrip("/"))
            if getattr(self, "prom", None):
                self.prom.base_url = prom_url.rstrip("/")
                # 换地址后重置熔断，便于立即探测
                self.prom._fail_streak = 0
                self.prom._open_until = 0.0
        if am_url:
            self._meta_set("alertmanager_url", am_url.rstrip("/"))

        probe = {"ok": None, "error": ""}
        if prom_url and getattr(self, "prom", None):
            try:
                await self.prom.query("1")
                probe = {"ok": True, "error": ""}
            except Exception as error:
                log.warning("Prometheus setup probe failed: %s", type(error).__name__)
                probe = {"ok": False, "error": "连接失败，请检查监控地址和服务状态后重试。"}

        self.db.audit(
            "web_user",
            sess["username"],
            "monitor_setup",
            detail={"prometheus_url": prom_url or "", "probe_ok": probe.get("ok")},
        )
        return _json(
            {
                "ok": True,
                "prometheus_url": prom_url or getattr(self.prom, "base_url", ""),
                "alertmanager_url": am_url,
                "probe": probe,
            }
        )

    # ---- Unified settings center: versioned prompts, inventory and about ----

    async def _settings_body(self, request: web.Request, allowed: set[str]) -> dict | None:
        try:
            body = await request.json()
        except (ValueError, TypeError):
            return None
        return body if isinstance(body, dict) and not set(body) - allowed else None

    @staticmethod
    def _settings_failure(error: Exception) -> web.Response:
        messages = {
            "invalid_prompt_key": "请选择有效的提示词。",
            "empty_prompt": "提示词不能为空。",
            "prompt_too_long": "提示词不能超过 20000 个字符。",
            "invalid_prompt": "提示词包含无效字符。",
            "invalid_change_note": "变更说明不能超过 300 个字符。",
            "invalid_version_id": "请选择有效的历史版本。",
            "version_not_found": "该提示词版本不存在。",
        }
        code = str(error) if isinstance(error, ValueError) else "settings_failed"
        if code not in messages:
            code = "settings_failed"
        return _json({"ok": False, "error": code, "message": messages.get(code, "设置操作未完成，请稍后重试。")}, 400 if code in messages else 500)

    async def api_settings_prompts_get(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        from .settings_admin import PromptSettings
        return _json(PromptSettings(self.db).overview())

    async def api_settings_prompts_save(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await self._settings_body(request, {"key", "text", "change_note"})
        if body is None:
            return _json({"ok": False, "error": "bad_request", "message": "请求格式不正确。"}, 400)
        from .settings_admin import PromptSettings
        try:
            current = PromptSettings(self.db).save(body.get("key"), body.get("text"), actor=sess["username"], change_note=body.get("change_note", ""))
        except Exception as error:
            return self._settings_failure(error)
        return _json({"ok": True, "current": current, "effect": "next_call", "message": "已保存，下次调查或决策调用生效。"})

    async def api_settings_prompts_restore(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await self._settings_body(request, {"key", "version_id"})
        if body is None:
            return _json({"ok": False, "error": "bad_request", "message": "请求格式不正确。"}, 400)
        from .settings_admin import PromptSettings
        try:
            current = PromptSettings(self.db).restore(body.get("key"), body.get("version_id"), actor=sess["username"])
        except Exception as error:
            return self._settings_failure(error)
        return _json({"ok": True, "current": current, "effect": "next_call", "message": "已恢复为新版本，下次调查或决策调用生效。"})

    async def api_settings_skills(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        from .settings_admin import discover_skills
        try:
            result = await asyncio.to_thread(discover_skills, workdir=Path(self._mimo().workdir or Path(__file__).resolve().parents[1]))
            # Redact source strings before JSON escapes quotes/backslashes in
            # credentials. Redacting the serialized JSON cannot match those keys.
            def redact(value):
                if isinstance(value, str):
                    return self._mimo()._redact(value)
                if isinstance(value, list):
                    return [redact(item) for item in value]
                if isinstance(value, dict):
                    return {redact(key): redact(item) for key, item in value.items()}
                return value
            return _json(await asyncio.to_thread(redact, result))
        except Exception:
            return _json({"ok": False, "error": "skills_unavailable", "message": "技能目录暂时无法读取，请稍后重试。"}, 503)

    async def api_settings_about(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        from .settings_admin import PROJECT_URL
        status = await self._mimo().status()
        return _json({"ok": True, "ayana_version": self.version, "mimocode_version": status.get("version") or "未安装或无法读取",
                      "project_url": PROJECT_URL, "update_supported": True, "update_note": "检查项目正式发布版本，不会安装或执行更新。"})

    async def api_settings_updates_check(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await self._settings_body(request, set())
        if body is None:
            return _json({"ok": False, "error": "bad_request", "message": "请求格式不正确。"}, 400)
        from .settings_admin import check_update
        result = await check_update(self.version)
        self.db.audit("web_user", sess["username"], "settings_update_checked", detail={"result": result.get("result") or result.get("error")}, channel="web")
        return _json(result)

    # ---- final architecture: ops constraints / mimo / ledger ----

    async def api_ops_constraints_get(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        if not self.ops_constraints:
            return _json({"ok": False, "error": "unavailable"}, 503)
        return _json(
            {
                "ok": True,
                "current": self.ops_constraints.current(),
                "versions": self.ops_constraints.list_versions(),
            }
        )

    async def api_ops_constraints_save(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._require_admin(request)
        self._check_csrf(request, sess)
        if not self.ops_constraints:
            return _json({"ok": False, "error": "unavailable"}, 503)
        body = await request.json()
        text = str(body.get("text") or "")
        try:
            cur = self.ops_constraints.save(
                text,
                actor=sess["username"],
                change_note=str(body.get("change_note") or ""),
                activate=bool(body.get("activate", True)),
            )
        except ValueError as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "current": cur})

    async def api_ops_constraints_activate(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._require_admin(request)
        self._check_csrf(request, sess)
        if not self.ops_constraints:
            return _json({"ok": False, "error": "unavailable"}, 503)
        body = await request.json()
        try:
            cur = self.ops_constraints.activate(int(body.get("version_id") or 0), actor=sess["username"])
        except ValueError as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "current": cur})

    async def api_ops_loop_status(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        inc_id = request.match_info["inc_id"]
        if not self.ops_loop:
            return _json({"ok": False, "error": "unavailable"}, 503)
        loop = self.ops_loop.status(inc_id)
        job = self.db.query_one(
            "SELECT status, rounds, last_result_status, last_error, generation, updated_at"
            " FROM investigation_jobs WHERE incident_id=?",
            (inc_id,),
        )
        ai = getattr(self, "auto_investigator", None)
        cfg = getattr(ai, "config", None) if ai else None
        return _json({
            "ok": True,
            "loop": loop,
            "investigation": dict(job) if job else None,
            "closed_loop_enabled": bool(getattr(cfg, "closed_loop", False)) if cfg else False,
            "auto_investigate_enabled": bool(getattr(cfg, "enabled", False)) if cfg else False,
        })

    def _mimo(self):
        if not self.mimo_admin:
            raise web.HTTPNotFound(text=json.dumps({"error": "mimo_admin_unavailable"}))
        return self.mimo_admin

    async def api_mimo_status(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        st = await self._mimo().status()
        return _json(st)

    async def api_mimo_start(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._require_admin(request)
        self._check_csrf(request, sess)
        res = await self._mimo().start()
        self.db.audit("web_user", sess["username"], "mimo_start", detail=res, channel="web")
        return _json(res)

    async def api_mimo_stop(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._require_admin(request)
        self._check_csrf(request, sess)
        res = await self._mimo().stop()
        self.db.audit("web_user", sess["username"], "mimo_stop", detail=res, channel="web")
        return _json(res)

    async def api_mimo_restart(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._require_admin(request)
        self._check_csrf(request, sess)
        res = await self._mimo().restart()
        self.db.audit("web_user", sess["username"], "mimo_restart", detail=res, channel="web")
        return _json(res)

    async def api_mimo_logs(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        lines = int(request.rel_url.query.get("lines") or 80)
        return _json(await self._mimo().logs(lines=lines))

    async def api_mimo_stats(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        return _json(await self._mimo().stats())

    async def api_mimo_providers(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        return _json(self._mimo().provider_summary())

    async def api_mimo_provider_status(self, request: web.Request) -> web.Response:
        """配置与验证状态。不含密钥。未验证时 available=false。"""
        self._require_admin(request)
        admin = self._mimo()
        summary = admin.provider_summary()
        state = admin.verification_state(self.db)
        st = await admin.status()
        return _json({
            "ok": True,
            "providers": summary.get("providers") or [],
            "model": summary.get("model") or "",
            "path": summary.get("path") or "",
            "verification": state,
            "mimo_cli": {
                "exists": st.get("exists"),
                "version": st.get("version") or "",
                "binary": st.get("binary") or "",
            },
            # 未通过真实连接验证前，不得宣称 MiMoCode 已可用
            "available": bool(state.get("verified")) and bool(st.get("exists")),
        })

    async def _mimo_provider_body(self, request: web.Request) -> dict | None:
        try:
            body = await request.json()
        except (ValueError, TypeError):
            return None
        if not isinstance(body, dict) or set(body) - {"provider_id", "base_url", "api_key", "model", "test"}:
            return None
        if any(key in body and not isinstance(body[key], str)
               for key in ("provider_id", "base_url", "api_key", "model")):
            return None
        if "test" in body and not isinstance(body["test"], bool):
            return None
        return body

    @staticmethod
    def _mimo_provider_failure(error: Exception, *, status: int = 400, saved: bool = False) -> web.Response:
        safe = {
            "invalid_provider_config", "unsafe_config_path", "bad_provider_id", "api_key_required",
            "bad_api_key", "invalid_base_url", "model_required", "invalid_model",
            "key_required_for_endpoint_change", "provider_not_verified", "provider_state_save_failed",
            "provider_save_failed",
        }
        code = error.args[0] if isinstance(error, ValueError) and error.args else ""
        if not isinstance(code, str) or code not in safe:
            code = "invalid_provider_config" if status == 400 else "provider_save_failed"
        messages = {
            "api_key_required": "请填写 API Key。",
            "key_required_for_endpoint_change": "更换服务地址或 Provider 时，请重新填写 API Key。",
            "provider_state_save_failed": "验证状态未能保存，请重新验证。",
            "provider_save_failed": "配置未能保存，请重试。",
        }
        if code == "provider_state_save_failed":
            status = 500
        message = "配置已写入，但验证状态未能保存，请重新验证。" if saved else messages.get(code, "模型配置无效，请检查地址、密钥和模型。")
        return _json({"ok": False, "saved": saved, "verified": False, "error": code, "message": message}, status)

    async def api_mimo_provider_test(self, request: web.Request) -> web.Response:
        """Validate a resolved provider off the event loop; draft keys are never returned."""
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await self._mimo_provider_body(request)
        if body is None:
            return _json({"ok": False, "error": "bad_request", "message": "请求格式不正确。"}, 400)
        admin = self._mimo()
        try:
            credentials = admin.resolve_provider(**{key: body.get(key, "")
                for key in ("provider_id", "base_url", "api_key", "model")})
            result = await asyncio.to_thread(admin.test_connection,
                **{key: credentials[key] for key in ("base_url", "api_key", "model")})
            admin.record_verification(self.db, credentials, result)
        except ValueError as error:
            return self._mimo_provider_failure(error)
        except Exception:
            return _json({"ok": False, "error": "connection_error", "message": "连接测试未完成，请重试。"}, 502)
        self.db.audit("web_user", sess["username"], "mimo_provider_test",
            detail={"result": result.get("result"), "http_status": result.get("http_status"),
                    "provider": credentials["provider_id"], "model": credentials["model"]}, channel="web")
        return _json({**result, "verification": admin.verification_state(self.db)})

    async def api_mimo_provider_apply(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await self._mimo_provider_body(request)
        if body is None:
            return _json({"ok": False, "error": "bad_request", "message": "请求格式不正确。"}, 400)
        admin = self._mimo()
        applied = None
        try:
            credentials = admin.resolve_provider(**{key: body.get(key, "")
                for key in ("provider_id", "base_url", "api_key", "model")})
            do_test = body.get("test", True)
            result = {"ok": False, "result": "not_tested", "message": "尚未验证。"}
            if do_test:
                result = await asyncio.to_thread(admin.test_connection,
                    **{key: credentials[key] for key in ("base_url", "api_key", "model")})
                if result.get("ok") is not True:
                    admin.record_verification(self.db, credentials, result)
                    self.db.audit("web_user", sess["username"], "mimo_provider_rejected",
                        detail={"result": result.get("result"), "provider": credentials["provider_id"],
                                "model": credentials["model"]}, channel="web")
                    return _json({"ok": False, "saved": False,
                        "error": result.get("result") or "test_failed",
                        "message": result.get("message") or "连接测试未通过，配置未保存。", "test": result}, 400)
            applied = admin.apply_provider(**credentials, verified=result.get("ok") is True)
            admin.record_verification(self.db, credentials, result)
            state = admin.verification_state(self.db)
        except ValueError as error:
            return self._mimo_provider_failure(error, saved=applied is not None)
        except Exception:
            return self._mimo_provider_failure(ValueError("provider_save_failed"), status=500, saved=applied is not None)
        verified = state.get("verified") is True
        self.db.audit("web_user", sess["username"], "mimo_provider_apply",
            detail={"provider": credentials["provider_id"], "model": credentials["model"],
                    "verified": verified}, channel="web")
        return _json({"ok": True, "saved": True, "verified": verified,
            "path": applied.get("path"), "provider": credentials["provider_id"],
            "model": credentials["model"], "test": result})

    async def api_mimo_provider_clear(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await self._mimo_provider_body(request)
        if body is None:
            return _json({"ok": False, "error": "bad_request", "message": "请求格式不正确。"}, 400)
        admin = self._mimo()
        try:
            result = admin.clear_provider(provider_id=body.get("provider_id", ""))
            admin.save_verification_state(self.db, {"verified": False, "last_result": "cleared"})
        except ValueError as error:
            return self._mimo_provider_failure(error)
        except Exception:
            return self._mimo_provider_failure(ValueError("provider_save_failed"), status=500)
        self.db.audit("web_user", sess["username"], "mimo_provider_cleared",
                      detail={"provider": body.get("provider_id", "")}, channel="web")
        return _json({**result, "verified": False})

    async def api_mimo_chat(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
        except (ValueError, TypeError):
            body = None
        if not isinstance(body, dict) or not all(isinstance(body.get(key), str) for key in ("incident_id", "prompt")):
            return _json({"ok": False, "error": "incident_id_and_prompt_required"}, 400)
        inc_id, prompt = body["incident_id"].strip(), body["prompt"].strip()
        if not inc_id or not prompt:
            return _json({"ok": False, "error": "incident_id_and_prompt_required"}, 400)
        inc = self.incidents.get_incident(inc_id)
        if not inc:
            return _json({"ok": False, "error": "not_found"}, 404)
        if inc.get("asset_id") not in self._visible_asset_ids(sess):
            return _json({"ok": False, "error": "permission_denied"}, 403)
        bridge = getattr(self, "session_bridge", None) or getattr(self.incidents, "session_bridge", None)
        if not bridge:
            return _json({"ok": False, "error": "session_bridge_unavailable"}, 503)
        try:
            attached = await asyncio.to_thread(bridge.attach_remote, inc_id)
            if attached.get("ok") is not True:
                return _json({"ok": False, "error": "mimo_session_failed", "message": "会话未能启动，请检查已验证配置。"}, 502)
            sent = await asyncio.to_thread(bridge.prompt_remote, inc_id, prompt)
            if sent.get("ok") is not True:
                return _json({"ok": False, "error": "mimo_prompt_failed", "message": "消息未能完成，请检查会话状态。"}, 502)
        except Exception:
            return _json({"ok": False, "error": "mimo_session_failed", "message": "会话请求未完成，请重试。"}, 502)
        self.db.audit("web_user", sess["username"], "mimo_chat",
                      detail={"incident_id": inc_id, "prompt_len": len(prompt)}, channel="web")
        return _json({"ok": True, "session": attached, "prompt_result": sent})

    # ---- Agent 工作台 API ----

    def _duty(self):
        return getattr(self, "duty", None) or getattr(self.incidents, "duty", None)

    def _bridge(self):
        return getattr(self, "session_bridge", None) or getattr(self.incidents, "session_bridge", None)

    def _agent_session_visible(self, user: dict, session: dict) -> bool:
        if not session:
            return False
        duty = self._duty()
        if not duty:
            return False
        assets = {str(row.get("asset_id") or "") for row in duty.incidents(session["id"])} - {""}
        visible = self._visible_asset_ids(user)
        if assets and not assets.issubset(visible):
            return False
        if session.get("origin") == "manual":
            return bool(user.get("is_admin") or session.get("created_by") == user.get("username"))
        return bool(user.get("is_admin") or assets)

    def _agent_session_require(self, user: dict, sid: str, *, control: bool = False) -> dict:
        duty = self._duty()
        session = duty.get(sid) if duty else None
        if not session or session.get("deleted_at") or not self._agent_session_visible(user, session):
            raise web.HTTPNotFound(text=json.dumps({"ok": False, "error": "session_unavailable"}), content_type="application/json")
        if control and (not user.get("is_admin") or session.get("delete_requested_at")):
            raise web.HTTPForbidden(text=json.dumps({"ok": False, "error": "permission_denied"}), content_type="application/json")
        return session

    async def _agent_remote_ready(self, sid: str) -> dict:
        import asyncio
        from .mimo_session import READONLY_AGENT
        duty = self._duty()
        bridge = self._bridge()
        if not duty or not bridge or not getattr(bridge, "mimo", None):
            raise ValueError("runtime_unavailable")
        if not self.mimo_serve:
            raise ValueError("runtime_unavailable")
        await self.mimo_serve.ensure_running()
        native_agent = self.agent_tui._agent_name() if getattr(self,"agent_tui",None) else READONLY_AGENT
        # Observing an existing task must never wait for its execution lease.
        current = duty.get(sid)
        if current and current.get("remote_session_id"):
            return {"session": current, "remote_session_id": current["remote_session_id"], "agent": native_agent}
        async with duty.async_turn(sid):
            session = duty.get(sid)
            if not session:
                raise ValueError("session_unavailable")
            rid = str(session.get("remote_session_id") or "")
            if not rid:
                remote = await asyncio.to_thread(bridge.mimo.allocate, title=session.get("title") or "Ayana")
                rid = remote.remote_session_id
                bridge._set_remote(sid, remote_session_id=rid, status="active", model=remote.model)
            return {"session": duty.get(sid), "remote_session_id": rid, "agent": native_agent}

    @staticmethod
    def _agent_runtime_failure() -> web.Response:
        return _json({"ok": False, "error": "runtime_unavailable", "message": "原生运行服务暂不可用，或当前模型配置尚未验证。任务和历史记录已保留。"}, 503)

    async def api_agent_terminal_prepare(self, request: web.Request) -> web.Response:
        user = self._require_admin(request); self._check_csrf(request, user)
        sid = request.match_info.get("sid") or ""
        session = self._agent_session_require(user, sid, control=True)
        manager = getattr(self, "agent_tui", None)
        if manager is None:
            return self._agent_runtime_failure()
        if session.get("status") != "open" and not session.get("remote_session_id"):
            return _json({"ok": False, "error": "archived_without_remote", "message": "该历史会话没有原生会话绑定，可在右侧查看关联记录。"}, 409)
        try:
            ready = await self._agent_remote_ready(sid)
            binding = await manager.ensure(sid, ready["remote_session_id"])
            self.db.audit("web_user", user["username"], "agent_terminal_prepared", detail={"session_id": sid}, channel="web")
            return _json({"ok": True, "binding": binding, "mode": "observe"})
        except Exception as error:
            code = getattr(error, "code", "") or type(error).__name__
            log.warning("agent terminal prepare failed sid=%s code=%s error=%s", sid, code, error)
            if code in ("provider_not_verified", "runtime_changed"):
                return _json({"ok": False, "error": code, "message": "当前模型配置尚未验证，请到设置中心完成运行时校验后再接入。"}, 503)
            if code in ("tui_start_failed", "tmux_not_installed", "tmux_unavailable", "tmux_runtime_not_started"):
                return _json({"ok": False, "error": code, "message": "原生终端运行环境未就绪，请联系管理员检查 tmux 与 agent-runtime。"}, 503)
            return self._agent_runtime_failure()

    async def api_agent_terminal_status(self, request: web.Request) -> web.Response:
        user = self._require_auth(request); sid = request.match_info.get("sid") or ""
        self._agent_session_require(user, sid)
        manager = getattr(self, "agent_tui", None)
        return _json(await manager.status(sid)) if manager else _json({"ok": True, "attached": False, "binding": None})

    async def api_agent_terminal_control(self, request: web.Request) -> web.Response:
        user = self._require_admin(request); self._check_csrf(request, user)
        sid = request.match_info.get("sid") or ""
        session = self._agent_session_require(user, sid, control=True)
        if session.get("status") != "open":
            return _json({"ok": False, "error": "session_archived", "message": "请先续接历史会话再取得控制权。"}, 409)
        try:
            body = await request.json()
        except (ValueError, TypeError): body = None
        if not isinstance(body, dict) or body.get("action") not in ("acquire", "release") or not isinstance(body.get("connection_id"), str):
            return _json({"ok": False, "error": "bad_request"}, 400)
        manager = getattr(self, "agent_tui", None)
        if not manager: return self._agent_runtime_failure()
        try:
            operation = manager.acquire_control if body["action"] == "acquire" else manager.release_control
            result = operation(sid, user["username"], body["connection_id"])
            import inspect
            if inspect.isawaitable(result): result = await result
            self.db.audit("web_user", user["username"], "agent_terminal_"+body["action"], detail={"session_id": sid}, channel="web")
            return _json({"ok": True, **(result or {})})
        except Exception:
            return _json({"ok": False, "error": "control_unavailable", "message": "控制权当前不可用，可能已由其他窗口持有。"}, 409)

    async def api_agent_session_reopen(self, request: web.Request) -> web.Response:
        user = self._require_admin(request); self._check_csrf(request, user)
        sid = request.match_info.get("sid") or ""
        self._agent_session_require(user, sid, control=True)
        result = self._duty().reopen_session(sid, actor=user["username"], as_manual=True)
        return _json(result, 200 if result.get("ok") else 409)

    async def api_agent_session_pause(self, request: web.Request) -> web.Response:
        user=self._require_admin(request);self._check_csrf(request,user)
        sid=request.match_info.get("sid") or ""
        session=self._agent_session_require(user,sid,control=True)
        result=self._duty().pause_session(sid,actor=user["username"])
        if not result.get("ok"):return _json(result,409)
        self._duty().interrupt_business_work(sid,actor=user["username"])
        rid=session.get("remote_session_id")
        if rid and getattr(self,"mimo_serve",None):
            try:
                await self.mimo_serve.client().abort(rid)
                result["stop_requested"]=True
            except Exception:
                result.update(stop_requested=False,message="调度已暂停，但本轮停止尚未确认；请核对任务状态。")
        result.update(self._duty().task_info(sid))
        return _json(result)

    async def api_agent_session_resume_duty(self, request: web.Request) -> web.Response:
        user=self._require_admin(request);self._check_csrf(request,user)
        sid=request.match_info.get("sid") or ""
        self._agent_session_require(user,sid,control=True)
        result=self._duty().resume_session(sid,actor=user["username"])
        # This lifts the scheduling pause. Interrupted/unknown native execution
        # is reconciled/recovered separately, never by replaying the old prompt.
        return _json(result,200 if result.get("ok") else 409)

    async def api_agent_session_recover(self, request: web.Request) -> web.Response:
        user=self._require_admin(request);self._check_csrf(request,user)
        sid=request.match_info.get("sid") or ""
        self._agent_session_require(user,sid,control=True)
        try:body=await request.json()
        except (ValueError,TypeError):body=None
        if not isinstance(body,dict) or not isinstance(body.get("connection_id"),str):
            return _json({"ok":False,"error":"connection_required"},400)
        manager=getattr(self,"agent_tui",None)
        if not manager:return self._agent_runtime_failure()
        if not manager._has_control(sid,user["username"],body["connection_id"],renew=True):
            return _json({"ok":False,"error":"control_required","message":"请先在当前会话取得控制权，再恢复任务。"},409)
        payload={key:value for key,value in body.items() if key!="connection_id"}
        try:
            result=await manager.recover_session(sid,payload)
            return _json(result,202 if result.get("ok") else 409)
        except Exception as error:
            code=getattr(error,"code","recovery_unavailable")
            return _json({"ok":False,"error":code,"message":"恢复尚未确认，原会话及执行记录已保留。","task":self._duty().task_info(sid)},409)

    async def api_agent_session_delete(self, request: web.Request) -> web.Response:
        user=self._require_admin(request);self._check_csrf(request,user)
        sid=request.match_info.get("sid") or ""
        session=self._agent_session_require(user,sid)
        try:body=await request.json() if request.can_read_body else {}
        except (ValueError,TypeError):body=None
        if not isinstance(body,dict) or any(key!="stop" for key in body) or type(body.get("stop",False)) is not bool:
            return _json({"ok":False,"error":"invalid_delete_request"},400)
        result=self._duty().request_delete(sid,actor=user["username"],stop=body.get("stop",False))
        if not result.get("ok"):return _json(result,409)
        if result.get("deleted") and getattr(self,"agent_tui",None):
            try:
                await self.agent_tui.release_viewport(sid,"session_deleted")
            except Exception:
                log.warning("viewport release on delete failed sid=%s",sid)
        if result.get("pending") and session.get("remote_session_id") and getattr(self,"mimo_serve",None):
            try:
                await self.mimo_serve.client().abort(session["remote_session_id"])
                result["stop_requested"]=True
            except Exception:
                result.update(stop_requested=False,message="删除请求已保存，停止尚未确认；会话将在结果核对后移除。")
        return _json(result,202 if result.get("pending") else 200)

    async def api_agent_session_copy_text(self, request: web.Request) -> web.Response:
        user=self._require_auth(request)
        sid=request.match_info.get("sid") or ""
        session=self._agent_session_require(user,sid)
        rid=session.get("remote_session_id")
        if not rid or not getattr(self,"mimo_serve",None):
            return _json({"ok":False,"error":"no_assistant_result","message":"会话还没有可复制的原生回复。"},409)
        try:
            messages=await self.mimo_serve.client().messages(rid,limit=100)
            assistants=[m for m in messages if isinstance(m,dict) and (m.get("info") or {}).get("role")=="assistant"]
            assistants.sort(key=lambda m:((m.get("info") or {}).get("time") or {}).get("created",0))
            text=""
            for message in reversed(assistants):
                text="\n".join(p.get("text","") for p in message.get("parts",[]) if isinstance(p,dict) and p.get("type")=="text" and isinstance(p.get("text"),str)).strip()
                if text:break
            if not text:return _json({"ok":False,"error":"no_assistant_result","message":"尚无可复制的回复正文。"},409)
            if len(text.encode("utf-8"))>256*1024:
                return _json({"ok":False,"error":"copy_text_too_large","message":"回复过长，请选择需要的部分复制。"},413)
            admin=getattr(self,"mimo_admin",None)
            if admin is not None:text=admin.redactor()(text)
            return _json({"ok":True,"text":text,"source":"latest_assistant"})
        except Exception:
            return _json({"ok":False,"error":"copy_unavailable","message":"暂时无法读取回复，可选择终端文字复制。"},502)

    async def api_agent_session_permissions(self, request: web.Request) -> web.Response:
        user = self._require_admin(request)
        self._check_csrf(request, user)
        sid = request.match_info.get("sid") or ""
        session = self._agent_session_require(user, sid, control=True)
        if session.get("status") != "open":
            return _json({"ok": False, "error": "session_archived"}, 409)
        try:
            body = await request.json()
        except (ValueError, TypeError):
            body = None
        if (not isinstance(body, dict) or not isinstance(body.get("connection_id"), str)
                or type(body.get("revision")) is not int
                or not any(key in body for key in ("access_mode", "approval_mode"))
                or any(key not in ("connection_id", "revision", "access_mode", "approval_mode") for key in body)
                or ("access_mode" in body and body["access_mode"] not in ("readonly", "readwrite"))
                or ("approval_mode" in body and body["approval_mode"] not in ("manual", "automatic"))):
            return _json({"ok": False, "error": "invalid_permissions"}, 400)
        manager = getattr(self, "agent_tui", None)
        if manager is None:
            return self._agent_runtime_failure()
        try:
            result = manager.change_permissions(sid, user["username"], body["connection_id"],
                access_mode=body.get("access_mode"), approval_mode=body.get("approval_mode"),
                expected_revision=body["revision"])
            return _json(result)
        except Exception as error:
            from .agent_authority import resolve_authority
            return _json({"ok": False, "error": getattr(error, "code", "permissions_unavailable"),
                "message": "权限切换未生效，请确认当前窗口仍持有控制权后重试。",
                "effective_permissions": resolve_authority(self.db, sid)}, 409)

    async def ws_agent_terminal(self, request: web.Request) -> web.StreamResponse:
        # Upgrade only after authentication, Origin and complete session ACL.
        user = self._require_auth(request)
        origin = request.headers.get("Origin", "")
        if not origin or not _origin_allowed(origin, request.headers.get("Host", "")):
            raise web.HTTPForbidden(text="origin rejected")
        sid = str(request.rel_url.query.get("session_id") or "")
        self._agent_session_require(user, sid)
        manager = getattr(self, "agent_tui", None)
        if not manager: return self._agent_runtime_failure()
        async def authorize():
            current = self._session(request)
            return bool(current and current.get("username") == user.get("username") and self._agent_session_visible(current, self._duty().get(sid)))
        return await manager.websocket(request, sid, authorize=authorize, username=user["username"])

    async def api_agent_sessions(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        duty = self._duty()
        if not duty:
            return _json({"ok": False, "error": "duty_unavailable"}, 503)
        status = str(request.rel_url.query.get("status") or "").strip()
        origin = str(request.rel_url.query.get("origin") or "").strip()
        limit = min(100, int(request.rel_url.query.get("limit") or 50))
        rows = duty.list_sessions(status=status, origin=origin, limit=limit)
        out = []
        for r in rows:
            if not self._agent_session_visible(sess, r):
                continue
            incs = duty.incidents(r.get("id") or "")
            open_n = sum(1 for i in incs if (i.get("status") or "") == "open")
            out.append({
                "id": r.get("id"),
                "title": r.get("title") or "",
                "origin": r.get("origin") or "auto",
                "status": r.get("status") or "open",
                "created_at": r.get("created_at") or 0,
                "updated_at": r.get("updated_at") or 0,
                "last_activity_at": r.get("last_activity_at") or 0,
                "archive_due_at": r.get("archive_due_at") or 0,
                "archived_at": r.get("archived_at") or 0,
                "remote_status": r.get("remote_status") or "none",
                "incident_count": len(incs),
                "open_incident_count": open_n,
                "paused_at":r.get("paused_at") or 0,
                "delete_requested_at":r.get("delete_requested_at") or 0,
                **duty.task_info(r["id"]),
            })
        return _json({"ok": True, "sessions": out, "settings": duty.settings()})

    async def api_agent_session_create(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        duty = self._duty()
        if not duty:
            return _json({"ok": False, "error": "duty_unavailable"}, 503)
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        title = str(body.get("title") or "").strip()
        prompt = str(body.get("prompt") or "").strip()
        res = duty.create(origin="manual", title=title, created_by=sess.get("username") or "web", prompt=prompt)
        self.db.audit("web_user", sess["username"], "agent_session_create",
                      detail={"session_id": res.get("session_id"), "title": title}, channel="web")
        return _json(res)

    async def api_agent_session_detail(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        duty = self._duty()
        sid = request.match_info.get("sid") or ""
        if not duty:
            return _json({"ok": False, "error": "duty_unavailable"}, 503)
        s = self._agent_session_require(sess, sid)
        incs = duty.incidents(sid)
        msgs = duty.messages(sid, limit=200)
        events = duty.events(sid, limit=100)
        pending_writes = []
        try:
            bridge = self._bridge()
            if bridge:
                pending_writes = bridge.list_pending_writes(limit=20)
                pending_writes = [w for w in pending_writes if w.get("session_id") == sid]
        except Exception:
            pending_writes = []
        pending_actions = []
        try:
            pending_actions = [
                dict(r) for r in self.db.query(
                    "SELECT id, incident_id, asset_id, object_id, capability, state, mode,"
                    " proposer_type, proposer_id, reason, created_at, approval_deadline"
                    " FROM actions WHERE state='proposed' ORDER BY created_at DESC LIMIT 20"
                )
            ]
        except Exception:
            pending_actions = []
        linked = {row["incident_id"] for row in incs}
        pending_actions = [row for row in pending_actions if row.get("incident_id") in linked]
        task=duty.task_info(sid)
        return _json({
            "ok": True,
            "session": s,
            "incidents": incs,
            "messages": msgs,
            "events": events,
            "pending_writes": pending_writes,
            "pending_actions": pending_actions,
            "can_prepare": bool(sess.get("is_admin")),
            "can_control": bool(sess.get("is_admin") and s.get("status") == "open" and not s.get("delete_requested_at")),
            **task,
            "can_recover":bool(sess.get("is_admin") and task["can_recover"]),
            "can_delete":bool(sess.get("is_admin") and not task["deletion_blockers"] and not s.get("delete_requested_at")),
            "can_request_delete":bool(sess.get("is_admin") and not s.get("deleted_at")),
            "effective_permissions": resolve_authority(self.db, sid),
            "runtime": (await self.agent_tui.status(sid)).get("binding") if getattr(self, "agent_tui", None) else None,
        })

    async def api_agent_session_prompt(self, request: web.Request) -> web.Response:
        import uuid
        user=self._require_admin(request);self._check_csrf(request,user)
        sid=request.match_info.get("sid") or ""
        self._agent_session_require(user,sid,control=True)
        try:body=await request.json()
        except (ValueError,TypeError):body=None
        if not isinstance(body,dict) or not isinstance(body.get("prompt"),str) or not 0<len(body["prompt"].strip())<=20000:
            return _json({"ok":False,"error":"prompt_required"},400)
        manager=getattr(self,"agent_tui",None)
        if manager is None:return self._agent_runtime_failure()
        connection=body.get("connection_id")
        if not isinstance(connection,str) or not manager._has_control(sid,user["username"],connection,renew=True):
            return _json({"ok":False,"error":"control_required","message":"请在当前会话取得控制权后发送。"},409)
        try:
            ready=await self._agent_remote_ready(sid);rid=ready["remote_session_id"]
            _,receipt=await manager._submit_prompt(sid,rid,"/session/"+rid+"/prompt_async",{"parts":[{"type":"text","text":body["prompt"].strip()}],"agent":ready["agent"],"messageID":"msg_"+uuid.uuid4().hex},origin="manual_api")
            return _json({"ok":True,"accepted":True,"session_id":sid,"remote_session_id":rid,"receipt":receipt},202)
        except Exception as error:
            code=getattr(error,"code","submission_unconfirmed")
            return _json({"ok":False,"error":code,"message":str(error)},503 if code=="native_backend_unavailable" else 409)

    async def api_agent_session_abort(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        duty = self._duty()
        sid = request.match_info.get("sid") or ""
        if not duty:
            return _json({"ok": False, "error": "unavailable"}, 503)
        s = self._agent_session_require(sess, sid, control=True)
        serve = getattr(self, "mimo_serve", None)
        remote_id = (s.get("remote_session_id") or "").strip()
        if not serve or not remote_id:
            return _json({"ok": False, "error": "no_remote_session"}, 400)
        try:
            duty.pause_session(sid,actor=sess["username"],reason="user_stop")
            duty.interrupt_business_work(sid,actor=sess["username"])
            await serve.client().abort(remote_id)
        except Exception as e:  # noqa: BLE001
            return _json({"ok": False, "error": "abort_failed", "message": str(e)[:200]}, 502)
        duty.record_event(sid, type="aborted", title="用户停止")
        self.db.audit("web_user", sess["username"], "agent_session_abort",
                      detail={"session_id": sid}, channel="web")
        return _json({"ok": True, "session_id": sid})

    async def api_agent_events(self, request: web.Request) -> web.Response:
        """实时事件轮询：after=unix_ts 增量。前端 1s 轮询即可获得流式体验。"""
        user = self._require_auth(request)
        after = float(request.rel_url.query.get("after") or 0)
        sess_filter = str(request.rel_url.query.get("session_id") or "").strip()
        permitted = {}
        for row in self.db.query("SELECT * FROM duty_sessions WHERE remote_session_id<>''"):
            session = dict(row)
            if self._agent_session_visible(user, session):
                permitted[session["remote_session_id"]] = session["id"]
        live = []
        fn = getattr(self, "mimo_events", None)
        if callable(fn):
            try:
                live = fn() or []
            except Exception:
                live = []
        out = []
        for ev in live:
            try:
                ts = float(ev.get("at") or 0)
            except Exception:
                ts = 0
            if ts <= after:
                continue
            remote = str(ev.get("session_id") or "")
            if remote not in permitted:
                continue
            if sess_filter and sess_filter not in (remote, permitted[remote]):
                continue
            out.append(ev)
        return _json({"ok": True, "events": out[-80:], "server_time": time.time()})

    async def api_agent_serve_status(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        serve = getattr(self, "mimo_serve", None)
        if not serve:
            return _json({"ok": False, "error": "not_configured"})
        try:
            h = await serve.client().health()
        except Exception as e:  # noqa: BLE001
            h = {"ok": False, "error": str(e)[:120]}
        return _json({"ok": True, "base_url": serve.base_url, "health": h})

    async def api_agent_session_archive(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        duty = self._duty()
        sid = request.match_info.get("sid") or ""
        if not duty:
            return _json({"ok": False, "error": "duty_unavailable"}, 503)
        self._agent_session_require(sess, sid, control=True)
        res = duty.archive_session(sid, reason="manual")
        self.db.audit("web_user", sess["username"], "agent_session_archive",
                      detail={"session_id": sid}, channel="web")
        return _json(res)

    async def api_agent_session_events(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        duty = self._duty()
        sid = request.match_info.get("sid") or ""
        if not duty:
            return _json({"ok": False, "error": "duty_unavailable"}, 503)
        self._agent_session_require(sess, sid)
        after_id = int(request.rel_url.query.get("after_id") or 0)
        events = duty.events(sid, after_id=after_id, limit=100)
        return _json({"ok": True, "events": events})

    async def api_agent_settings_get(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        duty = self._duty()
        if not duty:
            return _json({"ok": False, "error": "duty_unavailable"}, 503)
        settings = duty.settings()
        ssh_accounts = []
        ssh_roles=[]
        try:
            if self.ssh_store:
                ssh_roles=self.ssh_store.list_roles()
                for ep in self.ssh_store.list_endpoints():
                    ssh_accounts.append({
                        "asset_id": ep.get("asset_id"),
                        "role": ep.get("role"),
                        "username": ep.get("username"),
                        "credential_id": ep.get("credential_id"),
                        "enabled": bool(ep.get("enabled")),
                        "host": ep.get("host"),
                    })
        except Exception:
            ssh_accounts = []
        return _json({"ok": True, "settings": settings, "ssh_endpoints": ssh_accounts,"ssh_roles":ssh_roles})

    async def api_agent_settings_post(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        duty = self._duty()
        if not duty:
            return _json({"ok": False, "error": "duty_unavailable"}, 503)
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json"}, 400)
        allowed = {
            "require_human_approval",
            "auto_access_mode",
            "auto_approval_mode",
            "archive_delay_sec",
            "ssh_investigate_role",
            "ssh_execute_role",
        }
        changed = {}
        actor = sess.get("username") or "web"
        for key, value in body.items():
            if key not in allowed:
                continue
            if key == "require_human_approval":
                if type(value) is not bool:
                    return _json({"ok": False, "error": "boolean_required", "field": key}, 400)
                val = "1" if value else "0"
            elif key in ("auto_access_mode", "auto_approval_mode"):
                options = ("readonly", "readwrite") if key == "auto_access_mode" else ("manual", "automatic")
                if value not in options:
                    return _json({"ok": False, "error": "invalid_permission_mode", "field": key}, 400)
                val = value
            elif key == "archive_delay_sec":
                if type(value) is not int or not 30 <= value <= 3600:
                    return _json({"ok": False, "error": "invalid_archive_delay", "field": key}, 400)
                val = str(value)
            else:
                if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
                    return _json({"ok": False, "error": "invalid_credential_role", "field": key}, 400)
                store=getattr(self,"ssh_store",None)
                if store is not None and value not in {role["name"] for role in store.list_roles()}:
                    return _json({"ok":False,"error":"ssh_role_not_found","field":key,"message":"请选择已配置的 SSH 角色。"},400)
                val = str(value)
            changed[key] = val
        if ("require_human_approval" in changed and "auto_approval_mode" in changed
                and (changed["require_human_approval"] == "1") != (changed["auto_approval_mode"] == "manual")):
            return _json({"ok": False, "error": "conflicting_approval_modes"}, 400)
        duty.set_settings(changed, actor=actor)
        self.db.audit("web_user", actor, "agent_settings_saved",
                      detail={"changed": changed}, channel="web")
        return _json({"ok": True, "changed": changed, "settings": duty.settings()})

    async def api_agent_pending_writes(self, request: web.Request) -> web.Response:
        user = self._require_auth(request)
        bridge = self._bridge()
        if not bridge:
            return _json({"ok": False, "error": "bridge_unavailable"}, 503)
        visible = self._visible_asset_ids(user)
        pending = [row for row in bridge.list_pending_writes(limit=50)
                   if row.get("target") in visible or (row.get("session_id") and self._agent_session_visible(user, self._duty().get(row["session_id"])))]
        return _json({"ok": True, "pending": pending})

    async def api_agent_pending_approve(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        bridge = self._bridge()
        if not bridge:
            return _json({"ok": False, "error": "bridge_unavailable"}, 503)
        try:
            body = await request.json()
        except Exception:
            body = {}
        inc_id = str((body or {}).get("incident_id") or "").strip()
        action_key = str((body or {}).get("action_key") or "").strip()
        if not inc_id or not action_key:
            return _json({"ok": False, "error": "incident_id_and_action_key_required"}, 400)
        approved = bridge.approve_pending_write(inc_id, action_key, approved_by=sess.get("username") or "web")
        if not approved.get("ok"):
            return _json(approved, 400)
        params = approved.get("params") or {}
        command = str(params.get("command") or "")
        channel = str(params.get("channel") or "write")
        timeout = params.get("timeout")
        try:
            timeout_f = float(timeout) if timeout is not None else None
        except (TypeError, ValueError):
            timeout_f = None
        result: dict[str, Any] = {"approved": True}
        row = self.db.query_one(
            "SELECT target, result FROM session_write_ops WHERE incident_id=? AND action_key=?",
            (inc_id, action_key),
        )
        asset_id = (row["target"] if row else "") or ""
        authority_sid = str(params.get("_ayana_session_id") or "")
        if params.get("_ayana_tool"):
            try:
                from .mcp_tools import OpsContext, OpsTools
                from .transport import session_dispatch_guard
                context = OpsContext(db=self.db, transport=self.transport, prom=self.prom,
                    incidents=self.incidents, knowledge=bridge.knowledge, session_bridge=bridge,
                    actions=self.actions, promconfig=getattr(self,"promconfig",None),
                    ops_loop=getattr(self,"ops_loop",None), constraints=getattr(self,"ops_constraints",None))
                with session_dispatch_guard(self.db, authority_sid):
                    out = await OpsTools(context).call_approved(str(params["_ayana_tool"]),
                        params.get("_ayana_arguments") or {}, authority_session_id=authority_sid)
                bridge.complete_write(inc_id,action_key,ok=out.get("ok",True),result=json.dumps(out,default=str))
                result.update({"exec_state":"success" if out.get("ok",True) else "failed","tool_result":out})
            except Exception as error:
                if getattr(error,"dispatch_not_started",False):
                    bridge.release_write(inc_id,action_key,confirmed_safe=True,reason=error.code)
                else:
                    bridge.mark_unknown(inc_id,action_key,reason=type(error).__name__)
                result.update({"exec_state":"rejected" if getattr(error,"dispatch_not_started",False) else "unknown", "exec_error":getattr(error,"code","tool_failed")})
        elif command and asset_id and self.transport is not None:
            try:
                from .actions import classify_exec_result
                from .transport import session_dispatch_guard
                with session_dispatch_guard(self.db, authority_sid,asset_id=asset_id):
                    res = await self.transport.exec_shell(asset_id, command, timeout_f, channel=channel)
                state, detail = classify_exec_result(res)
                if state == "unknown":
                    bridge.mark_unknown(inc_id, action_key, reason=detail or "unknown")
                else:
                    bridge.complete_write(inc_id, action_key, ok=(state == "success"), result=(detail or "")[:500])
                result.update({"exec_state": state, "detail": (detail or "")[:300]})
            except Exception as e:  # noqa: BLE001
                if getattr(e,"dispatch_not_started",False):
                    bridge.release_write(inc_id,action_key,confirmed_safe=True,reason=e.code)
                else:
                    bridge.mark_unknown(inc_id, action_key, reason=str(e)[:120])
                result["exec_error"] = str(e)[:200]
        else:
            # 无命令参数：仅批准状态，调用方稍后执行
            result["note"] = "approved_without_inline_exec"
        self.db.audit("web_user", sess["username"], "pending_write_approved",
                      detail={"incident_id": inc_id, "action_key": action_key, "result": result}, channel="web")
        return _json({"ok": True, **result})

    async def api_agent_pending_reject(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        bridge = self._bridge()
        if not bridge:
            return _json({"ok": False, "error": "bridge_unavailable"}, 503)
        try:
            body = await request.json()
        except Exception:
            body = {}
        inc_id = str((body or {}).get("incident_id") or "").strip()
        action_key = str((body or {}).get("action_key") or "").strip()
        reason = str((body or {}).get("reason") or "human_rejected")
        if not inc_id or not action_key:
            return _json({"ok": False, "error": "incident_id_and_action_key_required"}, 400)
        res = bridge.reject_pending_write(inc_id, action_key, reason=reason)
        self.db.audit("web_user", sess["username"], "pending_write_rejected",
                      detail={"incident_id": inc_id, "action_key": action_key}, channel="web")
        return _json(res)

    async def api_agent_pending_actions(self, request: web.Request) -> web.Response:
        user = self._require_auth(request)
        rows = self.db.query(
            "SELECT id, incident_id, asset_id, object_id, capability, state, mode,"
            " proposer_type, proposer_id, reason, created_at, approval_deadline, params_json"
            " FROM actions WHERE state='proposed' ORDER BY created_at DESC LIMIT 50"
        )
        visible = self._visible_asset_ids(user)
        return _json({"ok": True, "actions": [dict(r) for r in rows if r["asset_id"] in visible]})

    async def api_executions(self, request: web.Request) -> web.Response:
        """统一查询 actions + session_write_ops（关联 Incident/资产）。"""
        sess = self._require_auth(request)
        inc_id = str(request.rel_url.query.get("incident_id") or "").strip()
        limit = min(200, int(request.rel_url.query.get("limit") or 50))
        where = " WHERE incident_id=?" if inc_id else ""
        params = (inc_id,) if inc_id else ()
        actions = [
            dict(r)
            for r in self.db.query(
                f"SELECT id, incident_id, asset_id, object_id, capability, state, mode,"
                f" proposer_type, proposer_id, created_at, finished_at, result_detail"
                f" FROM actions{where} ORDER BY created_at DESC LIMIT ?",
                (*params, limit),
            )
        ]
        try:
            wops = [
                dict(r)
                for r in self.db.query(
                    f"SELECT id, incident_id, session_id, action_key, status, result,"
                    f" target, claimed_by, created_at, updated_at FROM session_write_ops{where}"
                    f" ORDER BY created_at DESC LIMIT ?",
                    (*params, limit),
                )
            ]
        except Exception:
            wops = []
        visible = self._visible_asset_ids(sess)
        return _json({"ok": True, "actions": [row for row in actions if row.get("asset_id") in visible],
                      "session_write_ops": [row for row in wops if row.get("target") in visible]})

    # ---- business api ----

    async def api_overview(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        from .business import host_health_view, native_check_items

        # 短缓存：避免前端连点/轮询把 Prom 探测打满（Windows 连接拒绝约 2s/次）
        now_ts = time.time()
        visible = self._visible_asset_ids(sess)
        cache = getattr(self, "_overview_cache", None)
        if cache and cache.get("visible") == visible and (now_ts - cache["at"]) < 5.0:
            return _json(cache["data"])

        assets_raw = [row for row in self.db.query("SELECT * FROM assets ORDER BY id") if row["id"] in visible]
        open_inc = [incident for incident in self.incidents.list_incidents(status="open", limit=50) if incident.get("asset_id") in visible]
        open_by_asset = {}
        for i in open_inc:
            aid = i.get("asset_id") or ""
            open_by_asset[aid] = open_by_asset.get(aid, 0) + 1

        # Share the actual samples/selectors and native freshness with resources.
        results = await asyncio.gather(*(self._prom_business_items(dict(asset)) for asset in assets_raw))
        business_map = {asset["id"]: result[0] for asset, result in zip(assets_raw, results)}
        host_status = await self.host_monitor.hosts_status([dict(asset) for asset in assets_raw]) if self.host_monitor else []
        host_map = {item["asset_id"]: item for item in host_status}
        native_rows = [dict(row) for row in self.db.query("SELECT asset_id,last_state,last_at,interval_sec FROM checks WHERE enabled=1")
                       if row["asset_id"] in visible]
        native_items = native_check_items(native_rows)
        firing_by_asset = self._monitor_firing()

        assets = []
        for a in assets_raw:
            d = dict(a)
            d["objects"] = [
                dict(o)
                for o in self.db.query("SELECT * FROM objects WHERE asset_id=?", (a["id"],))
            ]
            prom_items = business_map.get(a["id"], [])
            native = [item for item in native_items if item["asset_id"] == a["id"]]
            metric = host_map.get(a["id"], {})
            view = host_health_view(
                prom_items=prom_items,
                native_states=[item["state"] for item in native],
                metric_state=metric.get("state", ""),
                metric_error=metric.get("error", ""),
                firing_severities=firing_by_asset.get(a["id"], []),
            )
            d["health"] = view["health"]
            d["health_dot"] = view["health_dot"]
            d["business_summary"] = view["business_summary"]
            d["probe"] = {"state": view["health"].get("state", "unknown")}
            assets.append(d)
        need = [i for i in open_inc if i.get("need_human")]
        actions = [action for action in self.actions.list_actions(limit=50)
                   if action.get("asset_id") in visible][:10]
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

        metric_items = [{"state": item["state"], "object": item["name"], "asset": aid}
                        for aid, items in business_map.items() for item in items]
        check_items = [{"state": item["state"]} for item in native_items]

        # 告警状态：单项状态（当前有 firing → 0/1；无 → 1/1）
        # 不把每条历史未结案事件算进来；只反映「此刻告警面是否干净」
        alert_items: list[dict] = []
        try:
            n_firing = sum(1 for row in self.db.query(
                "SELECT asset_id FROM alert_episodes WHERE status='firing'"
                " AND (source_state IS NULL OR source_state='firing')"
            ) if row["asset_id"] in visible)
            # Absence of alerts is not a successful observation.
            if n_firing or metric_items or check_items:
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
            "node_watch": self.nodewatch.overview_summary() if self.nodewatch else {"level": "off", "peers": []},
        }
        self._overview_cache = {"at": time.time(), "visible": visible, "data": data}
        return _json(data)

    def _visible_asset_ids(self, sess: dict) -> set[str]:
        """S10: 返回调用者有 asset.summary 权限的资产 ID 集合。admin 见全部。"""
        if not sess:
            return set()
        username = sess.get("username") or ""
        if username == "admin" or sess.get("is_admin"):
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

    @staticmethod
    def _is_sample_asset(row: Any) -> bool:
        """播种示例资产：demo-* 且未配置真实主机地址。"""
        if row is None:
            return False
        if isinstance(row, dict):
            aid = str(row.get("id") or "")
            host = str(row.get("host") or "").strip()
        else:
            try:
                aid = str(row["id"] or "")
                host = str(row["host"] or "").strip()
            except (KeyError, IndexError, TypeError):
                return False
        return aid.startswith("demo-") and not host

    @staticmethod
    def _monitor_not_onboarded(overview: dict) -> bool:
        """监控未接入：连接失败/无样本，而不是采集器装好后故障。"""
        state = (overview or {}).get("state") or ""
        if state in ("no_data", "not_configured"):
            return True
        return False

    def _meta_get(self, key: str) -> str:
        row = self.db.query_one("SELECT value FROM meta WHERE key=?", (key,))
        return str(row["value"]) if row and row["value"] is not None else ""

    def _meta_set(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def _asset_monitor_host(self, asset: dict, endpoints: list[dict] | None = None) -> str:
        """Resolve the monitoring host from current asset/connection configuration."""
        for key in ("monitor_host", "host"):
            host = str(asset.get(key) or "").strip()
            if host:
                return host
        store = self.ssh_store
        if store is None:
            try:
                store = self._ssh_store()
            except Exception:
                store = None
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
        sess = self._require_auth(request)
        asset_id = request.match_info["asset_id"]
        if asset_id not in self._visible_asset_ids(sess):
            return _json({"ok": False, "error": "permission_denied"}, 403)
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
        data["incidents"] = [inc for inc in self.incidents.list_incidents()
                             if inc.get("asset_id") == asset_id][:5]
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
        sess = self._require_auth(request)
        limit = int(request.rel_url.query.get("limit", "50"))
        loops = self.incidents.list_closed_loops(limit=limit)
        visible = self._visible_asset_ids(sess)
        loops = [loop for loop in loops if loop.get("asset_id") in visible]
        return _json({"ok": True, "loops": loops})

    async def api_incident_detail(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        inc_id = request.match_info["inc_id"]
        inc = self.incidents.get_incident(inc_id)
        if not inc:
            return _json({"ok": False, "error": "not_found"}, 404)
        if inc.get("asset_id") not in self._visible_asset_ids(sess):
            return _json({"ok": False, "error": "permission_denied"}, 403)
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
            "council": await self._council_snapshot(inc_id),
        })

    async def _council_snapshot(self, inc_id: str) -> dict:
        try:
            snapshot = self.legacy_history.snapshot(inc_id)
            if not isinstance(snapshot, dict):
                raise ValueError("invalid history snapshot")
            return snapshot
        except Exception:
            log.warning("legacy autonomy history unavailable for incident %s", inc_id)
            return {
                "enabled": False, "retired": True, "read_only": True,
                "status": "unavailable", "error": "legacy_history_unavailable",
            }

    def _council_visible_incident(self, request: web.Request, sess: dict) -> dict | web.Response:
        inc = self.incidents.get_incident(request.match_info["inc_id"])
        if not inc:
            return _json({"ok": False, "error": "not_found"}, 404)
        if inc.get("asset_id") not in self._visible_asset_ids(sess):
            return _json({"ok": False, "error": "permission_denied"}, 403)
        return inc

    async def api_incident_council(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        inc = self._council_visible_incident(request, sess)
        if isinstance(inc, web.Response):
            return inc
        return _json({"ok": True, "council": await self._council_snapshot(inc["id"])})

    async def api_autonomy_providers(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        return _json({
            "ok": True, "config": self.legacy_history.public_config(),
            "available": False, "retired": True, "read_only": True,
        })

    async def api_autonomy_providers_save(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        return _legacy_autonomy_retired()

    async def api_autonomy_usage(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        return _json({
            "ok": True, "usage": self.legacy_history.usage_summary(),
            "retired": True, "read_only": True,
        })

    async def api_autonomy_provider_verify(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        return _legacy_autonomy_retired()

    async def api_council_manual_review(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        inc = self._council_visible_incident(request, sess)
        if isinstance(inc, web.Response):
            return inc
        return _legacy_autonomy_retired()

    def _incident_disposition(self, inc: dict) -> dict:
        """P1-01：事件详情处置上下文（服务端求值，前端不重算 Policy）。"""
        from .fmt import ZH_CAP

        actions_list = inc.get("actions") or []
        pending = [a for a in actions_list if a.get("state") in ("proposed", "approved")
                   and a.get("mode") != "reviewed" and not a.get("council_grant_id")]
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
        from .fmt import ZH_CAP, ZH_EVENT, ZH_STAGE, ZH_STATE, ZH_STATUS, alert_name, readable_reason

        timeline = []
        # 默认优先保证最新事件可见（接口 desc 返回，此处取最新 8 条再正序展示）
        events = list(inc.get("events") or [])
        latest = events[:8] if events else []
        for e in reversed(latest):
            timeline.append({
                "time": e.get("at"),
                "label": ZH_EVENT.get(e.get("type", ""), e.get("title", "")),
                "type": e.get("type", ""),
            })

        what = alert_name(inc.get("title", ""))
        why_human = inc.get("need_human_reason", "")
        zh_reason = readable_reason(why_human) if why_human else ""
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
            elif "action_rejected" in why_human:
                suggestion = "本轮已跳过处置；目标恢复或开始新一轮故障后重新评估"
            else:
                suggestion = "查看详情后决定下一步"
        elif inc.get("status") == "open":
            suggestion = "系统正在处理，稍候刷新"

        automation_wait = None
        if inc.get("status") == "open" and inc.get("stage") == "watching" and not inc.get("need_human"):
            last_created = max((float(a.get("created_at") or 0) for a in inc.get("actions") or []), default=0)
            for event in events:
                if event.get("type") != "agent_waiting" or float(event.get("at") or 0) < last_created:
                    continue
                try:
                    waiting = json.loads(event.get("payload_json") or "{}")
                    if int(waiting.get("generation") or 1) != int(inc.get("generation") or 1):
                        continue
                    automation_wait = {"reason": readable_reason(str(waiting.get("reason") or "")), "retry_at": waiting.get("retry_at")}
                except (TypeError, ValueError, AttributeError):
                    pass
                break

        return {
            "title": what,
            "status_zh": ZH_STATUS.get(inc.get("status"), inc.get("status")),
            "stage_zh": ZH_STAGE.get(inc.get("stage"), inc.get("stage")),
            "why_human": zh_reason if inc.get("need_human") else "",
            "suggestion": suggestion,
            "automation_wait": automation_wait,
            "timeline": timeline,
            "last_action": {
                "capability_zh": ZH_CAP.get(cap, cap),
                "state_zh": ZH_STATE.get((action or {}).get("state", ""), ""),
            } if action else None,
        }

    async def api_incident_close(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        inc_id = request.match_info["inc_id"]
        inc = self.incidents.get_incident(inc_id)
        if not inc:
            return _json({"ok": False, "error": "not_found"}, 404)
        if inc.get("asset_id") not in self._visible_asset_ids(sess):
            return _json({"ok": False, "error": "permission_denied"}, 403)
        body = await request.json()
        reason = body.get("reason", "人工关闭")
        # P0-04：closed ≠ recovered，不伪造 resolved_at
        res = self.incidents.close_manual(
            inc_id, reason, actor=sess["username"], policy=self.policy,
            actor_type="web_user", is_admin=bool(sess.get("is_admin")),
        )
        if not res.get("ok"):
            status = 403 if res.get("error") == "permission_denied" else 404
            return _json({"ok": False, "error": res.get("error", "not_found")}, status)
        self.db.audit(
            "web_user", sess["username"], "incident_closed",
            asset_id=inc.get("asset_id") or "", object_id=inc_id,
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
        sess = self._require_auth(request)
        data = self.actions.get_action(request.match_info["aid"])
        if not data:
            return _json({"ok": False, "error": "not_found"}, 404)
        if data.get("asset_id") not in self._visible_asset_ids(sess):
            return _json({"ok": False, "error": "permission_denied"}, 403)
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
        try:
            totp_ok = self.auth.verify_totp(username, code)
        except AuthError as e:
            self.db.audit("web_user", username, "sensitive_totp_locked")
            return {"ok": False, "error": e.code, "message": str(e)}
        if not totp_ok:
            self.db.audit("web_user", username, "sensitive_totp_failed")
            return {"ok": False, "error": "totp_invalid"}
        self.db.audit("web_user", username, "sensitive_totp_ok")
        return None

    async def api_action_decision(self, request: web.Request) -> web.Response:
        """事件详情三选项；一次授权与长期授权共享对象和权限校验。"""
        from .fmt import approval_error
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
        except (ValueError, TypeError):
            return _json({"ok": False, "error": "invalid_json", "message": "请求格式错误"}, 400)
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "invalid_json", "message": "请求格式错误"}, 400)
        decision = body.get("decision")
        if decision not in ("execute_once", "reject", "allow_always"):
            return _json({"ok": False, "error": "invalid_decision", "message": "请选择执行一次、不执行或永久允许执行"}, 400)
        if decision != "reject":
            mfa_err = self._sensitive_totp(sess, body)
            if mfa_err:
                return _json(mfa_err, 401)
        try:
            result = await ApprovalService(self.actions).decide(
                decision, action_id=request.match_info["aid"],
                actor_type="web_user", actor_id=sess["username"], channel="web",
                is_admin=bool(sess.get("is_admin")), reason=str(body.get("reason") or ""),
            )
        except ActionError as e:
            return _json({"ok": False, "error": e.code, "message": approval_error(e.code)}, 400)
        return _json({"ok": True, **result})

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
                res = await ApprovalService(self.actions).decide(
                    "execute_once", action_id=request.match_info["aid"],
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
            res = await ApprovalService(self.actions).decide(
                "reject", action_id=request.match_info["aid"],
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
        action = self.actions.get_action(request.match_info["aid"])
        if not action:
            return _json({"ok": False, "error": "not_found"}, 404)
        if action.get("asset_id") not in self._visible_asset_ids(sess):
            return _json({"ok": False, "error": "permission_denied"}, 403)
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

    def _validate_permission_fields(self, sess: dict, fields: Any) -> dict:
        from . import formspec
        from .capabilities import list_capabilities
        result = formspec.validate_fields("permissions", fields, assets=self._assist_assets(sess),
                                          capabilities=list_capabilities(), partial=False)
        values = result["fields"]
        if values.get("scope") == "default" and (values.get("asset_id") or values.get("object_id", "*") != "*"):
            result["issues"].append({"field": "scope", "label": "范围", "code": "bad_scope",
                                      "message": "指定主机或对象的授权需要填写资产例外，请明确适用范围。"})
            result["valid"] = False
        result["ok"] = result["valid"]
        result["payload"] = None
        if result["valid"]:
            state = values["state"]
            result["payload"] = {"subject_type": "auto_rule", "subject_id": "agent", "capability": values["capability"],
                                 "asset_id": "*" if values["scope"] == "default" else values["asset_id"],
                                 "object_id": values.get("object_id", "*"), "allow": state != "deny",
                                 "require_approval": state != "auto", "auto_allowed": state == "auto"}
        result["message"] = "配置校验通过，请核对并确认保存。" if result["valid"] else "授权配置尚未完整或未通过校验，请核对提示。"
        return result

    async def api_permission_validate(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json", "message": "提交内容无法读取，请重新填写。"}, 400)
        if not isinstance(body, dict) or set(body) != {"fields"}:
            return _json({"ok": False, "error": "bad_fields", "message": "请提交需要校验的授权表单字段。"}, 400)
        return _json(self._validate_permission_fields(sess, body["fields"]))

    async def api_permission_upsert(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json", "message": "提交内容无法读取，请重新填写。"}, 400)
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_fields", "message": "授权配置内容的格式不正确。"}, 400)
        if body.get("subject_type") == "auto_rule" and body.get("subject_id") == "agent":
            for flag in ("allow", "require_approval", "auto_allowed"):
                if flag in body and not isinstance(body[flag], bool):
                    return _json({"ok": False, "error": "bad_state", "message": "请选择禁止、人工确认或允许执行中的一种策略。"}, 400)
            allow, approval, auto = body.get("allow", True), body.get("require_approval", True), body.get("auto_allowed", False)
            if allow and not approval and not auto:
                return _json({"ok": False, "error": "bad_state", "message": "允许执行的策略需要选择人工确认或自动执行。"}, 400)
            if allow and approval and auto:
                return _json({"ok": False, "error": "bad_state", "message": "人工确认和自动执行不能同时选择。"}, 400)
            asset_id = body.get("asset_id", "*")
            fields = {"capability": body.get("capability"), "state": "deny" if not allow else "confirm" if approval else "auto",
                      "scope": "default" if asset_id in ("", "*") else "exception", "object_id": body.get("object_id", "*")}
            if fields["scope"] == "exception":
                fields["asset_id"] = asset_id
            validated = self._validate_permission_fields(sess, fields)
            if not validated["valid"]:
                return _json(validated, 400)
            body = validated["payload"]
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
            return _json({"ok": False, "error": str(e), "message": "授权未能保存，请核对操作、适用范围及当前账号权限。"}, 400)
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
        return _legacy_autonomy_retired()

    async def api_agent_ceiling_set(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        return _legacy_autonomy_retired()

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

    async def api_notify_aibot_admins(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        cid = str(request.rel_url.query.get("channel_id") or "")
        store = self._channels()
        channel = store.get_meta(cid)
        if not channel or channel.get("kind") != "wecom_aibot":
            return _json({"ok": False, "error": "not_found", "detail": "智能机器人渠道不存在"}, 404)
        return _json({"ok": True, "users": store.list_seen_users(cid),
                      "selected": channel.get("config", {}).get("admin_user_ids") or []})

    async def api_notify_aibot_admins_save(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("admin_user_ids"), list):
            return _json({"ok": False, "error": "bad_admin_user_ids", "detail": "请选择成员 UserID，或留空"}, 400)
        try:
            channel = self._channels().set_admin_user_ids(
                str(body.get("id") or ""), body["admin_user_ids"], actor=sess["username"],
            )
        except Exception as exc:
            return _json({"ok": False, "error": getattr(exc, "code", "error"), "detail": str(exc)}, 400)
        return _json({"ok": True, "channel": channel})

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

    # ---- 节点守望 ----

    async def api_node_watch_heartbeat(self, request: web.Request) -> web.Response:
        """对端心跳入口：HMAC 自鉴权，不走管理员会话。"""
        if not self.nodewatch:
            return _json({"ok": False, "error": "disabled"}, 503)
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json"}, 400)
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json"}, 400)
        res = self.nodewatch.handle_heartbeat(body)
        return _json(res, 200 if res.get("ok") else 400)

    async def api_node_watch_status(self, request: web.Request) -> web.Response:
        self._require_admin(request)
        if not self.nodewatch:
            return _json({"ok": True, "enabled": False, "status": {}})
        return _json({"ok": True, "enabled": True, "status": self.nodewatch.status()})

    async def api_node_watch_send_test(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        if not self.nodewatch:
            return _json({"ok": False, "error": "disabled"}, 503)
        res = await self.nodewatch.send_once()
        return _json(res)

    def _nw(self):
        if not self.nodewatch:
            raise web.HTTPNotFound(text="nodewatch not configured")
        return self.nodewatch

    async def api_node_watch_invite_generate(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        nw = self._nw()
        body = await request.json() if request.can_read_body else {}
        if not isinstance(body, dict):
            body = {}
        node_id = str(body.get("node_id") or "").strip()
        url = str(body.get("url") or "").strip()
        if not url:
            # 默认用当前请求推断接收地址
            url = f"http://{request.host}/api/node-watch/heartbeat"
        try:
            ttl = float(body.get("ttl_sec") or 600)
        except (TypeError, ValueError):
            ttl = 600.0
        rotate = bool(body.get("rotate", True))
        res = nw.generate_invite(node_id=node_id, url=url, ttl_sec=ttl, rotate=rotate)
        code = 200 if res.get("ok") else 400
        return _json(res, code)

    async def api_node_watch_invite_parse(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        nw = self._nw()
        body = await request.json()
        res = nw.parse_invite_text(str((body or {}).get("invite") or ""))
        return _json(res, 200 if res.get("ok") else 400)

    async def api_node_watch_invite_apply(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        nw = self._nw()
        body = await request.json()
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json"}, 400)
        interval_raw = body.get("interval_sec")
        interval_sec = None
        if interval_raw is not None and str(interval_raw).strip() != "":
            try:
                interval_sec = float(interval_raw)
            except (TypeError, ValueError):
                return _json({"ok": False, "error": "bad_interval_sec"}, 400)
        res = nw.apply_invite(
            str(body.get("invite") or ""),
            expected_fp=str(body.get("fp") or ""),
            interval_sec=interval_sec,
        )
        return _json(res, 200 if res.get("ok") else 400)

    async def api_node_watch_settings(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        nw = self._nw()
        body = await request.json() if request.can_read_body else {}
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json"}, 400)
        kwargs: dict = {}
        if "interval_sec" in body and body.get("interval_sec") is not None:
            try:
                kwargs["interval_sec"] = float(body.get("interval_sec"))
            except (TypeError, ValueError):
                return _json({"ok": False, "error": "bad_interval_sec"}, 400)
        if "timeout_sec" in body and body.get("timeout_sec") is not None:
            try:
                kwargs["timeout_sec"] = float(body.get("timeout_sec"))
            except (TypeError, ValueError):
                return _json({"ok": False, "error": "bad_timeout_sec"}, 400)
        if "public_base_url" in body:
            kwargs["public_base_url"] = body.get("public_base_url") or ""
        res = nw.update_settings(**kwargs)
        return _json(res, 200 if res.get("ok") else 400)

    # ---- 主机资源监控 ----

    def _monitor(self):
        if not self.host_monitor:
            raise web.HTTPNotFound(text="host_monitor not configured")
        return self.host_monitor

    async def _prom_business_items(self, asset: dict) -> tuple[list[dict], list[dict]]:
        from .business import prometheus_checks

        key = (asset["id"], asset.get("prom_asset") or asset["id"])
        cache = getattr(self, "_business_cache", {})
        cached = cache.get(key)
        if cached and time.time() - cached[0] < 5:
            return cached[1]
        result = await prometheus_checks(self.prom, asset)
        cache[key] = (time.time(), result)
        self._business_cache = {entry: value for entry, value in cache.items() if time.time() - value[0] < 5}
        return result

    def _native_business_states(self, asset_id: str) -> list[str]:
        from .business import native_check_items

        rows = self.db.query("SELECT last_state,last_at,interval_sec FROM checks WHERE asset_id=? AND enabled=1", (asset_id,))
        return [item["state"] for item in native_check_items([dict(row) for row in rows])]

    def _monitor_firing(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for episode in self.db.query("SELECT asset_id,labels_json FROM alert_episodes WHERE status='firing' AND (source_state IS NULL OR source_state='firing')"):
            try:
                labels = json.loads(episode["labels_json"] or "{}")
            except (TypeError, ValueError):
                labels = {}
            severity = str(labels.get("severity") or "warning").lower()
            out.setdefault(str(episode["asset_id"] or ""), []).append(severity)
        return out

    async def api_monitor_business(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        asset_id = request.match_info["asset_id"]
        row = self.db.query_one("SELECT id,display_name,prom_asset FROM assets WHERE id=?", (asset_id,))
        if not row:
            return _json({"ok": False, "error": "not_found", "message": "这台主机已不存在，请重新选择。"}, 404)
        if asset_id not in self._visible_asset_ids(sess):
            return _json({"ok": False, "error": "denied", "message": "当前账户不能查看这台主机。"}, 403)
        items, errors = [], []
        probe_allowed = self.policy.check(subject_type="web_user", subject_id=sess["username"],
                                          capability="probe.status", asset_id=asset_id, object_id="*")["allowed"]
        if probe_allowed:
            prom_items, prom_errors = await self._prom_business_items(dict(row))
            items.extend(prom_items)
            errors.extend(prom_errors)
        else:
            errors.append({"source": "prometheus", "message": "当前账户没有查看 Prometheus 业务检查的权限。"})
        try:
            self._check_read(request)
        except web.HTTPForbidden:
            errors.append({"source": "ayana", "message": "当前账户没有查看原生业务检查的权限。"})
        else:
            try:
                from .business import native_check_items

                items.extend(native_check_items(self._checks().list_checks(asset_id)))
            except Exception:
                errors.append({"source": "ayana", "message": "暂时无法获取原生业务检查，请稍后刷新。"})
        return _json({"ok": True, "asset": dict(row), "items": items, "errors": errors})

    async def api_monitor_hosts(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        from .business import host_health_view

        rows = self.db.query(
            "SELECT id, display_name, prom_asset, enabled FROM assets ORDER BY id ASC"
        )
        visible = self._visible_asset_ids(sess)
        assets = [dict(r) for r in rows if r["id"] in visible]
        try:
            status = await self._monitor().hosts_status(assets)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

        # 统一健康：指标 + required checks + 业务检查 + 当前 firing（不吸收历史未结案）
        by_id = {s.get("asset_id"): s for s in status}
        firing_by_asset = self._monitor_firing()

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

            prom_items, _ = await self._prom_business_items(a)
            try:
                native_states = self._native_business_states(aid)
            except Exception:
                native_states = []
            view = host_health_view(
                prom_items=prom_items,
                native_states=native_states,
                metric_state=metric_state,
                metric_error=metric_error,
                firing_severities=firing_by_asset.get(aid, []),
            )
            hh = view["health_dot"]
            item["health"] = hh
            item["metric_state"] = metric_state
            item["state"] = hh["state"]  # 对外五态
            item["firing"] = view["firing"]
            item["host"] = a.get("host") or ""
            item["sample"] = self._is_sample_asset(a)
            out.append(item)
        return _json({"ok": True, "hosts": out})

    async def api_monitor_host(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        asset_id = request.match_info["asset_id"]
        range_key = request.rel_url.query.get("range", "1h")
        # 与 _visible_asset_ids 一致：admin 全部可见；其余走 asset.summary
        if sess.get("is_admin") or sess.get("username") == "admin":
            pass
        else:
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
            "SELECT id, display_name, prom_asset, host FROM assets WHERE id=?", (asset_id,)
        )
        if not row:
            return _json({"ok": False, "error": "not_found"}, 404)
        prom_asset = row["prom_asset"] or asset_id
        try:
            overview = await self._monitor().host_overview(prom_asset)
            history = await self._monitor().host_history(prom_asset, range_key)
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)
        from .business import host_health_view

        prom_items, _ = await self._prom_business_items(dict(row))
        try:
            native_states = self._native_business_states(asset_id)
        except Exception:
            native_states = []
        view = host_health_view(
            prom_items=prom_items,
            native_states=native_states,
            metric_state=overview.get("state", ""),
            metric_error=overview.get("error", ""),
            firing_severities=self._monitor_firing().get(asset_id, []),
        )
        health = view["health_dot"]
        # 示例资产 / 未接入监控：明确区分，不伪装成采集故障
        sample = self._is_sample_asset(row)
        not_onboarded = self._monitor_not_onboarded(overview)
        return _json(
            {
                "ok": True,
                "asset": dict(row),
                "overview": overview,
                "history": history,
                "health": health,
                "sample": sample,
                "monitor_not_configured": not_onboarded,
                "prometheus_url": getattr(self.prom, "base_url", ""),
            }
        )

    # ---- SSH 资产 / 凭据（v0.4.1）----

    def _ssh_store(self):
        # 统一入口：优先显式 ssh_store，回退 transport 内嵌 store；都没有则 None。
        # （原先此处与文件末尾各有一份同名方法，后者遮蔽前者，已合并为「可空返回」语义，
        #   与合并前实际生效版本一致；需要 404 的调用方用 _require_ssh_store。）
        if self.ssh_store is not None:
            return self.ssh_store
        store = getattr(self.transport, "store", None)
        if store is None:
            store = getattr(self.transport, "_store", None)
        return store

    def _require_ssh_store(self):
        store = self._ssh_store()
        if store is None:
            raise web.HTTPNotFound(text="ssh_store not configured")
        return store

    def _cred_store(self):
        if not self.cred_store:
            raise web.HTTPNotFound(text="cred_store not configured")
        return self.cred_store

    async def api_ssh_roles(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        return _json({"ok": True, "roles": self._require_ssh_store().list_roles()})

    async def api_ssh_role_add(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            role = self._require_ssh_store().add_role(
                name=body["name"],
                kind=body.get("kind") or "read",
                label=body.get("label") or "",
                actor=sess["username"],
            )
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 400)
        return _json({"ok": True, "role": role})

    async def api_ssh_endpoints(self, request: web.Request) -> web.Response:
        sess = self._require_auth(request)
        asset_id = request.rel_url.query.get("asset_id", "")
        visible = self._visible_asset_ids(sess)
        if asset_id and asset_id not in visible:
            return _json({"ok": False, "error": "permission_denied"}, 403)
        endpoints = [ep for ep in self._require_ssh_store().list_endpoints(asset_id)
                     if ep.get("asset_id") in visible]
        return _json({"ok": True, "endpoints": endpoints})

    async def api_ssh_endpoint_upsert(self, request: web.Request) -> web.Response:
        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json()
        try:
            ep = self._require_ssh_store().upsert_endpoint(
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
            ep = self._require_ssh_store().trust_host_key(
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
            self._require_ssh_store().delete_endpoint(
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
        # P4.2：远端认证变更必须显式确认，防止误触重复下发
        if not body.get("confirm"):
            return _json(
                {"ok": False, "error": "confirm_required", "hint": "set confirm=true"},
                400,
            )
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
                detail={
                    "ok": res.get("ok"),
                    "host": body.get("host"),
                    "already_present": res.get("already_present", False),
                },
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
            eps = self._require_ssh_store().list_endpoints(asset_id)
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
            ep = self._require_ssh_store().get_endpoint(asset_id, role) or ep
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
                tr = SSHTransport(self._require_ssh_store(), self._cred_store())
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
        if origin and host_hdr and not _origin_allowed(origin, host_hdr):
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
                cur = self._session(request)
                err = self._terminal_ok(cur, asset_id)
                if not cur or cur.get("username") != username or err:
                    await ws.send_json({"type": "error", "error": "permission_revoked", "hint": "终端授权已失效"})
                    self.terminal.close(sid, username=username, reason="permission_revoked")
                    await ws.close(code=4403, message=b"permission revoked")
                    break
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
                err = self._terminal_ok(cur, asset_id)
                if err:
                    await ws.send_json({"type": "error", "error": "permission_revoked", "hint": "终端授权已失效"})
                    await ws.close(code=4403, message=b"permission revoked")
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
        return _legacy_autonomy_retired()

    async def api_agent_status(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        from .runbook import list_runbook

        return _json({
            "ok": True, "retired": True, "read_only": True,
            "auto_enabled": False, "enabled": False, "llm_enabled": False,
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

    def _require_cap(
        self,
        sess: dict[str, Any],
        capability: str,
        *,
        admin: bool = False,
        respect_deny: bool = True,
        no_approval: bool = True,
        asset_id: str = "*",
        object_id: str = "*",
        deny_body: dict | None = None,
        admin_body: dict | None = None,
        approval_body: dict | None = None,
    ) -> dict[str, Any]:
        """统一能力门（P2-2）。

        admin=True          → 必须管理员（否则 admin_required）
        respect_deny=True   → 显式 deny 不因 admin 绕过（promconfig 语义）
        respect_deny=False  → admin 可读绕过 deny（checks.read 历史语义）
        no_approval=True    → require_approval 视为不可直接提交
        返回 policy 判定；失败抛 HTTPForbidden。不得放宽权限。
        """
        if admin and not sess.get("is_admin"):
            raise web.HTTPForbidden(
                text=json.dumps(admin_body or {"error": "admin_required"}),
                content_type="application/json",
            )
        d = self.policy.effective_decision(
            subject_type="web_user",
            subject_id=sess["username"],
            capability=capability,
            asset_id=asset_id,
            object_id=object_id,
        )
        if not d["allowed"]:
            # respect_deny=True：显式 deny 连 admin 也不绕过
            # respect_deny=False：admin 可读（历史 _check_read 语义）
            if respect_deny or not sess.get("is_admin"):
                body = deny_body or {"error": "denied", "reason": d.get("reason")}
                raise web.HTTPForbidden(
                    text=json.dumps(body), content_type="application/json"
                )
            return d
        if no_approval and d.get("require_approval"):
            body = approval_body or {
                "error": "approval_required",
                "require_approval": True,
            }
            raise web.HTTPForbidden(
                text=json.dumps(body), content_type="application/json"
            )
        return d

    def _check_read(self, request: web.Request) -> dict[str, Any]:
        sess = self._require_auth(request)
        # admin 拥有管理台读权限；其余用户需显式 checks.read
        self._require_cap(
            sess,
            "checks.read",
            admin=False,
            respect_deny=False,
            deny_body={
                "ok": False,
                "error": "denied",
                "message": "当前账户没有查看业务检查的权限，请联系管理员授权。",
            },
        )
        return sess

    def _check_write(self, request: web.Request) -> dict[str, Any]:
        sess = self._require_auth(request)
        self._check_csrf(request, sess)
        self._require_cap(
            sess,
            "checks.write",
            admin=True,
            respect_deny=True,
            no_approval=True,
            admin_body={
                "error": "admin_required",
                "message": "创建或修改业务检查需要管理员权限。",
            },
            deny_body={
                "error": "denied",
                "message": "当前策略禁止修改业务检查，请先调整授权。",
            },
            approval_body={
                "error": "approval_required",
                "message": "修改业务检查需要审批，当前页面不能直接提交。",
            },
        )
        return sess

    @staticmethod
    def _check_form_error(exc: Exception) -> web.Response:
        issues = getattr(exc, "issues", [])
        message = (issues[0].get("message") if issues else None) or getattr(exc, "detail", "")
        if not message:
            message = {"not_found": "这项检查已不存在，请刷新后重试。"}.get(
                getattr(exc, "code", ""), "配置未能保存，请检查表单内容并重试。")
        return _json({"ok": False, "error": getattr(exc, "code", "validation_failed"),
                      "message": message, "issues": issues}, 400)

    def _validate_check_body(self, sess: dict, body: dict) -> dict:
        from .formspec import validate_fields, validate_check_payload

        assets = self._assist_assets(sess)
        if "fields" in body:
            return validate_fields("checks", body["fields"], assets=assets, partial=False)
        return validate_check_payload(body, assets=assets)

    async def api_checks_validate(self, request: web.Request) -> web.Response:
        """Validate and adapt the real form before user confirmation; never save or execute."""
        sess = self._check_read(request)
        self._check_csrf(request, sess)
        try:
            body = await request.json()
            if not isinstance(body, dict):
                raise ValueError("body")
        except Exception:
            return _json({"ok": False, "error": "bad_json", "message": "表单内容无法读取，请重新填写。"}, 400)
        result = self._validate_check_body(sess, body)
        return _json({"ok": result["valid"], "fields": result["fields"], "payload": result["payload"],
                      "issues": result["issues"], "missing": result["missing"], "defaulted": result["defaulted"],
                      "message": "表单校验通过，请核对后确认创建。" if result["valid"] else "配置还不完整或存在错误，请根据提示修改。"})

    async def api_checks_list(self, request: web.Request) -> web.Response:
        self._check_read(request)
        asset_id = request.rel_url.query.get("asset_id", "")
        try:
            return _json({"ok": True, "checks": self._checks().list_checks(asset_id)})
        except Exception as e:
            return _json({"ok": False, "error": str(e)}, 502)

    async def api_checks_create(self, request: web.Request) -> web.Response:
        sess = self._check_write(request)
        try:
            body = await request.json()
            if not isinstance(body, dict):
                return _json({"ok": False, "error": "bad_input", "message": "表单内容格式不正确。"}, 400)
            result = self._validate_check_body(sess, body)
            if not result["valid"]:
                return _json({"ok": False, "error": "validation_failed", "message": "请修改表单中标出的内容后再创建。",
                              "issues": result["issues"], "missing": result["missing"]}, 400)
            item = self._checks().create_check(**result["payload"], actor=sess["username"])
            return _json({"ok": True, "check": item})
        except Exception as e:
            return self._check_form_error(e)

    async def api_checks_update(self, request: web.Request) -> web.Response:
        sess = self._check_write(request)
        try:
            body = await request.json()
            if not isinstance(body, dict):
                return _json({"ok": False, "error": "bad_input", "message": "表单内容格式不正确。"}, 400)
            if set(body) - {"id", "name", "params", "expect", "interval_sec", "fail_threshold", "severity", "enabled"}:
                return _json({"ok": False, "error": "unknown_field", "message": "更新内容包含当前表单不支持的配置项。"}, 400)
            fields = {k: body[k] for k in ("name", "params", "expect", "interval_sec", "fail_threshold", "severity", "enabled") if k in body}
            item = self._checks().update_check(body.get("id") or "", actor=sess["username"], **fields)
            return _json({"ok": True, "check": item})
        except Exception as e:
            return self._check_form_error(e)

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
        self._require_cap(
            sess,
            "promconfig.write",
            admin=True,
            respect_deny=True,
            no_approval=True,
            asset_id=asset_id,
        )
        return sess

    def _check_prom_read(self, request: web.Request) -> dict[str, Any]:
        sess = self._require_auth(request)
        # 尊重显式 deny，不因 admin 绕过
        self._require_cap(
            sess,
            "promconfig.read",
            admin=False,
            respect_deny=True,
            no_approval=False,
        )
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

    # ---- 外部事务 ----

    def _ext(self):
        if not self.exttx:
            raise web.HTTPNotFound(text=json.dumps({"error": "exttx_disabled"}))
        return self.exttx

    async def api_ext_report(self, request: web.Request) -> web.Response:
        """外部上报入口：独立 Token，无会话权限。"""
        from .exttx import ExtTxError

        svc = self._ext()
        auth = request.headers.get("Authorization", "")
        raw = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not raw:
            raw = request.headers.get("X-Ext-Token", "").strip()
        try:
            who = svc.authenticate_token(raw)
        except ExtTxError as e:
            return _json({"ok": False, "error": e.code}, 401)
        try:
            body = await request.json()
        except Exception:
            return _json({"ok": False, "error": "bad_json"}, 400)
        if not isinstance(body, dict):
            return _json({"ok": False, "error": "bad_json"}, 400)
        body_key = str(body.get("event_key") or "").strip()
        if body_key and body_key != who["event_key"]:
            self.db.audit(
                "ext_token", who["token_id"], "ext_report_denied",
                detail={"event_key": body_key[:40], "hint": who.get("token_hint", "")},
            )
            return _json({"ok": False, "error": "event_key_mismatch"}, 403)
        try:
            res = svc.report(
                body,
                token_hint=who.get("token_hint", ""),
                received_at=now(),
            )
        except ExtTxError as e:
            return _json({"ok": False, "error": e.code, "detail": e.detail}, 400)
        return _json(res)

    async def api_ext_transactions(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        return _json({"ok": True, "transactions": self._ext().list_transactions()})

    async def api_ext_transaction_create(self, request: web.Request) -> web.Response:
        from .exttx import ExtTxError

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json() if request.can_read_body else {}
        if not isinstance(body, dict):
            body = {}
        try:
            tx = self._ext().create_transaction(body, actor=sess.get("username", ""))
        except ExtTxError as e:
            return _json({"ok": False, "error": e.code, "detail": e.detail}, 400)
        return _json({"ok": True, "transaction": tx})

    async def api_ext_transaction_update(self, request: web.Request) -> web.Response:
        from .exttx import ExtTxError

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json() if request.can_read_body else {}
        if not isinstance(body, dict):
            body = {}
        try:
            tx = self._ext().update_transaction(
                request.match_info["tid"], body, actor=sess.get("username", "")
            )
        except ExtTxError as e:
            code = 404 if e.code == "not_found" else 400
            return _json({"ok": False, "error": e.code, "detail": e.detail}, code)
        return _json({"ok": True, "transaction": tx})

    async def api_ext_transaction_enabled(self, request: web.Request) -> web.Response:
        from .exttx import ExtTxError

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json() if request.can_read_body else {}
        if not isinstance(body, dict):
            body = {}
        try:
            tx = self._ext().set_enabled(
                request.match_info["tid"],
                bool(body.get("enabled", True)),
                actor=sess.get("username", ""),
            )
        except ExtTxError as e:
            code = 404 if e.code == "not_found" else 400
            return _json({"ok": False, "error": e.code, "detail": e.detail}, code)
        return _json({"ok": True, "transaction": tx})

    async def api_ext_transaction_delete(self, request: web.Request) -> web.Response:
        from .exttx import ExtTxError

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        try:
            res = self._ext().delete_transaction(
                request.match_info["tid"], actor=sess.get("username", "")
            )
        except ExtTxError as e:
            code = 404 if e.code == "not_found" else 400
            return _json({"ok": False, "error": e.code, "detail": e.detail}, code)
        return _json(res)

    async def api_ext_token_issue(self, request: web.Request) -> web.Response:
        from .exttx import ExtTxError

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        try:
            res = self._ext().issue_token(
                request.match_info["tid"], actor=sess.get("username", "")
            )
        except ExtTxError as e:
            code = 404 if e.code == "not_found" else 400
            return _json({"ok": False, "error": e.code, "detail": e.detail}, code)
        return _json(res)

    async def api_ext_token_rotate(self, request: web.Request) -> web.Response:
        from .exttx import ExtTxError

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        body = await request.json() if request.can_read_body else {}
        if not isinstance(body, dict):
            body = {}
        old_id = str(body.get("old_token_id") or "").strip()
        try:
            res = self._ext().rotate_token(
                request.match_info["tid"], old_id, actor=sess.get("username", "")
            )
        except ExtTxError as e:
            code = 404 if e.code == "not_found" else 400
            return _json({"ok": False, "error": e.code, "detail": e.detail}, code)
        return _json(res)

    async def api_ext_token_revoke(self, request: web.Request) -> web.Response:
        from .exttx import ExtTxError

        sess = self._require_admin(request)
        self._check_csrf(request, sess)
        try:
            res = self._ext().revoke_token(
                request.match_info["token_id"], actor=sess.get("username", "")
            )
        except ExtTxError as e:
            code = 404 if e.code == "not_found" else 400
            return _json({"ok": False, "error": e.code, "detail": e.detail}, code)
        return _json(res)

    async def api_ext_runs(self, request: web.Request) -> web.Response:
        self._require_auth(request)
        q = request.rel_url.query
        try:
            limit = int(q.get("limit", "50"))
        except ValueError:
            limit = 50
        runs = self._ext().list_runs(request.match_info["tid"], limit=limit)
        return _json({"ok": True, "runs": runs})
