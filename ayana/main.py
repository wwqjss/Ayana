"""Ayana 入口：装配业务服务、Web、OneBot、后台任务。"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path

from aiohttp import web

from . import VERSION
from .actions import ActionService
from .agent_query import AgentQueryService
from .alertmanager import AlertIngest
from .auth import AuthService
from .config import load_config
from .controlled import ControlledExecutor
from .db import Database, now
from .incidents import IncidentService
from .auto_investigate import AutoInvestigator, InvestConfig
from .session_bridge import SessionBridge
from .investigation import InvestigationService
from .instance import acquire_single_instance_lock
from .knowledge import KnowledgeBase
from .llm import make_llm
from .ntsafe import AssetBinding, IdentityGate, NTClient
from .notify import Notifier
from .notify_channels import ChannelStore
from .monitor import HostMonitor
from .wecom_aibot import WeComAibotManager
from .wecom_bot import WeComBot
from .messagelog import MessageLog
from .onewbot import OneBotServer
from .permission_change import PermissionChangeService
from .policy import Policy
from .prom import PromClient
from .promconfig import build_prom_config_service
from .checks import CheckService
from .exttx import ExtTxService
from .qqbot import QQBot
from .credentials import CredentialStore
from .transport import SSHAssetStore, SSHTransport
from .terminal import TerminalService
from .web import WebApp

log = logging.getLogger("ayana")

# 示例资产（首次空库播种）。公开版不含真实主机地址；请在 Web「连接」页登记实际资产。
DEFAULT_ASSETS = [
    {
        "id": "demo-web",
        "display_name": "Demo Web",
        "read_alias": "demo-web",
        "write_alias": "demo-web-exec",
        "expected_host_id": "DEMO-WEB",
        "prom_asset": "demo-web",
        "host": "",
        "objects": [
            {"kind": "service", "name": "nginx", "unit": "nginx"},
            {"kind": "port", "name": "http-80", "port": 80, "protocol": "tcp"},
        ],
    },
    {
        "id": "demo-db",
        "display_name": "Demo DB",
        "read_alias": "demo-db",
        "write_alias": "demo-db-exec",
        "expected_host_id": "DEMO-DB",
        "prom_asset": "demo-db",
        "host": "",
        "objects": [
            {"kind": "container", "name": "postgres", "container": "postgres"},
        ],
    },
]


def setup_logging(level: str, log_file: str | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
    )


def seed_assets(db: Database) -> None:
    row = db.query_one("SELECT COUNT(*) AS n FROM assets")
    if row and row["n"] > 0:
        return
    t = now()
    for a in DEFAULT_ASSETS:
        db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " prom_asset, host, enabled, notes, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,1,'',?,?)",
            (
                a["id"],
                a["display_name"],
                a["read_alias"],
                a["write_alias"],
                a["expected_host_id"],
                a["prom_asset"],
                a.get("host") or "",
                t,
                t,
            ),
        )
        for o in a.get("objects") or []:
            db.execute(
                "INSERT INTO objects(id, asset_id, kind, name, unit, container, port, protocol,"
                " external_probe, auto_recover, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    f"{a['id']}:{o['kind']}:{o['name']}",
                    a["id"],
                    o["kind"],
                    o["name"],
                    o.get("unit", ""),
                    o.get("container", ""),
                    o.get("port"),
                    o.get("protocol", ""),
                    o.get("external_probe", ""),
                    int(o.get("auto_recover", 0)),
                    t,
                ),
            )
    db.audit("system", "seed", "assets_seeded")
    # 知识正文在 knowledge/*.md；此处仅建索引可重建，不再写 object_knowledge 正文
    # auto_rule 基础权限：只读调查 + runbook 执行
    from .policy import Policy

    policy = Policy(db)
    policy.upsert_permission(
        subject_type="auto_rule", subject_id="agent", capability="asset.summary",
        asset_id="*", object_id="*", allow=True, require_approval=False, auto_allowed=False, actor="system",
    )
    for cap in ("service.restart", "service.start", "service.stop"):
        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability=cap,
            asset_id="*", object_id="*", allow=True, require_approval=False,
            auto_allowed=True, actor="system",
        )
    # 人工 Web 终端：仅 admin；Agent 不可（policy 层硬拦）。S02: 不再通配给所有 web 用户
    policy.upsert_permission(
        subject_type="web_user", subject_id="admin", capability="shell.interactive",
        asset_id="*", object_id="*", allow=True, require_approval=False, auto_allowed=False, actor="system",
    )
    for cap in ("checks.read", "checks.write"):
        row = db.query_one(
            "SELECT id FROM permissions WHERE subject_type='web_user' AND subject_id='admin'"
            " AND capability=? AND asset_id='*' AND object_id='*'",
            (cap,),
        )
        if not row:
            policy.upsert_permission(
                subject_type="web_user", subject_id="admin", capability=cap,
                asset_id="*", object_id="*", allow=True, require_approval=False,
                auto_allowed=False, actor="system",
            )


def ensure_checks_admin_perms(db: Database) -> None:
    """已有库升级：补齐 admin 的 checks.* 种子（不覆盖已有决定）。"""
    from .policy import Policy

    policy = Policy(db)
    for cap in ("checks.read", "checks.write"):
        row = db.query_one(
            "SELECT id FROM permissions WHERE subject_type='web_user' AND subject_id='admin'"
            " AND capability=? AND asset_id='*' AND object_id='*'",
            (cap,),
        )
        if row:
            continue
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability=cap,
            asset_id="*", object_id="*", allow=True, require_approval=False,
            auto_allowed=False, actor="system",
        )


def ensure_promconfig_admin_perms(db: Database) -> None:
    """已有库升级：仅为缺失的 admin 权限插入种子，不覆盖已有决定。

    监控只读能力（asset.summary / probe.status）与 promconfig / node_exporter
    一并补齐：admin 是初始运维账号，资源详情与业务检查只读必须可用。
    """
    from .policy import Policy

    policy = Policy(db)
    for cap in (
        "asset.summary",
        "probe.status",
        "promconfig.read",
        "promconfig.write",
        "node_exporter.status",
        "node_exporter.manage",
    ):
        row = db.query_one(
            "SELECT id, allow, require_approval FROM permissions"
            " WHERE subject_type='web_user' AND subject_id='admin' AND capability=?"
            " AND asset_id='*' AND object_id='*'",
            (cap,),
        )
        if row:
            continue
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability=cap,
            asset_id="*", object_id="*", allow=True, require_approval=False,
            auto_allowed=False, actor="system",
        )


def load_bindings(db: Database) -> list[AssetBinding]:
    out = []
    for r in db.query("SELECT * FROM assets WHERE enabled=1"):
        out.append(
            AssetBinding(
                asset_id=r["id"],
                read_alias=r["read_alias"],
                write_alias=r["write_alias"],
                expected_host_id=r["expected_host_id"] or "",
                host_id_verified_at=r["host_id_verified_at"],
            )
        )
    return out


class App:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.db = Database(cfg["db_path"])
        import os
        log.info("db path resolved to: %s (base_dir=%s) cwd=%s abs=%s",
                 self.db.path, cfg.get("base_dir", ""), os.getcwd(), os.path.abspath(self.db.path))
        seed_assets(self.db)
        dedicated = str(cfg.get("web_auth_pepper") or "")
        onewbot = str(cfg.get("onewbot_token") or "")
        pepper = dedicated or onewbot
        legacy: list[str] = []
        if dedicated and onewbot and dedicated != onewbot:
            # 专用 pepper：历史哈希可能用 onewbot_token，登录成功后自动迁移
            legacy = [onewbot]
        if not dedicated:
            log.warning(
                "web_auth_pepper not set; falling back to onewbot_token for password pepper. "
                "Set AYANA_WEB_AUTH_PEPPER to a dedicated secret."
            )
        self.auth = AuthService(
            self.db,
            pepper=pepper,
            session_ttl=int(cfg.get("web_session_ttl_sec", 43200)),
            max_failed=int(cfg.get("web_max_failed_logins", 8)),
            lockout=int(cfg.get("web_lockout_sec", 900)),
            totp_key=cfg.get("totp_encrypt_key") or "",
            legacy_peppers=legacy,
        )
        self.policy = Policy(self.db)
        self.nt = NTClient(privilege_mode="restricted_dispatcher")
        self.gate = IdentityGate(self.nt, load_bindings(self.db))
        self.knowledge = KnowledgeBase(self.db)
        self.prom = PromClient(cfg.get("prometheus_url", "http://127.0.0.1:9090"))
        # 首登/设置页写入的运行时覆盖（DB meta），优先于 config.json
        try:
            _prow = self.db.query_one("SELECT value FROM meta WHERE key='prometheus_url'")
            if _prow and str(_prow["value"] or "").strip():
                self.prom.base_url = str(_prow["value"]).strip().rstrip("/")
                log.info("prometheus_url overridden from meta: %s", self.prom.base_url)
        except Exception as e:
            log.warning("load prometheus_url meta failed: %s", e)
        self.incidents = IncidentService(self.db)
        # 工作台：值班/手动会话生命周期
        from .duty_session import DutySessionManager

        self.duty = DutySessionManager(self.db)
        # P2 薄桥：只做映射/复用/幂等，不做自动处置（旧自治仍禁用）
        self.session_bridge = SessionBridge(self.db, knowledge=self.knowledge, duty=self.duty)
        self.incidents.session_bridge = self.session_bridge
        # P6.2: one verified provider and one MCP/DB binding for all runtime clients.
        from .mimo_admin import MimoAdmin
        from .mimo_session import MimoSessionClient

        _ai_cfg = InvestConfig.from_dict(cfg.get("auto_investigate") or {})
        _code_root = str(Path(__file__).resolve().parents[1])
        _config_base = str(Path(cfg.get("base_dir") or _code_root).resolve())
        self.mimo_admin = MimoAdmin(
            mimo_bin=str(cfg.get("mimo_bin") or _ai_cfg.mimo_bin or "mimo"),
            workdir=str(cfg.get("mimo_workdir") or _code_root),
            serve_url=str(cfg.get("mimo_serve_url") or ""),
            unit_name=str(cfg.get("mimo_unit") or ""),
        )

        def _mimo_runtime():
            runtime = self.mimo_admin.runtime_configuration(self.db)
            overlay = dict(runtime.get("config") or {})
            overlay["mcp"] = {
                **(overlay.get("mcp") or {}),
                "ayana": {
                    "type": "local", "enabled": True,
                    "command": [sys.executable, "-m", "ayana.mcp_server", _config_base],
                    "environment": {
                        "AYANA_MCP_DB_PATH": str(Path(self.db.path).resolve()),
                        "PYTHONPATH": _code_root + os.pathsep + os.environ.get("PYTHONPATH", ""),
                    },
                },
            }
            return {
                **runtime, "config": overlay,
                "environment": {
                    "AYANA_MCP_DB_PATH": str(Path(self.db.path).resolve()),
                    "PYTHONPATH": _code_root + os.pathsep + os.environ.get("PYTHONPATH", ""),
                },
            }

        def _mimo_ready():
            try:
                _mimo_runtime()
                return True
            except Exception:
                return False

        self.mimo_read_client = MimoSessionClient(
            mimo_bin=self.mimo_admin.mimo_bin, cwd=self.mimo_admin.workdir,
            readonly_env=True, default_timeout=_ai_cfg.timeout_sec,
            runtime_resolver=_mimo_runtime,
        )
        self.mimo_decision_client = MimoSessionClient(
            mimo_bin=self.mimo_admin.mimo_bin, cwd=self.mimo_admin.workdir,
            decision_only=True, default_timeout=max(_ai_cfg.decision_timeout_sec, _ai_cfg.timeout_sec),
            runtime_resolver=_mimo_runtime,
        )
        # Manual chat shares the verified read-only client rather than a no_mimo bridge.
        self.session_bridge.mimo = self.mimo_read_client
        self.auto_investigator = None
        if _ai_cfg.enabled:
            _ai_bridge = SessionBridge(self.db, knowledge=self.knowledge, mimo=self.mimo_read_client, duty=self.duty)
            self.auto_investigator = AutoInvestigator(
                self.db, knowledge=self.knowledge, mimo=self.mimo_read_client,
                bridge=_ai_bridge, config=_ai_cfg, mimo_write=self.mimo_decision_client,
                readiness_callback=_mimo_ready,
            )
            self.incidents.auto_investigator = self.auto_investigator
            log.info("auto_investigate enabled closed_loop=%s max_concurrent=%s timeout=%s",
                     _ai_cfg.closed_loop, _ai_cfg.max_concurrent, _ai_cfg.timeout_sec)
        else:
            log.info("auto_investigate disabled")
        # SSH：凭据加密 + 端点；有端点用原生 SSH，否则回落 NT（迁移期）
        self.creds = CredentialStore(self.db, master_key=cfg.get("ssh_credential_key") or "")
        self.ssh_store = SSHAssetStore(self.db)
        self.ssh_transport = SSHTransport(self.ssh_store, self.creds)
        self.terminal = TerminalService(self.db, self.ssh_store, self.creds)

        class _Router:
            """仅原生 SSH。NT 已移除。"""

            def __init__(self, ssh, store):
                self._ssh = ssh
                self._store = store

            async def probe(self, asset_id, tokens, timeout=None):
                return await self._ssh.probe(asset_id, tokens, timeout=timeout)

            async def exec(self, asset_id, tokens, timeout=None):
                return await self._ssh.exec(asset_id, tokens, timeout=timeout)

            async def send_file(self, asset_id, local_path, remote_path, *, timeout=60.0):
                """推文件（安装二进制等）。委托 SSHTransport。"""
                return await self._ssh.send_file(
                    asset_id, local_path, remote_path, timeout=timeout
                )

            def _endpoint(self, asset_id, role):
                return self._ssh._endpoint(asset_id, role)

        self.transport = _Router(self.ssh_transport, self.ssh_store)
        # S02: 不再在每次启动时恢复通配 shell.interactive；权限由 seed_assets 仅建 admin 规则
        self.investigation = InvestigationService(
            self.db, self.nt, self.gate, self.prom, self.policy,
            knowledge=self.knowledge,
            transport=self.transport,
        )
        self.actions = ActionService(
            self.db,
            self.nt,
            self.gate,
            self.policy,
            self.prom,
            transport=self.transport,
            action_ttl=int(cfg.get("action_ttl_sec", 1800)),
            verify_window=int(cfg.get("verify_window_sec", 90)),
            verify_timeout=int(cfg.get("verify_timeout_sec", 300)),
        )
        # P4.2：ActionService 与 Session 桥共用写幂等台账
        self.actions.write_ops = self.session_bridge
        from .ops_constraints import OpsConstraints
        from .ops_loop import OpsLoop, ensure_ops_loop_schema

        ensure_ops_loop_schema(self.db)
        self.ops_constraints = OpsConstraints(self.db)
        self.ops_loop = OpsLoop(
            self.db,
            actions=self.actions,
            incidents=self.incidents,
            bridge=self.session_bridge,
            constraints=self.ops_constraints,
        )
        # P6.1：把闭环依赖注入自动调查器
        if self.auto_investigator is not None:
            self.auto_investigator.ops_loop = self.ops_loop
            self.auto_investigator.actions = self.actions
            self.auto_investigator.incidents = self.incidents
        self.notifier = Notifier(self.db, default_target="")
        self.ops_loop.notifier = self.notifier
        self.alert_ingest = AlertIngest(self.db, incidents=self.incidents, notifier=self.notifier)
        self.notifier.set_default_target(
            f"user:{cfg['admin_qq']}" if cfg.get("admin_qq") else ""
        )
        self.channel_store = ChannelStore(
            self.db,
            master_key=cfg.get("notify_channel_key") or cfg.get("ssh_credential_key") or "",
        )
        self.notifier.set_channel_store(self.channel_store)
        self._node_name = str(cfg.get("node_name") or "")
        self.host_monitor = HostMonitor(self.prom)
        try:
            self.promconfig = build_prom_config_service(
                self.db, cfg, prom=self.prom, transport=self.ssh_transport
            )
        except Exception as e:
            log.warning("promconfig disabled: %s", e)
            self.promconfig = None
        self.checks = CheckService(self.db, self._checks_transport())
        self.checks.notifier = self.notifier
        self.checks.incidents = self.incidents
        self.exttx = ExtTxService(
            self.db,
            incidents=self.incidents,
            notifier=self.notifier,
            pepper=cfg.get("web_auth_pepper") or "",
        )
        self.aibot_manager = WeComAibotManager()
        self.channel_store.set_aibot_manager(self.aibot_manager)
        self.mlog = MessageLog(self.db)
        self.channel_store.set_mlog(self.mlog)
        self.llm = make_llm(cfg)
        # 节点守望：心跳收发 + 失联调查（默认关闭，配置后启用）
        try:
            from .nodewatch import NodeWatchService

            self.nodewatch = NodeWatchService(
                self.db,
                config=cfg.get("node_watch") or {},
                notifier=self.notifier,
                channel_store=self.channel_store,
                config_path=str(Path(cfg.get("base_dir") or ".") / "config.json"),
            )
        except Exception as e:
            log.warning("nodewatch disabled: %s", e)
            self.nodewatch = None
        # 全局设置（DB meta）覆盖 secrets/env 中的 LLM 配置
        try:
            for _k in ("llm_base_url", "llm_model", "llm_api_key"):
                _row = self.db.query_one("SELECT value FROM meta WHERE key=?", (_k,))
                if _row and str(_row["value"] or "").strip():
                    if _k == "llm_base_url":
                        self.llm.base_url = str(_row["value"]).strip().rstrip("/")
                    elif _k == "llm_model":
                        self.llm.model = str(_row["value"]).strip()
                    else:
                        self.llm.api_key = str(_row["value"]).strip()
            log.info(
                "llm settings: model=%s base_set=%s key_set=%s",
                self.llm.model,
                bool(self.llm.base_url),
                bool(self.llm.api_key),
            )
        except Exception as e:
            log.warning("load llm meta failed: %s", e)
        self.investigation.llm = self.llm
        # P4.4: old execution services have no runtime composition path.
        # Compatibility attributes are inert; historical data is read separately.
        self.agent = self.providers = self.council = self.autonomy = None
        self.legacy_agent_loop = False
        self.ob = OneBotServer(cfg["onewbot_token"], int(cfg.get("self_id") or 0))
        self.qq = QQBot(
            self.db,
            self.ob,
            self.incidents,
            self.investigation,
            self.actions,
            self.policy,
            self.notifier,
            admin_qq=str(cfg.get("admin_qq") or ""),
            admin_wecom_users=cfg.get("admin_wecom_users") or [],
            channel_store=self.channel_store,
            version=VERSION,
        )
        # 统一消息入口：Agent 查询 + 受控命令
        self.agent_query = AgentQueryService(self.host_monitor, self.db)
        self.controlled = ControlledExecutor(
            self.db, self.transport, self.policy, self.actions
        )
        self.qq.agent_query = self.agent_query
        self.qq.controlled = self.controlled
        self.permission_changes = PermissionChangeService(
            self.db,
            self.policy,
            totp_verifier=lambda username, code: self.auth.verify_totp(username, code),
        )
        self.webapp = WebApp(
            self.db,
            self.auth,
            self.policy,
            self.incidents,
            self.investigation,
            self.actions,
            self.prom,
            static_dir=Path(__file__).resolve().parent / "static",
            version=VERSION,
            webhook_token=cfg.get("webhook_token") or "",
            alert_ingest=self.alert_ingest,
            notifier=self.notifier,
            permission_changes=self.permission_changes,
            ssh_store=self.ssh_store,
            cred_store=self.creds,
            transport=self.transport,
            terminal=self.terminal,
            channel_store=self.channel_store,
            host_monitor=self.host_monitor,
            aibot_manager=self.aibot_manager,
            mlog=self.mlog,
            promconfig=self.promconfig,
            checks=self.checks,
            llm=self.llm,
            nodewatch=getattr(self, "nodewatch", None),
            exttx=self.exttx,
            ops_loop=self.ops_loop,
            ops_constraints=self.ops_constraints,
            mimo_admin=self.mimo_admin,
            duty=self.duty,
            session_bridge=self.session_bridge,
            alertmanager_webhook_path=cfg.get("alertmanager_webhook_path") or "/hooks/alertmanager",
        )
        self._stop = asyncio.Event()
        self._bg_tasks: list[asyncio.Task] = []

    def _checks_transport(self):
        """检查通道：统一走 transport.resolve_exec_channel（SSH 优先，仅本机资产 LocalExec）。"""
        from .ntsafe import NTResult
        from .transport import ChannelUnavailable, resolve_exec_channel

        ssh = self.ssh_transport
        local_assets: set[str] = set()
        try:
            pc = self.cfg.get("prometheus_config") or {}
            if isinstance(pc, dict):
                local_assets = {
                    str(x) for x in (pc.get("local_assets") or []) if str(x).strip()
                }
        except Exception:
            pass

        class _T:
            async def probe(self, asset_id, tokens, timeout=None):
                try:
                    ch = resolve_exec_channel(
                        asset_id, ssh, local_assets=local_assets, role="read"
                    )
                except ChannelUnavailable:
                    return NTResult(
                        ok=False,
                        output="endpoint_missing: " + str(asset_id),
                        returncode=255,
                    )
                return await ch.probe(asset_id, tokens, timeout=timeout)

            async def exec(self, asset_id, tokens, timeout=None):
                try:
                    ch = resolve_exec_channel(
                        asset_id, ssh, local_assets=local_assets, role="write"
                    )
                except ChannelUnavailable:
                    return NTResult(
                        ok=False,
                        output="endpoint_missing: " + str(asset_id),
                        returncode=255,
                    )
                return await ch.exec(asset_id, tokens, timeout=timeout)

            async def send_file(self, asset_id, local_path, remote_path, *, timeout=60.0):
                try:
                    ch = resolve_exec_channel(
                        asset_id, ssh, local_assets=local_assets, role="write"
                    )
                except ChannelUnavailable:
                    return NTResult(
                        ok=False,
                        output="endpoint_missing: " + str(asset_id),
                        returncode=255,
                    )
                return await ch.send_file(
                    asset_id, local_path, remote_path, timeout=timeout
                )

        return _T()

    def _write_bootstrap_password(self, password: str) -> None:
        """P1-05: 一次性口令文件：与 DB 同目录、O_EXCL、0600、拒符号链接。"""
        try:
            db_path = Path(self.db.path).resolve()
            pw_path = db_path.parent / "bootstrap-admin.password"
            if pw_path.is_symlink() or pw_path.exists():
                log.warning(
                    "BOOTSTRAP admin created; password file already exists or is a symlink, not overwritten: %s",
                    pw_path,
                )
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(str(pw_path), flags, 0o600)
            try:
                os.write(fd, (password + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            log.warning(
                "BOOTSTRAP admin created; one-time password file: %s (mode 600). "
                "Change password after first login and delete the file.",
                pw_path,
            )
        except Exception as e:
            log.warning(
                "BOOTSTRAP admin created but one-time password file was not written (%s). "
                "Password was not logged; reset via ops if lost.",
                type(e).__name__,
            )

    def _write_setup_token(self, token: str) -> Path | None:
        """Setup Token 文件：与 DB 同目录、O_EXCL、0600、拒符号链接。Token 不进日志。"""
        try:
            db_path = Path(self.db.path).resolve()
            tok_path = db_path.parent / "setup-admin.token"
            if tok_path.is_symlink():
                log.warning("setup token path is a symlink, not written: %s", tok_path)
                return None
            if tok_path.exists():
                # 已有未消费的 token 文件：不覆盖，便于用户仍可打开
                log.info("setup token file already exists: %s", tok_path)
                return tok_path
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(str(tok_path), flags, 0o600)
            try:
                os.write(fd, (token + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            log.warning(
                "SETUP registration open; one-time token file: %s (mode 600). "
                "Open the web console and register the admin account with this token.",
                tok_path,
            )
            return tok_path
        except Exception as e:
            log.warning("setup token file was not written (%s)", type(e).__name__)
            return None

    async def start(self) -> None:
        # 启动安全检查
        unknown = self.actions.mark_unknown_unfinished()
        if unknown:
            log.warning("marked %d dispatched actions as unknown after restart", unknown)
        backfilled = self.actions.backfill_missing_verifications()
        if backfilled:
            log.info("backfilled %d verification obligations", backfilled)
        resumed = self.actions.resume_pending_verifications()
        if resumed:
            log.info("resumed %d pending verifications", resumed)
        # 一次性 Token 注册门闩：不单凭用户数=0 开放
        try:
            setup = self.auth.ensure_setup_initialized()
            if setup.get("token"):
                self._write_setup_token(str(setup["token"]))
                setup["token"] = ""
            log.info("setup state: %s", setup.get("state"))
        except Exception as e:
            log.warning("setup init failed: %s", e)
        try:
            ensure_promconfig_admin_perms(self.db)
            ensure_checks_admin_perms(self.db)
        except Exception as e:
            log.warning("ensure promconfig admin perms failed: %s", e)

        ws_app = web.Application()
        ws_app.router.add_get(self.cfg.get("ws_path", "/ws"), self.ob.handle_ws)
        http_app = self.webapp.build()

        ws_runner = web.AppRunner(ws_app)
        http_runner = web.AppRunner(http_app)
        await ws_runner.setup()
        await http_runner.setup()
        ws_site = web.TCPSite(
            ws_runner, self.cfg.get("ws_host", "127.0.0.1"), int(self.cfg.get("ws_port", 6199))
        )
        http_site = web.TCPSite(
            http_runner, self.cfg.get("http_host", "127.0.0.1"), int(self.cfg.get("http_port", 6200))
        )
        await ws_site.start()
        await http_site.start()
        log.info("Ayana v%s ws=%s:%s%s http=%s:%s", VERSION,
                 self.cfg.get("ws_host"), self.cfg.get("ws_port"), self.cfg.get("ws_path"),
                 self.cfg.get("http_host"), self.cfg.get("http_port"))

        # 后台：outbox、周期对账、事件关联
        self._bg_tasks.append(asyncio.create_task(self._bg_outbox()))
        self._bg_tasks.append(asyncio.create_task(self._bg_reconcile()))
        self._bg_tasks.append(asyncio.create_task(self._bg_correlate()))
        # 工作台：会话归档倒计时恢复 + 周期 tick
        try:
            self.duty.recover()
        except Exception as e:  # noqa: BLE001
            log.warning("duty recover failed: %s", e)
        self._bg_tasks.append(asyncio.create_task(self._bg_duty_archives()))
        # P4.3：只读调查 worker（独立于旧自治）
        if self.auto_investigator is not None:
            self._bg_tasks.append(asyncio.create_task(self.auto_investigator.run_forever()))
        # Manual authorization expiry is independent of any investigation worker.
        self._bg_tasks.append(asyncio.create_task(self._bg_maintenance()))

        # 推送通道：QQ 走 OneBot；多渠道由 ChannelStore 路由
        async def _sender(target: str, body: str) -> bool:
            return await self.ob.send_to_target(target, body)

        self.notifier.set_sender(_sender)
        self.channel_store.set_qq_sender(_sender)
        self.wecom_bot = WeComBot(self.qq, self.aibot_manager, self.channel_store, self.mlog,
                                  node_name=str(getattr(self, "_node_name", "") or ""))
        self.qq.mlog = self.mlog
        self.aibot_manager._on_message = self.wecom_bot.on_channel_frame
        # 全新安装不预置任何通知渠道（含 QQ）；由用户主动添加。
        # 老实例已有渠道原样保留，不做迁移/停用。
        # 启动已启用的企微智能机器人长连接
        self._bg_tasks.append(asyncio.create_task(self._bg_aibot()))
        self._bg_tasks.append(asyncio.create_task(self._bg_checks()))
        self._bg_tasks.append(asyncio.create_task(self._bg_ext_watch()))
        if getattr(self, "nodewatch", None):
            try:
                self.nodewatch.start()
                log.info(
                    "node-watch started send=%s recv=%s",
                    self.nodewatch.enabled_send(),
                    self.nodewatch.enabled_recv(),
                )
            except Exception:
                log.exception("node-watch start failed")

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except NotImplementedError:
                pass
        await self._stop.wait()
        log.info("shutting down")
        if getattr(self, "nodewatch", None):
            try:
                await self.nodewatch.stop()
            except Exception:
                pass
        for t in self._bg_tasks:
            t.cancel()
        await asyncio.gather(*(task for task in self._bg_tasks if isinstance(task, asyncio.Future)), return_exceptions=True)
        try:
            await self.aibot_manager.stop_all()
        except Exception:
            pass
        await ws_runner.cleanup()
        await http_runner.cleanup()

    async def _bg_checks(self) -> None:
        """业务检查调度：轻量默认，不依赖 Prometheus。"""
        while not self._stop.is_set():
            try:
                await self.checks.run_due()
            except Exception as e:
                log.warning("checks tick failed: %s", e)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=15)
            except asyncio.TimeoutError:
                pass

    async def _bg_ext_watch(self) -> None:
        """外部事务：running 超时 + 心跳失联 + 计划漏跑。"""
        while not self._stop.is_set():
            try:
                self.exttx.watch_tick()
            except Exception:
                log.exception("ext watch tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass

    async def _bg_outbox(self) -> None:
        while not self._stop.is_set():
            try:
                self.notifier.compensate_missing()
                await self.notifier.flush()
                self.db.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('worker_outbox_last_ok', ?)",
                    (str(time.time()),),
                )
            except Exception:
                log.exception("outbox flush failed")
            await asyncio.sleep(3)

    async def _bg_aibot(self) -> None:
        """维持企微智能机器人长连接（一渠道一连接）。"""
        while not self._stop.is_set():
            try:
                chans = self.channel_store.list_enabled()
                enabled_aibot_ids = set()
                log.info("bg_aibot scanning %d channels", len(chans))
                for ch in chans:
                    if ch.get("kind") != "wecom_aibot":
                        continue
                    log.info("bg_aibot found wecom_aibot channel %s", ch.get("id"))
                    enabled_aibot_ids.add(ch["id"])
                    try:
                        raw = self.channel_store.reveal_for_send(ch["id"])
                        sec = raw.get("secret") or {}
                        cfg = raw.get("config") or {}
                        bot_id = str(sec.get("bot_id") or "")
                        secret = str(sec.get("secret") or "")
                        if bot_id and secret:
                            await self.aibot_manager.ensure(
                                ch["id"],
                                bot_id=bot_id,
                                secret=secret,
                                ws_url=str(cfg.get("ws_url") or ""),
                            )
                    except Exception:
                        log.exception("aibot ensure failed for %s", ch.get("id"))
                # S06: 停用/删除的渠道立即断开，不能当安全停止
                for cid in list(self.aibot_manager._clients.keys()):
                    if cid not in enabled_aibot_ids:
                        log.info("bg_aibot stopping disabled channel %s", cid)
                        try:
                            await self.aibot_manager.stop(cid)
                        except Exception:
                            log.exception("aibot stop failed for %s", cid)
            except Exception:
                log.exception("aibot bg loop failed")
            await asyncio.sleep(30)

    async def _bg_reconcile(self) -> None:
        while not self._stop.is_set():
            try:
                if self.cfg.get("alertmanager_url"):
                    try:
                        alerts = await self.alert_ingest.fetch_am_alerts(self.cfg["alertmanager_url"])
                        self.alert_ingest.reconcile(alerts, source_ok=True)
                        self.alert_ingest.last_status = "available"
                    except Exception as e:
                        log.warning("AM fetch failed: %s", e)
                        self.alert_ingest.last_status = "unavailable"
                        self.alert_ingest.reconcile([], source_ok=False)
                self.db.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('worker_reconcile_last_ok', ?)",
                    (str(time.time()),),
                )
                for incident in self.db.query(
                    "SELECT id FROM incidents WHERE status='open' AND need_human=1"
                    " AND need_human_reason LIKE '%awaiting_approval:%' LIMIT 50"
                ):
                    self.incidents.reconcile(incident["id"], resolution_basis="approval_reconcile")
            except Exception as e:
                log.warning("AM reconcile failed: %s", e)
            await asyncio.sleep(60)

    async def _bg_duty_archives(self) -> None:
        """值班会话归档倒计时 tick + 标题刷新。"""
        while not self._stop.is_set():
            try:
                self.duty.tick_archives()
            except Exception as e:  # noqa: BLE001
                log.warning("duty tick_archives failed: %s", e)
            try:
                for sess in self.duty.list_sessions(status="open", origin="auto", limit=5):
                    sid = sess.get("id") or ""
                    if not sid:
                        continue
                    title = self.duty.auto_title_from_incidents(sid)
                    if title and title != (sess.get("title") or ""):
                        self.duty.update_title(sid, title)
            except Exception as e:  # noqa: BLE001
                log.warning("duty title refresh failed: %s", e)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass

    async def _bg_maintenance(self) -> None:
        """Expire manual proposals and permission changes without legacy agents."""
        while not self._stop.is_set():
            for name, expire in (
                ("proposals", self.actions.expire_stale_proposals),
                ("permission_changes", self.permission_changes.expire_stale),
            ):
                try:
                    expire()
                except Exception:
                    log.exception("expire %s failed", name)
            try:
                self.db.execute(
                    "INSERT OR REPLACE INTO meta(key,value) VALUES('worker_maintenance_last_ok',?)",
                    (str(time.time()),),
                )
            except Exception:
                log.exception("maintenance heartbeat failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=15)
            except asyncio.TimeoutError:
                pass

    async def _bg_correlate(self) -> None:
        """同步 episode→Incident（孤儿修复）。

        正向转换已由各写入点内联调用 upsert_from_episode；
        本循环只做补偿（60s）：
        - incident_id='' 的 episode
        - episode=resolved 且对应 Incident 仍 open，且本 episode 无 hold 标记
        """
        while not self._stop.is_set():
            try:
                rows = self.db.query(
                    "SELECT e.* FROM alert_episodes e"
                    " LEFT JOIN incidents i ON i.id = e.incident_id"
                    " LEFT JOIN events h ON h.incident_id = e.incident_id"
                    "   AND h.type='alert_resolved_hold'"
                    "   AND h.payload_json LIKE '%' || e.id || '%'"
                    " WHERE e.source_state!='quarantine' AND e.source_health!='quarantine'"
                    " AND (e.incident_id=''"
                    "    OR (e.status='resolved' AND e.incident_id!=''"
                    "        AND (i.id IS NULL OR i.status='open') AND h.id IS NULL))"
                    " ORDER BY e.first_seen ASC"
                )
                processed = 0
                for r in rows:
                    if r["incident_id"] and not self.incidents.episode_is_current(r["incident_id"], dict(r)):
                        continue
                    # 与实时入站共用关联/恢复/通知入口；旧代不占本轮处理名额。
                    self.alert_ingest._sync_incident(r["id"])
                    processed += 1
                    if processed >= 30:
                        break
            except Exception:
                log.exception("correlate failed")
            await asyncio.sleep(60)

    def reload_gate(self) -> None:
        self.gate = IdentityGate(self.nt, load_bindings(self.db))
        self.investigation.gate = self.gate
        self.actions.gate = self.gate


async def amain(config_path: str) -> None:
    cfg = load_config(config_path)
    setup_logging(cfg.get("log_level", "INFO"), cfg.get("log_file"))
    # 监控 required checks / runbook 从配置注入（发行版默认为空）
    try:
        from .health import apply_required_checks
        from .runbook import apply_runbook_rules

        apply_required_checks(cfg.get("required_checks"))
        apply_runbook_rules(cfg.get("runbook_rules"))
        log.info(
            "monitor config loaded: required_assets=%d runbook_rules=%d",
            len(cfg.get("required_checks") or {}),
            len(cfg.get("runbook_rules") or []),
        )
    except Exception as e:
        log.warning("apply monitor config failed: %s", e)
    lock = acquire_single_instance_lock(cfg.get("instance_lock") or "/tmp/ayana.lock")
    try:
        log.info("Ayana v%s starting", VERSION)
        app = App(cfg)
        await app.start()
    finally:
        try:
            if os.name != "nt":
                import fcntl

                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            lock.close()
        except Exception:
            pass


def _build_auth_for_ops(cfg: dict, db: Database) -> AuthService:
    """与 App 同一套 pepper 逻辑，供本地运维 CLI 使用。"""
    dedicated = str(cfg.get("web_auth_pepper") or "")
    onewbot = str(cfg.get("onewbot_token") or "")
    pepper = dedicated or onewbot
    legacy: list[str] = []
    if dedicated and onewbot and dedicated != onewbot:
        legacy = [onewbot]
    return AuthService(
        db,
        pepper=pepper,
        session_ttl=int(cfg.get("web_session_ttl_sec", 43200)),
        max_failed=int(cfg.get("web_max_failed_logins", 8)),
        lockout=int(cfg.get("web_lockout_sec", 900)),
        totp_key=cfg.get("totp_encrypt_key") or "",
        legacy_peppers=legacy,
    )


def _write_one_time_password(db: Database, password: str, filename: str) -> Path | None:
    """一次性口令文件：与 DB 同目录、O_EXCL、0600、拒符号链接。口令不进日志。"""
    try:
        db_path = Path(db.path).resolve()
        pw_path = db_path.parent / filename
        if pw_path.is_symlink() or pw_path.exists():
            log.warning("password file already exists or is a symlink, not overwritten: %s", pw_path)
            return None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(str(pw_path), flags, 0o600)
        try:
            os.write(fd, (password + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        return pw_path
    except Exception as e:
        log.warning("one-time password file was not written (%s)", type(e).__name__)
        return None


def _reset_admin_password(cfg: dict, username: str) -> int:
    """服务器本地管理员恢复：重置口令 + 强制改密 + 撤销全部会话。"""
    db = Database(cfg["db_path"])
    try:
        auth = _build_auth_for_ops(cfg, db)
        password = auth.reset_user_password(username)
        pw_path = _write_one_time_password(db, password, f"reset-{username}.password")
        if pw_path:
            print(f"OK: user '{username}' password reset; must_change_password=1; all sessions revoked.")
            print(f"One-time password written to: {pw_path} (mode 600). Login and change it, then delete the file.")
        else:
            print(f"OK: user '{username}' password reset; must_change_password=1; all sessions revoked.")
            print("WARNING: could not write one-time password file (exists?). Password was not printed.")
        return 0
    except Exception as e:
        print(f"ERROR: reset failed: {e}", file=sys.stderr)
        return 1
    finally:
        try:
            db.close()
        except Exception:
            pass


def cli() -> None:
    parser = argparse.ArgumentParser(prog="ayana")
    parser.add_argument("config", nargs="?", default="config.json")
    parser.add_argument("--seed-only", action="store_true")
    parser.add_argument(
        "--reset-admin-password",
        action="store_true",
        help="本地重置指定用户口令并强制下次登录改密（写入一次性口令文件，不打印口令）",
    )
    parser.add_argument(
        "--reset-admin-user",
        default="admin",
        help="与 --reset-admin-password 搭配：目标用户名（默认 admin）",
    )
    args = parser.parse_args()
    if args.reset_admin_password:
        cfg = load_config(args.config)
        setup_logging(cfg.get("log_level", "INFO"), None)
        sys.exit(_reset_admin_password(cfg, args.reset_admin_user))
    if args.seed_only:
        cfg = load_config(args.config)
        setup_logging(cfg.get("log_level", "INFO"), None)
        db = Database(cfg["db_path"])
        seed_assets(db)
        print("seeded", db.query("SELECT id FROM assets"))
        return
    try:
        asyncio.run(amain(args.config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cli()
