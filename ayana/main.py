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
from .agent import AgentLoop
from .alertmanager import AlertIngest
from .auth import AuthService
from .config import load_config
from .db import Database, now
from .incidents import IncidentService
from .investigation import InvestigationService
from .instance import acquire_single_instance_lock
from .knowledge import KnowledgeBase
from .llm import make_llm
from .ntsafe import AssetBinding, IdentityGate, NTClient
from .notify import Notifier
from .onewbot import OneBotServer
from .policy import Policy
from .prom import PromClient
from .qqbot import QQBot
from .web import WebApp

log = logging.getLogger("ayana")

DEFAULT_ASSETS = [
    {
        "id": "nerv",
        "display_name": "NERV",
        "read_alias": "nerv",
        "write_alias": "nerv-exec",
        "expected_host_id": "NERV",
        "prom_asset": "nerv",
        "objects": [
            {"kind": "service", "name": "frps", "unit": "frps", "auto_recover": 1},
            {"kind": "service", "name": "nginx", "unit": "nginx"},
            {"kind": "service", "name": "php-fpm", "unit": "php-fpm"},
            {"kind": "port", "name": "frps-32659", "port": 32659, "protocol": "tcp"},
            {"kind": "probe", "name": "frps-probe", "external_probe": "tcp_connect"},
        ],
    },
    {
        "id": "kanata",
        "display_name": "KANATA",
        "read_alias": "kanata",
        "write_alias": "kanata-exec",
        "expected_host_id": "KANATA",
        "prom_asset": "kanata",
        "objects": [
            {"kind": "container", "name": "harbor-core", "container": "harbor-core"},
            {"kind": "container", "name": "nginx", "container": "nginx"},
            {"kind": "service", "name": "alist", "unit": "alist"},
        ],
    },
    {
        "id": "sora",
        "display_name": "Sora",
        "read_alias": "sora",
        "write_alias": "sora-exec",
        "expected_host_id": "sora",
        "prom_asset": "sora",
        "objects": [
            {"kind": "service", "name": "hysteria-server", "unit": "hysteria-server"},
            {"kind": "port", "name": "hy2-443", "port": 443, "protocol": "udp"},
        ],
    },
    {
        "id": "yomi",
        "display_name": "Yomi",
        "read_alias": "yomi",
        "write_alias": "yomi-exec",
        "expected_host_id": "yomi",
        "prom_asset": "yomi",
        "objects": [],
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
            " prom_asset, enabled, notes, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,1,'',?,?)",
            (
                a["id"],
                a["display_name"],
                a["read_alias"],
                a["write_alias"],
                a["expected_host_id"],
                a["prom_asset"],
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
        seed_assets(self.db)
        self.auth = AuthService(
            self.db,
            pepper=cfg.get("web_auth_pepper") or cfg["onewbot_token"],
            session_ttl=int(cfg.get("web_session_ttl_sec", 43200)),
            max_failed=int(cfg.get("web_max_failed_logins", 8)),
            lockout=int(cfg.get("web_lockout_sec", 900)),
        )
        self.policy = Policy(self.db)
        self.nt = NTClient(privilege_mode="restricted_dispatcher")
        self.gate = IdentityGate(self.nt, load_bindings(self.db))
        self.knowledge = KnowledgeBase(self.db)
        self.prom = PromClient(cfg.get("prometheus_url", "http://127.0.0.1:9090"))
        self.incidents = IncidentService(self.db)
        self.investigation = InvestigationService(
            self.db, self.nt, self.gate, self.prom, self.policy,
            knowledge=self.knowledge,
        )
        self.actions = ActionService(
            self.db,
            self.nt,
            self.gate,
            self.policy,
            self.prom,
            action_ttl=int(cfg.get("action_ttl_sec", 1800)),
            verify_window=int(cfg.get("verify_window_sec", 90)),
            verify_timeout=int(cfg.get("verify_timeout_sec", 300)),
        )
        self.notifier = Notifier(self.db, default_target="")
        self.alert_ingest = AlertIngest(self.db, incidents=self.incidents, notifier=self.notifier)
        self.notifier.set_default_target(
            f"user:{cfg['admin_qq']}" if cfg.get("admin_qq") else ""
        )
        self.llm = make_llm(cfg)
        self.investigation.llm = self.llm
        self.agent = AgentLoop(
            self.db, self.investigation, self.actions, self.policy,
            self.llm, self.notifier,
            auto_enabled=bool(cfg.get("auto_remediation_enabled", False)),
            knowledge=self.knowledge,
        )
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
            version=VERSION,
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
            agent=self.agent,
        )
        self._stop = asyncio.Event()
        self._bg_tasks: list[asyncio.Task] = []

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

        admin = self.auth.ensure_bootstrap_admin("admin")
        if admin:
            log.warning("BOOTSTRAP admin password (rotate after first login): %s", admin)

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

        # 后台：outbox、周期对账、事件关联、Agent
        self._bg_tasks.append(asyncio.create_task(self._bg_outbox()))
        self._bg_tasks.append(asyncio.create_task(self._bg_reconcile()))
        self._bg_tasks.append(asyncio.create_task(self._bg_correlate()))
        self._bg_tasks.append(asyncio.create_task(self._bg_agent()))

        # 推送通道
        async def _sender(target: str, body: str) -> bool:
            return await self.ob.send_to_target(target, body)

        self.notifier.set_sender(_sender)

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except NotImplementedError:
                pass
        await self._stop.wait()
        log.info("shutting down")
        for t in self._bg_tasks:
            t.cancel()
        await ws_runner.cleanup()
        await http_runner.cleanup()

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
            except Exception as e:
                log.warning("AM reconcile failed: %s", e)
            await asyncio.sleep(60)

    async def _bg_agent(self) -> None:
        """Agent 闭环：只读调查 + 提案（始终）；自动派发仅 auto_enabled。"""
        while not self._stop.is_set():
            try:
                rows = self.db.query(
                    "SELECT id FROM incidents WHERE status='open' AND need_human=0"
                    " AND stage IN ('pending','investigating')"
                    " ORDER BY created_at ASC LIMIT 3"
                )
                for r in rows:
                    await self.agent.handle_incident(r["id"])
                # 过期 proposal 清扫（TTL / approval_deadline）
                try:
                    self.actions.expire_stale_proposals()
                except Exception:
                    log.exception("expire proposals failed")
                self.db.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('worker_agent_last_ok', ?)",
                    (str(time.time()),),
                )
            except Exception:
                log.exception("agent loop failed")
            await asyncio.sleep(15)

    async def _bg_correlate(self) -> None:
        """同步 episode→Incident。

        只消费「未处理转换」：
        - incident_id='' 的 episode
        - episode=resolved 且对应 Incident 仍 open，且本 episode 无 hold 标记
        """
        while not self._stop.is_set():
            try:
                rows = self.db.query(
                    "SELECT e.id, e.status, e.incident_id FROM alert_episodes e"
                    " LEFT JOIN incidents i ON i.id = e.incident_id"
                    " LEFT JOIN events h ON h.incident_id = e.incident_id"
                    "   AND h.type='alert_resolved_hold'"
                    "   AND h.payload_json LIKE '%' || e.id || '%'"
                    " WHERE e.incident_id=''"
                    "    OR (e.status='resolved' AND e.incident_id!=''"
                    "        AND (i.id IS NULL OR i.status='open') AND h.id IS NULL)"
                    " ORDER BY e.first_seen ASC LIMIT 30"
                )
                for r in rows:
                    rid = r["id"]
                    if not r["incident_id"]:
                        inc_id = self.incidents.upsert_from_episode(rid)
                        if inc_id:
                            self.notifier.enqueue(
                                dedup_key=f"ev:corr:{inc_id}:{rid}",
                                target=f"user:{self.qq.admin_qq}" if self.qq.admin_qq else "",
                                body=f"[Ayana] incident {inc_id} opened",
                            )
                    if r["status"] == "resolved" and r["incident_id"]:
                        self.incidents.on_episode_resolved(rid)
            except Exception:
                log.exception("correlate failed")
            await asyncio.sleep(5)

    def reload_gate(self) -> None:
        self.gate = IdentityGate(self.nt, load_bindings(self.db))
        self.investigation.gate = self.gate
        self.actions.gate = self.gate


async def amain(config_path: str) -> None:
    cfg = load_config(config_path)
    setup_logging(cfg.get("log_level", "INFO"), cfg.get("log_file"))
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


def cli() -> None:
    parser = argparse.ArgumentParser(prog="ayana")
    parser.add_argument("config", nargs="?", default="config.json")
    parser.add_argument("--seed-only", action="store_true")
    args = parser.parse_args()
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
