"""节点守望：实例间 HTTP 心跳 + 失联调查 + 告警。

设计约束：
- 心跳直连对端公网/内网 HTTP，不经过 FRP，避免同一故障点。
- FRP/HTTP 健康口仅作可选佐证；未配置路径 = 未配置，不算失败。
- 网络不可达 ≠ 主机宕机：措辞用「疑似失联」。
- 发送/接收两个开关互相独立，可只发、只收。
- 同一失联事件只告警一次；恢复需有效心跳，不凭偶然连通。
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from typing import Any, Callable

log = logging.getLogger("ayana.nodewatch")

# 状态
STATUS_ONLINE = "online"
STATUS_SUSPECT = "suspect"
STATUS_DOWN = "down"
STATUS_UNKNOWN = "unknown"


def _now() -> float:
    return time.time()


def sign_payload(*, secret: str, node_id: str, ts: float, nonce: str, seq: int, payload: dict) -> str:
    """HMAC-SHA256：node_id|ts|nonce|seq|payload_json。"""
    body = json.dumps(payload or {}, sort_keys=True, separators=(",", ":"))
    raw = f"{node_id}|{ts:.6f}|{nonce}|{seq}|{body}"
    return hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_payload(
    *,
    secret: str,
    node_id: str,
    ts: float,
    nonce: str,
    seq: int,
    payload: dict,
    sig: str,
    max_skew_sec: float = 120.0,
) -> tuple[bool, str]:
    if not secret:
        return False, "missing_secret"
    if not node_id or not nonce or not sig:
        return False, "missing_fields"
    try:
        tsf = float(ts)
    except (TypeError, ValueError):
        return False, "bad_ts"
    if abs(_now() - tsf) > max_skew_sec:
        return False, "ts_skew"
    expect = sign_payload(
        secret=secret, node_id=node_id, ts=tsf, nonce=str(nonce), seq=int(seq), payload=payload or {}
    )
    if not hmac.compare_digest(expect, str(sig)):
        return False, "bad_sig"
    return True, ""


class NodeWatchService:
    """心跳接收 + 发送 + 失联守望。"""

    def __init__(
        self,
        db: Any,
        *,
        config: dict | None = None,
        notifier: Any = None,
        channel_store: Any = None,
    ):
        self.db = db
        self.cfg = dict(config or {})
        self.notifier = notifier
        self.channel_store = channel_store
        self._send_task: asyncio.Task | None = None
        self._watch_task: asyncio.Task | None = None
        self._stopped = False
        self._last_send: dict[str, Any] = {}
        self._aiohttp: Any = None

    # ---- config helpers ----

    @property
    def send_cfg(self) -> dict:
        return dict(self.cfg.get("send") or {})

    @property
    def recv_cfg(self) -> dict:
        return dict(self.cfg.get("recv") or {})

    def enabled_send(self) -> bool:
        return bool(self.send_cfg.get("enabled"))

    def enabled_recv(self) -> bool:
        return bool(self.recv_cfg.get("enabled"))

    def send_secret(self) -> str:
        return str(self.send_cfg.get("shared_secret") or "")

    def recv_secret(self) -> str:
        return str(self.recv_cfg.get("shared_secret") or self.send_secret() or "")

    def allowed_nodes(self) -> set[str]:
        raw = self.recv_cfg.get("allowed_nodes") or []
        return {str(x).strip() for x in raw if str(x).strip()}

    def timeout_sec(self) -> float:
        try:
            return float(self.recv_cfg.get("timeout_sec") or 180)
        except (TypeError, ValueError):
            return 180.0

    def send_interval_sec(self) -> float:
        try:
            v = float(self.send_cfg.get("interval_sec") or 60)
        except (TypeError, ValueError):
            v = 60.0
        return max(10.0, v)

    def probes(self) -> list[dict]:
        out = []
        for p in self.recv_cfg.get("probes") or []:
            if not isinstance(p, dict):
                continue
            kind = str(p.get("kind") or "http").lower()
            url = str(p.get("url") or "").strip()
            if kind == "http" and url:
                try:
                    tmo = float(p.get("timeout_sec") or 5)
                except (TypeError, ValueError):
                    tmo = 5.0
                out.append({"kind": "http", "url": url, "timeout_sec": tmo})
        return out

    # ---- receive ----

    def handle_heartbeat(self, body: dict) -> dict:
        """校验并落库。成功返回 ok=True。"""
        node_id = str(body.get("node_id") or "").strip()
        nonce = str(body.get("nonce") or "").strip()
        sig = str(body.get("sig") or "").strip()
        try:
            ts = float(body.get("ts") or 0)
            seq = int(body.get("seq") or 0)
        except (TypeError, ValueError):
            return {"ok": False, "error": "bad_fields"}
        payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}

        allowed = self.allowed_nodes()
        if allowed and node_id not in allowed:
            return {"ok": False, "error": "node_not_allowed"}

        ok, err = verify_payload(
            secret=self.recv_secret(),
            node_id=node_id,
            ts=ts,
            nonce=nonce,
            seq=seq,
            payload=payload,
            sig=sig,
        )
        if not ok:
            log.warning("node-watch heartbeat rejected: %s node=%s", err, node_id)
            return {"ok": False, "error": err}

        # nonce 防重放（短窗口）
        if self._nonce_seen(nonce):
            return {"ok": False, "error": "replay"}
        self._store_nonce(nonce)

        self._upsert_peer(node_id=node_id, ts=ts, seq=seq, payload=payload)
        return {"ok": True}

    def _nonce_seen(self, nonce: str) -> bool:
        row = self.db.query_one(
            "SELECT nonce FROM node_watch_nonces WHERE nonce=? AND seen_at>=?",
            (nonce, _now() - 300),
        )
        return bool(row)

    def _store_nonce(self, nonce: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO node_watch_nonces(nonce, seen_at) VALUES(?,?)",
            (nonce, _now()),
        )
        # 顺手清理
        self.db.execute("DELETE FROM node_watch_nonces WHERE seen_at<?", (_now() - 600,))

    def _upsert_peer(self, *, node_id: str, ts: float, seq: int, payload: dict) -> None:
        now = _now()
        was = self.get_peer(node_id)
        prev_status = (was or {}).get("status") or STATUS_UNKNOWN
        self.db.execute(
            """
            INSERT INTO node_watch_peers(
              node_id, last_seq, last_ts, last_seen_at, last_payload,
              status, created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(node_id) DO UPDATE SET
              last_seq=excluded.last_seq,
              last_ts=excluded.last_ts,
              last_seen_at=excluded.last_seen_at,
              last_payload=excluded.last_payload,
              status=excluded.status,
              updated_at=excluded.updated_at
            """,
            (
                node_id,
                int(seq),
                float(ts),
                now,
                json.dumps(payload or {}, ensure_ascii=False),
                STATUS_ONLINE,
                now,
                now,
            ),
        )
        # 恢复通知
        if prev_status in (STATUS_DOWN, STATUS_SUSPECT):
            self._notify(
                f"[节点守望] {node_id} 心跳已恢复\n"
                f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            self.db.execute(
                "UPDATE node_watch_peers SET incident_open=0, last_alert_at=NULL WHERE node_id=?",
                (node_id,),
            )

    def get_peer(self, node_id: str) -> dict | None:
        row = self.db.query_one("SELECT * FROM node_watch_peers WHERE node_id=?", (node_id,))
        return dict(row) if row else None

    def list_peers(self) -> list[dict]:
        rows = self.db.query("SELECT * FROM node_watch_peers ORDER BY node_id ASC")
        return [dict(r) for r in rows]

    # ---- send ----

    async def send_once(self) -> dict:
        """向对端发一次心跳。"""
        cfg = self.send_cfg
        url = str(cfg.get("target_url") or "").strip()
        node_id = str(cfg.get("node_id") or "node").strip() or "node"
        secret = self.send_secret()
        if not url or not secret:
            return {"ok": False, "error": "send_not_configured"}
        row = self.db.query_one("SELECT value FROM meta WHERE key='node_watch_send_seq'")
        try:
            seq = int(row["value"] if row else 0) + 1
        except Exception:
            seq = 1
        self.db.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('node_watch_send_seq', ?)",
            (str(seq),),
        )
        ts = _now()
        nonce = uuid.uuid4().hex
        payload = {
            "version": str(cfg.get("version") or ""),
            "sent_at": ts,
        }
        sig = sign_payload(
            secret=secret, node_id=node_id, ts=ts, nonce=nonce, seq=seq, payload=payload
        )
        body = {
            "node_id": node_id,
            "ts": ts,
            "nonce": nonce,
            "seq": seq,
            "payload": payload,
            "sig": sig,
        }
        try:
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=float(cfg.get("timeout_sec") or 8))
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.post(url, json=body) as resp:
                    text = await resp.text()
                    ok = resp.status == 200
                    self._last_send = {
                        "at": ts,
                        "ok": ok,
                        "status": resp.status,
                        "body": text[:200],
                    }
                    return {"ok": ok, "status": resp.status, "body": text[:200]}
        except Exception as e:
            self._last_send = {"at": ts, "ok": False, "error": str(e)[:200]}
            log.warning("node-watch send failed: %s", e)
            return {"ok": False, "error": str(e)[:200]}

    def last_send(self) -> dict:
        return dict(self._last_send)

    # ---- probes / investigation ----

    async def run_probes(self) -> dict[str, Any]:
        """并行跑已配置探测。未配置 → 未配置，不算失败。"""
        items = self.probes()
        results: list[dict] = []
        if not items:
            return {
                "configured": False,
                "any_ok": None,
                "all_failed": None,
                "results": [],
                "note": "not_configured",
            }

        async def _one(p: dict) -> dict:
            if p["kind"] != "http":
                return {"kind": p["kind"], "ok": False, "error": "unsupported"}
            try:
                import aiohttp

                timeout = aiohttp.ClientTimeout(total=p["timeout_sec"])
                async with aiohttp.ClientSession(timeout=timeout) as sess:
                    async with sess.get(p["url"]) as resp:
                        ok = 200 <= resp.status < 300
                        return {
                            "kind": "http",
                            "url": p["url"],
                            "ok": ok,
                            "status": resp.status,
                        }
            except Exception as e:
                return {
                    "kind": "http",
                    "url": p["url"],
                    "ok": False,
                    "error": str(e)[:160],
                }

        results = list(await asyncio.gather(*[_one(p) for p in items]))
        any_ok = any(r.get("ok") for r in results)
        all_failed = not any_ok
        return {
            "configured": True,
            "any_ok": any_ok,
            "all_failed": all_failed,
            "results": results,
            "note": "",
        }

    # ---- watchdog loop ----

    async def watch_tick(self) -> dict:
        """一轮守望扫描。"""
        if not self.enabled_recv():
            return {"skipped": "recv_disabled"}
        now = _now()
        tmo = self.timeout_sec()
        peers = self.list_peers()
        # 也覆盖 allowed_nodes 里尚未出现过的
        known = {p["node_id"] for p in peers}
        for n in self.allowed_nodes():
            if n not in known:
                peers.append({"node_id": n, "status": STATUS_UNKNOWN, "last_seen_at": None})

        actions = []
        for p in peers:
            node_id = str(p.get("node_id") or "")
            if not node_id:
                continue
            last = p.get("last_seen_at")
            status = p.get("status") or STATUS_UNKNOWN
            incident_open = int(p.get("incident_open") or 0)

            if last is None:
                # 从未收到：不立刻告警，等超时从 first_seen 计——用 now 兜底不告
                continue

            age = now - float(last)
            if age <= tmo:
                continue

            # 超时 → 调查
            probe_res = await self.run_probes()
            probe_res["node_id"] = node_id
            probe_res["age_sec"] = round(age, 1)
            actions.append(probe_res)

            if probe_res.get("configured") and probe_res.get("any_ok"):
                # 心跳断但旁路还在 → 通道异常，不报整机
                self._set_peer_status(node_id, STATUS_SUSPECT)
                if not incident_open:
                    self._notify(
                        f"[节点守望] {node_id} 心跳超时，但旁路探测仍通\n"
                        f"结论: 心跳通道异常（非整机宕机）\n"
                        f"超时: {int(age)}s / 阈值 {int(tmo)}s\n"
                        f"探测: {probe_res.get('results')}"
                    )
                    self.db.execute(
                        "UPDATE node_watch_peers SET incident_open=1, last_alert_at=? WHERE node_id=?",
                        (now, node_id),
                    )
                continue

            if probe_res.get("configured") and probe_res.get("all_failed"):
                # 全部已配置路径失败 → 疑似失联
                self._set_peer_status(node_id, STATUS_DOWN)
                if not incident_open:
                    self._notify(
                        f"[节点守望] {node_id} 疑似失联\n"
                        f"心跳: 已超时 {int(age)}s（阈值 {int(tmo)}s）\n"
                        f"旁路: 全部已配置探测失败\n"
                        f"说明: 网络不可达≠物理宕机，请人工确认"
                    )
                    self.db.execute(
                        "UPDATE node_watch_peers SET incident_open=1, last_alert_at=? WHERE node_id=?",
                        (now, node_id),
                    )
                continue

            # 未配置旁路：仅心跳超时
            self._set_peer_status(node_id, STATUS_DOWN)
            if not incident_open:
                note = (
                    "旁路未配置（按设计允许，仅心跳判定）"
                    if not probe_res.get("configured")
                    else "旁路结果未知"
                )
                self._notify(
                    f"[节点守望] {node_id} 疑似失联\n"
                    f"心跳: 已超时 {int(age)}s（阈值 {int(tmo)}s）\n"
                    f"{note}\n"
                    f"说明: 网络不可达≠物理宕机，请人工确认"
                )
                self.db.execute(
                    "UPDATE node_watch_peers SET incident_open=1, last_alert_at=? WHERE node_id=?",
                    (now, node_id),
                )

        return {"ok": True, "actions": actions, "at": now}

    def _set_peer_status(self, node_id: str, status: str) -> None:
        self.db.execute(
            "UPDATE node_watch_peers SET status=?, updated_at=? WHERE node_id=?",
            (status, _now(), node_id),
        )

    def _notify(self, body: str) -> None:
        log.info("node-watch notify: %s", body.replace("\n", " | "))
        if not self.notifier:
            return
        try:
            ch = str(self.recv_cfg.get("alert_channel_id") or "")
            if ch:
                self.notifier.enqueue(None, body=body, channel_id=ch)
            else:
                self.notifier.enqueue(None, body=body)
        except Exception:
            log.exception("node-watch notify failed")

    # ---- loops ----

    def start(self) -> None:
        self._stopped = False
        if self.enabled_send():
            self._send_task = asyncio.create_task(self._send_loop(), name="node-watch-send")
        if self.enabled_recv():
            self._watch_task = asyncio.create_task(self._watch_loop(), name="node-watch-watch")

    async def stop(self) -> None:
        self._stopped = True
        for t in (self._send_task, self._watch_task):
            if t and not t.done():
                t.cancel()
        self._send_task = self._watch_task = None

    async def _send_loop(self) -> None:
        # 启动先发一发
        try:
            await self.send_once()
        except Exception:
            log.exception("node-watch first send failed")
        while not self._stopped:
            try:
                await asyncio.sleep(self.send_interval_sec())
                if self._stopped:
                    return
                await self.send_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("node-watch send loop error")

    async def _watch_loop(self) -> None:
        while not self._stopped:
            try:
                await asyncio.sleep(15)
                if self._stopped:
                    return
                await self.watch_tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("node-watch watch loop error")

    # ---- admin/status ----

    def status(self) -> dict[str, Any]:
        return {
            "send": {
                "enabled": self.enabled_send(),
                "node_id": self.send_cfg.get("node_id"),
                "target_url": self.send_cfg.get("target_url"),
                "interval_sec": self.send_interval_sec(),
                "last_send": self.last_send(),
            },
            "recv": {
                "enabled": self.enabled_recv(),
                "timeout_sec": self.timeout_sec(),
                "allowed_nodes": sorted(self.allowed_nodes()),
                "probes_configured": len(self.probes()),
                "probes": self.probes(),
            },
            "peers": self.list_peers(),
        }
