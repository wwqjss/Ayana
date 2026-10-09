"""Agent 监控查询：自然语言 → Prometheus 指标。

- 复用 HostMonitor / 资产映射 / 监控 API，不重复采集
- 只读，但仍受身份认证与资产读取权限约束
- 回复注明目标主机、实际数据、时间范围，不编造
- 错误引导用通用占位符，不列真实资产名
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .monitor import HostMonitor, RANGES

log = logging.getLogger("ayana.agent_query")

# 指标关键词 → metric key
METRIC_KEYWORDS: dict[str, tuple[str, ...]] = {
    "cpu": ("cpu", "CPU", "处理器"),
    "memory": ("内存", "memory", "mem", "RAM"),
    "swap": ("swap", "Swap", "交换"),
    "disk": ("磁盘", "disk", "硬盘", "存储"),
    "load": ("负载", "load", "load1", "load5"),
    "net": ("网络", "网络", "net", "流量", "带宽"),
}

# 时间范围关键词
RANGE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "15m": ("15分钟", "15m", "一刻钟"),
    "1h": ("1小时", "1h", "一小时", "最近一小时", "过去一小时"),
    "6h": ("6小时", "6h", "六小时"),
    "24h": ("24小时", "24h", "24 小时", "一天", "一整天", "最近一天", "过去一天"),
    "7d": ("7天", "7d", "7 天", "一周", "七天"),
}

# 状态关键词（总览）
STATUS_KEYWORDS = ("状态", "情况", "怎么样", "如何", "正常吗", "健康", "status", "概览", "总览")

# 比较关键词
COMPARE_KEYWORDS = ("对比", "比较", "和", "跟", "vs", "与")


@dataclass
class QueryIntent:
    """解析出的查询意图。"""

    host: str = ""
    metric: str = ""  # cpu/memory/swap/disk/load/net/""=全部
    metrics: list[str] = field(default_factory=list)  # 多指标
    range_key: str = "1h"
    compare_hosts: list[str] = field(default_factory=list)
    want_status: bool = False
    raw: str = ""


def parse_query(text: str, known_hosts: list[str]) -> QueryIntent:
    """确定性关键词解析。known_hosts 用于识别主机名（不回显未授权主机）。"""
    t = (text or "").strip()
    intent = QueryIntent(raw=t)
    if not t:
        return intent

    lower = t.lower()
    compact = t.replace(" ", "").replace("　", "")

    # 时间范围
    for rk, kws in RANGE_KEYWORDS.items():
        if any(k in t or k in lower or k in compact for k in kws):
            intent.range_key = rk
            break

    # 指标（支持多指标）
    metrics: list[str] = []
    for metric, kws in METRIC_KEYWORDS.items():
        if any(k in t or k in lower for k in kws):
            metrics.append(metric)
    intent.metric = metrics[0] if metrics else ""
    intent.metrics = metrics

    # 状态
    if any(k in t for k in STATUS_KEYWORDS):
        intent.want_status = True

    # 主机识别（只认已知主机，大小写不敏感）
    host_lower_map = {h.lower(): h for h in known_hosts}
    found: list[str] = []
    # 先找「A 和 B / A 对比 B」
    for sep in ("和", "与", "跟", "对比", "比较", "vs"):
        if sep in t:
            parts = re.split(rf"[{sep}]|对比|比较", t)
            for p in parts:
                for h_low, h_real in host_lower_map.items():
                    if h_low in p.lower() and h_real not in found:
                        found.append(h_real)
            break
    if not found:
        for h_low, h_real in host_lower_map.items():
            if h_low in lower and h_real not in found:
                found.append(h_real)

    if len(found) >= 2:
        intent.compare_hosts = found[:3]
        intent.host = found[0]
    elif found:
        intent.host = found[0]

    return intent


def _fmt_val(metric_key: str, value: float | None, unit: str) -> str:
    if value is None:
        return "—"
    if unit == "%":
        return f"{value:.1f}%"
    if unit == "B/s":
        units = ["B/s", "KB/s", "MB/s", "GB/s"]
        x, i = abs(value), 0
        while x >= 1024 and i < len(units) - 1:
            x /= 1024
            i += 1
        return f"{x:.1f} {units[i]}"
    if metric_key.startswith("load"):
        return f"{value:.2f}"
    return f"{value:.1f}"


def _fmt_state(st: str) -> str:
    return {
        "ok": "正常",
        "warn": "偏高",
        "bad": "异常",
        "not_enabled": "未启用",
        "no_data": "暂无数据",
        "collect_error": "采集失败",
    }.get(st, st)


def _fmt_range(rk: str) -> str:
    return {
        "15m": "最近 15 分钟",
        "1h": "最近 1 小时",
        "6h": "最近 6 小时",
        "24h": "最近 24 小时",
        "7d": "最近 7 天",
    }.get(rk, rk)


class AgentQueryService:
    """Agent 监控查询服务（只读）。"""

    def __init__(self, monitor: HostMonitor, db: Any):
        self.monitor = monitor
        self.db = db

    def _authorized_hosts(self, actor_type: str, actor_id: str, policy: Any) -> list[str]:
        """返回该主体有 asset.summary 权限的主机 id 列表。"""
        rows = self.db.query(
            "SELECT id, display_name, prom_asset FROM assets WHERE enabled=1 ORDER BY id"
        )
        out = []
        for r in rows:
            aid = str(r["id"])
            try:
                d = policy.check(
                    subject_type=actor_type,
                    subject_id=actor_id,
                    capability="asset.summary",
                    asset_id=aid,
                    object_id="*",
                )
            except Exception:
                continue
            if d.get("allowed"):
                out.append(aid)
        return out

    async def handle(
        self,
        text: str,
        *,
        actor_type: str,
        actor_id: str,
        policy: Any,
    ) -> str:
        """处理自然语言监控查询，返回人类可读文本。"""
        hosts = self._authorized_hosts(actor_type, actor_id, policy)
        if not hosts:
            return "暂无可用监控目标。"

        intent = parse_query(text, hosts)
        if not intent.host and not intent.compare_hosts:
            return (
                "未能识别查询目标。\n"
                "用法示例: 查询 <host> 的 CPU 状态\n"
                f"时间范围: {', '.join(RANGES.keys())}"
            )

        # 权限再校验（解析出的主机也必须在授权列表内）
        targets = intent.compare_hosts or ([intent.host] if intent.host else [])
        targets = [h for h in targets if h in hosts]
        if not targets:
            return "目标不可用或无访问权限"

        if len(targets) >= 2:
            return await self._compare(targets, intent)
        return await self._single(targets[0], intent)

    async def _single(self, host: str, intent: QueryIntent) -> str:
        try:
            history = await self.monitor.host_history(host, intent.range_key)
        except Exception as e:
            log.exception("agent_query history failed")
            return f"查询失败: {str(e)[:80]}"
        if history.get("state") == "collect_error":
            return f"[{host}] 采集失败: Prometheus 不可达或查询失败"
        metrics = history.get("metrics") or {}
        labels = {
            "cpu": "CPU",
            "memory": "内存",
            "swap": "Swap",
            "disk": "磁盘",
            "load1": "负载1m",
            "load5": "负载5m",
            "net_rx": "网络接收",
            "net_tx": "网络发送",
        }
        keys = {
            "cpu": ("cpu",),
            "memory": ("memory",),
            "swap": ("swap",),
            "disk": ("disk",),
            "load": ("load1", "load5"),
            "net": ("net_rx", "net_tx"),
        }
        if intent.metrics:
            selected = []
            for m in intent.metrics:
                selected.extend(keys.get(m, ()))
            keys_list = tuple(dict.fromkeys(selected))  # dedupe, keep order
        else:
            keys_list = keys.get(intent.metric, ("cpu", "memory", "swap", "disk", "load1", "load5"))

        lines = [f"[{host}] {_fmt_range(intent.range_key)}"]
        for k in keys_list:
            m = metrics.get(k)
            if not m:
                continue
            label = labels.get(k, k)
            st = _fmt_state(m.get("state", ""))
            val = _fmt_val(k, m.get("value"), m.get("unit", ""))
            if m.get("state") == "not_enabled":
                lines.append(f"  {label}: 未启用")
            else:
                lines.append(f"  {label}: {val} · {st}")
        lines.append(f"数据源 Prometheus · 时间范围 {intent.range_key}")
        return "\n".join(lines)

    async def _compare(self, hosts: list[str], intent: QueryIntent) -> str:
        metric = intent.metric or "cpu"
        keys = {
            "cpu": ("cpu",),
            "memory": ("memory",),
            "swap": ("swap",),
            "disk": ("disk",),
            "load": ("load1",),
            "net": ("net_rx",),
        }.get(metric, ("cpu",))
        lines = [f"跨主机比较 · {metric} · {_fmt_range(intent.range_key)}"]
        for h in hosts:
            try:
                history = await self.monitor.host_history(h, intent.range_key)
            except Exception:
                lines.append(f"  [{h}] 采集失败")
                continue
            metrics = history.get("metrics") or {}
            parts = []
            for k in keys:
                m = metrics.get(k)
                if not m:
                    continue
                if m.get("state") == "not_enabled":
                    parts.append(f"{k}=未启用")
                else:
                    parts.append(f"{k}={_fmt_val(k, m.get('value'), m.get('unit', ''))}({_fmt_state(m.get('state', ''))})")
            lines.append(f"  [{h}] " + " ".join(parts))
        lines.append(f"数据源 Prometheus · 时间范围 {intent.range_key}")
        return "\n".join(lines)
