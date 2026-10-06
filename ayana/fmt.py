"""QQ 通知格式：人类可读，不暴露内部 ID。

完整 ID / 技术细节在 Web 事件详情和审计里。
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

CST = timezone(timedelta(hours=8))

ZH_STATUS = {"open": "处理中", "resolved": "已恢复", "closed": "已关闭"}
ZH_STAGE = {
    "pending": "待调查", "investigating": "调查中", "awaiting_approval": "待批准",
    "executing": "执行中", "verifying": "验证中", "watching": "观察中",
    "done": "完成", "need_human": "需人工",
}
ZH_STATE = {
    "proposed": "已提案", "approved": "已批准", "dispatched": "已派发",
    "success": "成功", "failure": "失败", "unknown": "结果未知",
    "cancelled": "已取消", "expired": "已过期",
}
ZH_ALERT = {
    "TargetDown": "服务不可达",
    "PrometheusJobMissing": "采集丢失",
    "DiskUsageHigh": "磁盘过高",
    "MemoryLow": "内存不足",
}
ZH_CAP = {
    "service.restart": "重启服务",
    "service.start": "启动服务",
    "service.stop": "停止服务",
    "container.restart": "重启容器",
}


def _t(ts: float | None) -> str:
    if not ts:
        return "刚刚"
    return datetime.fromtimestamp(ts, CST).strftime("%m-%d %H:%M")


def _z(m: dict, s: str) -> str:
    return m.get(s or "", s or "")


def alert_name(text: str) -> str:
    for en, cn in ZH_ALERT.items():
        text = text.replace(en, cn)
    return text


def fmt_incident_open(inc: dict) -> str:
    """新事件通知。"""
    return (
        f"告警\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}\n"
        f"时间: {_t(inc.get('created_at'))}"
    )


def fmt_incident_resolved(inc: dict) -> str:
    return (
        f"已恢复\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}\n"
        f"持续: {_t(inc.get('created_at'))} → {_t(inc.get('resolved_at'))}"
    )


def fmt_verified(inc: dict, action: dict | None = None, verification: dict | None = None) -> str:
    cap = ZH_CAP.get((action or {}).get("capability", ""), (action or {}).get("capability", ""))
    return (
        f"恢复验证通过\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}\n"
        f"处置: {cap}\n"
        f"时间: {_t((action or {}).get('finished_at'))}"
    )


def fmt_agent_exec(inc: dict, rule_name: str, capability: str) -> str:
    return (
        f"自动处置\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}\n"
        f"动作: {ZH_CAP.get(capability, capability)}\n"
        f"规则: {rule_name}"
    )


def fmt_escalate(inc: dict, reason: str, llm_summary: str = "") -> str:
    """找人通知。reason 是人类可读的原因。"""
    zh_reason = reason
    if reason == "no_runbook_match":
        zh_reason = "没有匹配的自动处置规则"
    elif reason.startswith("policy_denied"):
        zh_reason = "没有自动处置权限"
    elif reason.startswith("budget_exhausted"):
        zh_reason = "自动处置次数已用完"
    elif reason == "auto_remediation_disabled":
        zh_reason = "自动处置未开启"
    elif reason.startswith("exec_"):
        zh_reason = f"执行{ZH_STATE.get(reason.split('_', 1)[-1], '异常')}"
    elif reason.startswith("exec_error"):
        zh_reason = "执行出错"

    body = (
        f"需要你处理\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}\n"
        f"原因: {zh_reason}"
    )
    if llm_summary:
        body += f"\n分析: {llm_summary[:80]}"
    return body


def fmt_action_result(inc: dict, action: dict, state: str) -> str:
    cap = ZH_CAP.get(action.get("capability", ""), action.get("capability", ""))
    return (
        f"处置{'完成' if state == 'success' else '结果: ' + _z(ZH_STATE, state)}\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {action.get('asset_id', '?')} / 对象: {action.get('object_id', '?')}\n"
        f"动作: {cap}"
    )
