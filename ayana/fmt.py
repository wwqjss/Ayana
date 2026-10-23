"""QQ 通知格式：人类可读，不暴露内部 ID。

完整 ID / 技术细节在 Web 事件详情和审计里。
中文词表唯一来源（P2-3）：ZH_* 只在本模块定义，其他模块 import。
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import re
import shlex

CST = timezone(timedelta(hours=8))

# resolved 统一为「已恢复」（与 fmt_incident_resolved 文案一致）
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
# 事件类型 → 中文（timeline / 通知共用）
ZH_EVENT = {
    "council_received": "接奏",
    "council_investigating": "调查",
    "council_planning": "拟旨",
    "council_reviewing": "会审",
    "council_approved": "准奏",
    "council_vetoed": "封驳",
    "council_executing": "奉旨执行",
    "council_verifying": "验证",
    "council_reporting": "回奏",
    "council_done": "结案",
    "council_manual_required": "转人工裁决",
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
    "agent_waiting": "自动处置暂缓",
    "agent_escalated": "转人工",
    "incident_resolved": "事件解决",
    "incident_reopened": "事件复发",
    "incident_closed": "事件关闭",
    "reconcile_not_seen": "对账未见",
    "reconcile_observed": "对账观察",
    "generation_bumped": "轮次递增",
    "check_failed": "检查失败",
    "check_recovered": "检查恢复",
    "incident_refired": "告警复发",
}


def _t(ts: float | None) -> str:
    if not ts:
        return "刚刚"
    return datetime.fromtimestamp(ts, CST).strftime("%m-%d %H:%M")


def alert_name(text: str) -> str:
    for en, cn in ZH_ALERT.items():
        text = text.replace(en, cn)
    return text


def fmt_incident_open(inc: dict, *, at: float | None = None, refire: bool = False) -> str:
    """新事件 / 复发通知。at 用当前问题时间，不用 created_at（复发时才是今天）。"""
    head = "告警复发" if refire else "告警"
    return (
        f"{head}\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}\n"
        f"时间: {_t(at if at is not None else inc.get('created_at'))}"
    )


def fmt_incident_resolved(inc: dict) -> str:
    return (
        f"已恢复\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}\n"
        f"持续: {_t(inc.get('created_at'))} → {_t(inc.get('resolved_at'))}"
    )


def fmt_council_notice(inc: dict, stage: str, *, reason: str = "", goal: str = "", rounds: list | None = None) -> str:
    """Compact lifecycle notices; callers choose significant transitions only.

    Manual escalation includes the three immutable rounds and concrete vetoes.
    Full evidence stays in the existing authenticated incident timeline.
    """
    labels = {"manual_required": "自治处置需人工裁决", "failed": "自治处置关键失败", "recovered": "自治处置已恢复", "reporting": "自治处置回奏"}
    parts = [labels.get(stage, "自治处置"), alert_name(inc.get("title", "")),
             f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}",
             f"故障轮次: {inc.get('generation') or 1}"]
    if goal:
        parts.append("修复目标: " + str(goal))
    if reason:
        parts.append("原因: " + str(reason))
    for record in (rounds or [])[-3:]:
        plan = record.get("plan") or {}
        parts.append(f"方案 v{record.get('version', '?')}: {plan.get('rationale') or plan.get('repair_goal') or ''}")
        for review in record.get("reviews") or []:
            if review.get("approve") is False:
                parts.append(f"{review.get('provider') or review.get('role', '委员')}封驳: {review.get('reason') or '未提供有效理由'}")
    if stage == "manual_required":
        parts.append("只读调查和监控继续。管理员可在事件详情查看完整证据与三轮方案；重新拟案仍须双委员审议。")
    parts.append("事件: " + str(inc.get("id", "")))
    return "\n".join(parts)


def fmt_agent_exec(inc: dict, rule_name: str, capability: str) -> str:
    if not re.search(r"[\u3400-\u9fff]", rule_name) or re.search(r"\brb_", rule_name):
        rule_name = f"{inc.get('object_id') or '目标服务'} 故障自动处置"
    return (
        f"自动处置\n"
        f"{alert_name(inc.get('title', ''))}\n"
        f"资产: {inc.get('asset_id', '?')} / 对象: {inc.get('object_id', '?')}\n"
        f"动作: {ZH_CAP.get(capability, capability)}\n"
        f"规则: {rule_name}"
    )


def fmt_escalate(inc: dict, reason: str, llm_summary: str = "") -> str:
    """找人通知。reason 是人类可读的原因。"""
    zh_reason = readable_reason(reason)
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


def readable_reason(reason: str) -> str:
    """通知只显示可读原因，完整判据保留在事件与审计。"""
    reasons = {
        "cooldown": "自动处置冷却中，稍后重试",
        "daily_limit": "已达二十四小时自动处置次数上限",
        "budget_exhausted": "自动处置次数已用完",
        "fresh_failed_probe": "等待最新的失败探测结果",
        "exec_channel_ok": "执行通道暂不可用",
        "verification_ready": "恢复验证暂未就绪",
        "object_locked": "已有操作正在处理该对象",
        "global_pause": "自动处置已暂停",
        "control_plane_object": "控制面服务需要人工处理",
        "policy_allowed": "没有自动处置权限",
        "policy_denied": "没有自动处置权限",
        "precondition": "自动处置条件尚未满足，请查看事件详情",
        "awaiting_approval": "处置操作等待授权，请查看事件详情",
        "action_rejected": "本轮处置已选择不执行",
        "approval_expired": "授权请求已过期，请查看事件详情",
        "verify_failed": "恢复验证未通过，请查看事件详情",
        "unsupported_verification_profile": "该对象尚未配置恢复验证",
        "propose_failed": "处置提案未能建立，请查看事件详情",
        "exec_error": "执行出错，请查看事件详情",
        "execution_blocked": "操作已批准，执行条件暂未满足；可在事件详情继续执行",
    }
    for key, value in reasons.items():
        if key in reason:
            return value
    if re.search(r"[\u3400-\u9fff]", reason) and not re.search(r"(?:act|inc|rb)_[A-Za-z0-9_-]+", reason):
        return reason
    return "自动处置暂不可用，请查看事件详情"


def fmt_approve_request(inc: dict, action: dict, *, rule_name: str = "", command: str = "") -> str:
    """一条提案的授权消息，不以内部操作或规则编号要求人回复。"""
    payload = action.get("params") or {}
    if not payload and action.get("params_json"):
        try:
            payload = json.loads(action["params_json"])
        except (TypeError, ValueError):
            payload = {}
    if not isinstance(payload, dict):
        payload = {}
    obj = str(payload.get("object_name") or inc.get("object_id") or "目标服务")
    capability = action.get("capability") or ""
    cap_label = ZH_CAP.get(capability, "处置操作")
    tokens = payload.get("tokens") or []
    if not command and isinstance(tokens, list) and tokens and all(isinstance(t, str) for t in tokens):
        command = shlex.join(tokens)
    if not command and capability in {"service.restart", "service.start", "service.stop"}:
        command = shlex.join(["systemctl", capability.split(".")[-1], obj])
    if not rule_name or not re.search(r"[\u3400-\u9fff]", rule_name) or re.search(r"\brb_", rule_name):
        rule_name = f"{obj} 探测失败自动{cap_label.removesuffix('服务').removesuffix('容器')}"
    return (
        f"需要你授权\n{alert_name(inc.get('title', ''))}\n"
        f"动作: {cap_label}{' ' + command if command else ''}\n"
        f"规则: {rule_name}\n\n"
        "回复一个：\n"
        "执行一次 → 只执行这次\n"
        "不执行 → 跳过\n"
        "永久允许执行 → 以后自动执行，不再询问\n"
        "如有多条待授权操作，请在事件详情中选择。"
    )


def fmt_auto_wait(inc: dict, *, reason: str, retry_at: float | None = None) -> str:
    body = f"自动处置暂缓\n{alert_name(inc.get('title', ''))}\n原因: {readable_reason(reason)}"
    if retry_at:
        label = "下次可执行时间" if "冷却" in reason or "cooldown" in reason else "下次自动检查时间"
        body += f"\n{label}: {_t(retry_at)}（北京时间）"
    return body


def approval_error(code: str) -> str:
    return {
        "approval_ambiguous": "有多条待授权操作，请打开事件详情，选择对应操作后授权。",
        "approval_not_found": "当前没有可授权的操作，可能已经处理或过期。",
        "not_found": "当前没有可授权的操作，可能已经处理或过期。",
        "approve_denied": "你没有批准此操作的权限，请联系管理员。",
        "reject_denied": "你没有拒绝此操作的权限，请联系管理员。",
        "admin_required": "永久允许执行需要管理员授权，请联系管理员或在控制台操作。",
        "permanent_admin_required": "永久允许执行需要管理员授权，请联系管理员或在控制台操作。",
        "self_approve_denied": "此操作需要另一位有权限的人批准。",
        "approval_expired": "这条授权请求已过期，请查看事件详情。",
        "bad_state": "此操作已经处理，请查看事件详情。",
        "expired": "这条授权请求已过期，请查看事件详情。",
        "permanent_agent_only": "只有系统提出的处置操作才能设置以后自动执行。",
        "permanent_allow_denied": "此目标已有禁止执行规则，永久允许不能覆盖禁止项。",
        "denied_by_agent_ceiling": "系统权限上限不允许此类自动处置，请联系管理员。",
        "control_plane_forbidden": "控制面服务不能永久允许自动执行，请人工处理。",
    }.get(code, "授权未完成，请在事件详情查看权限或执行条件。")
