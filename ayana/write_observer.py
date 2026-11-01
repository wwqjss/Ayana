"""Read-only reconciliation of durable, structured write requests.

No command replay and no inference from model prose. Unknown historical shell
commands without an objective verifier keep their lock and get a clear status.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .promconfig import CONFIG_FILE, MANAGED_FILE_SD, MANAGED_JOB, parse_simple_yaml


PROM_TOOLS = frozenset({"config.prom_target_add", "config.prom_target_update", "config.prom_target_delete"})


def _object_json(value: str) -> dict:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def recover_native_operation(row: dict, messages: list, bridge: Any, remote_id: str) -> dict:
    """Recover exact legacy MCP input only when both durable fingerprints match."""
    sid = row["session_id"]
    for message in messages if isinstance(messages, list) else []:
        info = message.get("info", {}) if isinstance(message, dict) else {}
        if info.get("role") != "assistant" or info.get("sessionID") not in (None, remote_id):
            continue
        for part in message.get("parts", []) if isinstance(message.get("parts"), list) else []:
            if not isinstance(part, dict) or part.get("type") != "tool" or part.get("tool") != "mcp_tool_use":
                continue
            state = part.get("state")
            inputs = state.get("input") if isinstance(state, dict) else None
            if not isinstance(inputs, dict) or not isinstance(inputs.get("arguments"), dict):
                continue
            name = next((tool for tool in PROM_TOOLS if inputs.get("name") == "ayana_" + tool.replace(".", "_")), "")
            if not name:
                continue
            args = inputs["arguments"]
            if bridge.make_action_key(sid, name, args, context="mcp-tool-write") != row["action_key"]:
                continue
            payload = {"_ayana_session_id": sid, "_ayana_tool": name, "_ayana_arguments": args}
            fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:16]
            if row.get("params_hash") and row["params_hash"] != fingerprint:
                continue
            return {"tool": name, "arguments": args, "source": "native_tool_input",
                    "message_id": info.get("id", ""), "part_id": part.get("id", "")}
    return {}


def _probe_present(raw: str, args: dict) -> bool:
    data = parse_simple_yaml(raw)
    if not isinstance(data, dict):
        return False
    probe = args.get("probe") or {}
    expected_labels = args.get("labels") or {}
    expected_rules = [
        {"source_labels": ["__address__"], "target_label": "__param_target"},
        {"source_labels": ["__param_target"], "target_label": "instance"},
        {"target_label": "__address__", "replacement": probe.get("exporter")},
    ]
    for job in data.get("scrape_configs") or []:
        if not isinstance(job, dict) or job.get("metrics_path") != "/probe" or job.get("scheme", "http") != "http":
            continue
        if probe.get("job_name") and job.get("job_name") != probe["job_name"]:
            continue
        if (job.get("params") or {}).get("module") != [probe.get("module", "http_2xx")]:
            continue
        # Prometheus expands default keys in loaded config. Check each requested
        # relabel operation and reject additional transformations.
        rules = job.get("relabel_configs") or []
        if len(rules) != len(expected_rules) or job.get("metric_relabel_configs"):
            continue
        if not all(isinstance(rule, dict) and rule.get("action", "replace") == "replace"
                   and all(rule.get(key) == value for key, value in expected.items())
                   for rule, expected in zip(rules, expected_rules)):
            continue
        if any(isinstance(group, dict) and args.get("address") in (group.get("targets") or [])
               and all((group.get("labels") or {}).get(key) == value for key, value in expected_labels.items())
               for group in job.get("static_configs") or []):
            return True
    return False


def _live_probe_present(targets: list, args: dict) -> bool:
    """Match the active JSON target, independent of Prometheus YAML formatting."""
    probe = args.get("probe") or {}
    address, exporter = args.get("address"), probe.get("exporter")
    module = probe.get("module", "http_2xx")
    job = probe.get("job_name")
    if job is None:
        fingerprint = json.dumps([address, exporter, module], separators=(",", ":")).encode()
        job = "ayana-probe-" + hashlib.sha256(fingerprint).hexdigest()[:16]
    try:
        expected = urlsplit("http://" + exporter + "/probe")
    except (TypeError, ValueError):
        return False
    for target in targets:
        if not isinstance(target, dict) or target.get("scrapePool") != job:
            continue
        labels = target.get("labels") or {}
        if not isinstance(labels, dict) or labels.get("instance") != address or any(
                labels.get(key) != value for key, value in (args.get("labels") or {}).items()):
            continue
        raw_url = target.get("scrapeUrl")
        if not isinstance(raw_url, str) or any(ord(char) <= 32 or ord(char) == 127 for char in raw_url):
            continue
        try:
            actual = urlsplit(raw_url)
            query = parse_qs(actual.query, keep_blank_values=True, strict_parsing=True)
            if (actual.scheme != "http" or actual.hostname != expected.hostname or actual.port != expected.port
                    or actual.username is not None or actual.password is not None or actual.fragment
                    or actual.path != "/probe" or query != {"module": [module], "target": [address]}):
                continue
        except (TypeError, ValueError):
            continue
        return True
    return False


async def observe_prom_target(pc: Any, operation: dict) -> dict:
    """Confirm requested *configuration effect*, independently of target health."""
    tool = operation.get("tool")
    args = operation.get("arguments")
    if tool not in PROM_TOOLS or not isinstance(args, dict) or not pc:
        return {"status": "unsupported", "message": "这条历史操作缺少可自动核实的请求记录；相关变更暂缓，无需猜测结果。"}
    if args.get("probe"):
        if tool != "config.prom_target_add":
            return {"status": "unsupported", "message": "这类探测目标修改尚无可靠的自动验证规则；相关变更暂缓。"}
        raw = await pc.fs.read_text(CONFIG_FILE)
        if not _probe_present(raw, args):
            return {"status": "pending", "message": "系统尚未在监控配置中确认所需探测目标，将继续自动检查。"}
        if not pc.prom:
            return {"status": "pending", "message": "配置文件已包含目标，正在等待监控服务确认已加载。"}
        # Prometheus normalises YAML into indentless sequences that the tiny
        # source-preserving parser does not support. The active-target JSON is
        # the direct runtime fact: verify pool, labels, exporter, module and URL.
        live = await pc.prom.targets()
        if not isinstance(live, list) or not _live_probe_present(live, args):
            return {"status": "pending", "message": "配置文件已包含目标，正在等待监控服务确认已加载。"}
        return {"outcome": "executed", "evidence": {"kind": "prometheus_live_probe",
                "summary": "已从配置文件和 Prometheus 实际生效的探测目标确认目标地址、标签、探测器及模块均符合请求。"}}
    items = json.loads(await pc.fs.read_text(MANAGED_FILE_SD))
    if not isinstance(items, list):
        raise ValueError("invalid discovery file")
    deleted = tool == "config.prom_target_delete"
    address = (args.get("new_address") if tool == "config.prom_target_update" else None) or args.get("address")
    labels = {} if deleted else args.get("labels")
    present = any(isinstance(item, dict) and address in (item.get("targets") or []) and
                  all((item.get("labels") or {}).get(key) == value for key, value in (labels or {}).items()) for item in items)
    if (deleted and present) or (not deleted and not present):
        return {"status": "pending", "message": "系统尚未在配置中确认本次目标变更，将继续自动检查。"}
    if not pc.prom:
        return {"status": "pending", "message": "配置状态已确认，正在等待监控服务确认实际加载结果。"}
    live = await pc.prom.targets()
    if not isinstance(live, list):
        raise ValueError("invalid target response")
    def managed_target(target, target_address):
        return (isinstance(target, dict) and target.get("scrapePool") == MANAGED_JOB
                and ((target.get("discoveredLabels") or {}).get("__address__") == target_address
                     or (target.get("labels") or {}).get("instance") == target_address))
    live_present = any(managed_target(target, address)
                       and all((target.get("labels") or {}).get(key) == value for key, value in (labels or {}).items()) for target in live)
    if live_present == deleted:
        return {"status": "pending", "message": "配置状态已确认，正在等待监控服务确认实际加载结果。"}
    if tool == "config.prom_target_update" and args.get("new_address") and args["new_address"] != args.get("address"):
        if any(args["address"] in (item.get("targets") or []) for item in items) or any(
                managed_target(target, args["address"]) for target in live):
            return {"status": "pending", "message": "新目标已出现，系统仍在检查旧目标是否已完成替换。"}
    return {"outcome": "executed", "evidence": {"kind": "prometheus_live_target",
            "summary": "已从目标配置和 Prometheus 实际目标列表确认本次目标变更。"}}


async def reconcile_write_results(db: Any, bridge: Any, *, promconfig: Any = None,
                                  native_client: Any = None, host_observer: Any = None) -> int:
    """One bounded pass. Observers may read; they must never resubmit writes."""
    stamp = time.time()
    # A lease expiry is uncertainty; a late definitive result may still complete
    # the same operation. Expiry never releases a lock or authorises a replay.
    db.execute("UPDATE session_write_ops SET status='unknown',result='lease_expired',updated_at=? "
               "WHERE status='claimed' AND lease_expires_at>0 AND lease_expires_at<?", (stamp, stamp))
    rows = db.query("SELECT * FROM session_write_ops WHERE status='unknown' AND COALESCE(CASE WHEN json_valid(reconciliation_json) "
                    "THEN CAST(json_extract(reconciliation_json,'$.next_check_at') AS REAL) END,0)<=? "
                    "ORDER BY COALESCE(CASE WHEN json_valid(reconciliation_json) THEN CAST(json_extract(reconciliation_json,'$.checked_at') AS REAL) END,0),"
                    "updated_at LIMIT 5", (stamp,))
    histories: dict[str, list] = {}
    resolved = 0
    for raw in rows:
        row = dict(raw)
        operation = _object_json(row.get("operation_json", ""))
        try:
            if not operation.get("arguments") and native_client and row.get("session_id") and ":config.prom_target_" in row["action_key"]:
                session = bridge.duty.get(row["session_id"]) or {}
                rid = session.get("remote_session_id") or ""
                if rid:
                    if rid not in histories:
                        histories[rid] = await asyncio.wait_for(native_client.messages(rid, limit=200), timeout=5)
                    recovered = recover_native_operation(row, histories[rid], bridge, rid)
                    if recovered:
                        operation = recovered
                        bridge.set_write_observation(row["incident_id"], row["action_key"], operation=operation)
            checking = {"status": "checking", "message": "系统正在读取执行凭据与实际配置，自动确认结果。", "checked_at": stamp}
            if operation.get("tool") in PROM_TOOLS:
                bridge.set_write_observation(row["incident_id"], row["action_key"], reconciliation=checking)
                result = await asyncio.wait_for(observe_prom_target(promconfig, operation), timeout=20)
            elif host_observer and (operation.get("tool") == "host.exec" or ":exec_shell:" in row["action_key"]):
                result = await asyncio.wait_for(host_observer(row, operation), timeout=20)
            else:
                result = {"status": "unsupported", "message": "这条历史操作未保留足够的执行凭据，系统无法可靠确认结果；相关变更暂缓，无需猜测结果。"}
            if result.get("outcome") in ("executed", "not_executed", "retry_safe") and result.get("evidence"):
                resolution = bridge.resolve_write_result(row["incident_id"], row["action_key"],
                    outcome=result["outcome"], evidence=result["evidence"])
                resolved += bool(resolution.get("ok"))
                continue
            result = {**result, "checked_at": stamp, "next_check_at": stamp + 60}
        except Exception:
            # Network failures are absence of evidence, never proof of failure.
            result = {"status": "pending", "checked_at": stamp, "next_check_at": stamp + 60,
                      "message": "自动检查暂时未取得完整结果，系统将在一分钟后复查；相关变更暂缓。"}
        bridge.set_write_observation(row["incident_id"], row["action_key"], reconciliation=result)
    return resolved
