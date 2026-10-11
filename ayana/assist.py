"""自然语言辅助配置（表单副驾驶）。

约束（硬）：
- 只查询、只填写、只定位界面；不执行、不保存、不调 /exec
- 字段必须过 schema；未知字段丢弃；缺失进 missing 由前端追问
- LLM 可用时理解复杂中文；失败/未配置 → 确定性解析兜底
- 状态/权限展示一律来自现有引擎，不编造
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable

log = logging.getLogger("ayana.assist")

# ── 字段 schema（checks）────────────────────────────────────────
CHECK_KINDS = ("port", "service", "command")
CHECK_SEVERITIES = ("info", "warning", "critical")
CHECK_EXPECTS = ("exit0", "contains", "not_contains")

CHECK_FIELDS: dict[str, dict[str, Any]] = {
    "asset_id": {"type": "str", "required": True},
    "kind": {"type": "enum", "values": CHECK_KINDS, "default": "port"},
    "name": {"type": "str", "max": 64},
    "params.port": {"type": "int", "min": 1, "max": 65535},
    "params.proto": {"type": "enum", "values": ("tcp", "udp"), "default": "tcp"},
    "params.unit": {"type": "str", "max": 64},
    "params.cmd": {"type": "str", "max": 500},
    "expect.mode": {"type": "enum", "values": CHECK_EXPECTS, "default": "exit0"},
    "expect.value": {"type": "str", "max": 200},
    "interval_sec": {"type": "int", "min": 15, "max": 3600, "default": 60},
    "fail_threshold": {"type": "int", "min": 1, "max": 10, "default": 2},
    "severity": {"type": "enum", "values": CHECK_SEVERITIES, "default": "warning"},
}

# ── 字段 schema（permissions）───────────────────────────────────
PERM_STATES = ("deny", "confirm", "auto")
PERM_FIELDS: dict[str, dict[str, Any]] = {
    "capability": {"type": "str", "required": False},
    "asset_id": {"type": "str"},
    "object_id": {"type": "str", "default": "*"},
    "state": {"type": "enum", "values": PERM_STATES},
    "scope": {"type": "enum", "values": ("default", "exception"), "default": "default"},
}

CAP_ALIASES = {
    "查看状态": "asset.summary",
    "资产摘要": "asset.summary",
    "查看服务状态": "service.status",
    "服务状态": "service.status",
    "查看日志": "service.logs",
    "日志": "service.logs",
    "重启服务": "service.restart",
    "重启": "service.restart",
    "启动服务": "service.start",
    "停止服务": "service.stop",
    "重启容器": "container.restart",
    "容器重启": "container.restart",
    "查看端口": "port.listen",
    "端口": "port.listen",
    "磁盘": "disk.usage",
    "内存": "memory.available",
    "负载": "load.current",
    "探测": "probe.status",
}

KIND_KEYWORDS = {
    "port": ("端口", "tcp", "udp", "端口监听", "port"),
    "service": ("服务", "systemd", "服务启动", "service", "unit"),
    "command": ("命令", "curl", "脚本", "command", "cmd", "自定义"),
}


def _validate_fields(raw: dict[str, Any], schema: dict[str, dict[str, Any]]) -> tuple[dict, list[str]]:
    """过 schema：非法丢弃。返回 (fields, unknown_keys)。"""
    out: dict[str, Any] = {}
    unknown: list[str] = []
    for k, v in (raw or {}).items():
        spec = schema.get(k)
        if not spec:
            unknown.append(k)
            continue
        t = spec.get("type")
        try:
            if t == "int":
                iv = int(v)
                if "min" in spec and iv < spec["min"]:
                    continue
                if "max" in spec and iv > spec["max"]:
                    continue
                out[k] = iv
            elif t == "enum":
                sv = str(v).strip().lower()
                if sv in (spec.get("values") or ()):
                    out[k] = sv
            else:
                sv = str(v).strip()
                if not sv:
                    continue
                if len(sv) > int(spec.get("max") or 200):
                    sv = sv[: int(spec.get("max") or 200)]
                out[k] = sv
        except Exception:
            continue
    return out, unknown


def _flatten(prefix: str, d: dict) -> dict:
    out = {}
    for k, v in (d or {}).items():
        if isinstance(v, dict):
            out.update(_flatten(f"{prefix}.{k}" if prefix else k, v))
        else:
            out[f"{prefix}.{k}" if prefix else k] = v
    return out


def parse_checks_rules(text: str, *, assets: list[str], existing_names: list[str]) -> dict[str, Any]:
    """确定性解析：业务检查。"""
    t = (text or "").strip()
    fields: dict[str, Any] = {}
    missing: list[dict] = []
    notes: list[str] = []

    # 资产
    for a in assets:
        if a.lower() in t.lower():
            fields["asset_id"] = a
            break

    # 类型
    for kind, kws in KIND_KEYWORDS.items():
        if any(k in t.lower() or k in t for k in kws):
            fields["kind"] = kind
            break

    # 名称：「叫/名称/叫做」
    m = re.search(r"(?:叫|名称是|名称为|叫做|命名)[为是]?\s*([A-Za-z0-9_\-]{1,32})", t)
    if m:
        fields["name"] = m.group(1)

    # 端口：8080 端口 / 端口 8080 / port:8080（禁止无中生有）
    m = re.search(r"(?:端口|port)[:：\s]*(\d{1,5})", t, re.I)
    if not m:
        m = re.search(r"(\d{2,5})\s*(?:端口|port)", t, re.I)
    if m:
        p = int(m.group(1))
        if 1 <= p <= 65535:
            fields["params.port"] = p
            fields.setdefault("kind", "port")

    # 「程序/进程/服务是否正常运行」→ 服务或命令，不是端口
    if "kind" not in fields and any(
        k in t for k in ("程序", "进程", "服务是否", "是否正常", "是否运行", "运行状态", "是否在跑")
    ):
        fields["kind"] = "service"
        # 没有具体 unit 名 → 追问，不猜
        if not re.search(r"(?:服务|service|unit|程序名|进程名)[:：\s]*([A-Za-z0-9_\-\.\@]{1,64})", t, re.I):
            if "params.unit" not in fields:
                pass  # 走 missing

    # 服务名
    m = re.search(r"(?:服务|service|unit)[:：\s]*([A-Za-z0-9_\-\.\@]{1,64})", t, re.I)
    if m and "params.unit" not in fields:
        fields["params.unit"] = m.group(1)
        fields.setdefault("kind", "service")

    # URL / curl → command
    if "curl" in t.lower() or re.search(r"https?://", t, re.I):
        fields.setdefault("kind", "command")
        m = re.search(r"(curl\s+.+|https?://\S+)", t, re.I)
        if m:
            cmd = m.group(1).strip()
            if not cmd.lower().startswith("curl") and "://" in cmd:
                cmd = f"curl -f {cmd}"
            fields["params.cmd"] = cmd

    # 间隔：每 N 秒 / N 秒 / 每 N 分钟
    m = re.search(r"每\s*(\d+)\s*(秒|s|分钟|min|m)", t, re.I)
    if m:
        n = int(m.group(1))
        unit = m.group(2).lower()
        fields["interval_sec"] = max(15, min(3600, n * 60 if unit.startswith("m") or unit == "分钟" else n))
    else:
        m = re.search(r"间隔\s*(\d+)\s*(秒|s|分钟|min)", t, re.I)
        if m:
            n = int(m.group(1))
            unit = m.group(2).lower()
            fields["interval_sec"] = max(15, min(3600, n * 60 if unit.startswith("m") else n))

    # 连续失败
    m = re.search(r"(?:连续|连续失败|失败)\s*(\d+)\s*(次|回)?", t)
    if m:
        fields["fail_threshold"] = max(1, min(10, int(m.group(1))))

    # 级别
    if any(k in t for k in ("严重", "critical", "紧急", "P1")):
        fields["severity"] = "critical"
    elif any(k in t for k in ("提示", "info", "信息", "低")):
        fields["severity"] = "info"
    elif any(k in t for k in ("警告", "warning", "告警级别", "warn")):
        fields["severity"] = "warning"

    # 名称默认（仅在目标明确时）
    if "name" not in fields:
        if fields.get("kind") == "port" and fields.get("params.port"):
            fields["name"] = f"port-{fields['params.port']}"
        elif fields.get("kind") == "service" and fields.get("params.unit"):
            fields["name"] = str(fields["params.unit"])[:32]
        elif fields.get("kind") == "command" and fields.get("params.cmd"):
            fields["name"] = "http-check"

    # 缺失追问
    if "asset_id" not in fields:
        missing.append({"key": "asset_id", "label": "主机", "question": "要监控哪台主机？"})
    if "kind" not in fields:
        missing.append({"key": "kind", "label": "检查类型", "question": "检查类型是端口、服务，还是自定义命令？"})
    elif fields["kind"] == "port" and "params.port" not in fields:
        missing.append({"key": "params.port", "label": "端口", "question": "要检查哪个端口？"})
    elif fields["kind"] == "service" and "params.unit" not in fields:
        missing.append({"key": "params.unit", "label": "服务名", "question": "要检查哪个服务名？"})
    elif fields["kind"] == "command" and "params.cmd" not in fields:
        missing.append({"key": "params.cmd", "label": "命令", "question": "要执行什么命令来判定成功？"})

    if fields.get("name") and fields["name"] in existing_names:
        notes.append(f"名称「{fields['name']}」可能已存在，提交前可改名。")

    return {
        "domain": "checks",
        "route": "checks_form",
        "action": "fill",
        "fields": fields,
        "missing": missing,
        "notes": notes,
        "source": "rules",
    }


def parse_perm_rules(text: str, *, assets: list[str], capabilities: list[str]) -> dict[str, Any]:
    """确定性解析：权限工作台定位 + 填表。"""
    t = (text or "").strip()
    fields: dict[str, Any] = {}
    missing: list[dict] = []
    notes: list[str] = []

    # 路由：查询例外 / ceiling / 生效 / 默认
    route = "perm_defaults"
    if any(k in t for k in ("例外", "特殊授权", "覆盖", "单独授权")):
        route = "perm_exceptions"
    if any(k in t for k in ("上限", "ceiling", "Agent 权限", "agent 上限")):
        route = "perm_ceiling"
    if any(k in t for k in ("生效", "最终", "查看.*权限", "查一下.*权限", "有什么权限")):
        if any(k in t for k in ("修改", "改成", "设置", "允许", "禁止", "放开")):
            route = "perm_workbench"
        else:
            route = "perm_effective"
    if any(k in t for k in ("默认策略", "所有服务器", "全部资产", "所有资产", "统一")):
        route = "perm_defaults"
    if any(k in t for k in ("修改", "改成", "设置为", "允许", "禁止", "需要确认", "自动执行", "放开")):
        if route == "perm_effective":
            route = "perm_workbench"
        fields["scope"] = "default" if route == "perm_defaults" else "exception"

    # 资产
    for a in assets:
        if a.lower() in t.lower():
            fields["asset_id"] = a
            fields["scope"] = "exception"
            break

    # 能力（先匹配更长别名，避免「重启」抢「容器重启」）
    for label, cap in sorted(CAP_ALIASES.items(), key=lambda x: -len(x[0])):
        if label in t:
            fields["capability"] = cap
            break
    if "capability" not in fields:
        for cap in capabilities:
            if cap.lower() in t.lower():
                fields["capability"] = cap
                break

    # 对象
    m = re.search(r"(?:对象|服务|容器|unit|容器名)[:：\s]*([A-Za-z0-9_\-\.\@]{1,64})", t, re.I)
    if m:
        fields["object_id"] = m.group(1)

    # 三态
    if any(k in t for k in ("禁止", "不允许", "禁止掉", "不要")):
        fields["state"] = "deny"
    elif any(k in t for k in ("自动", "自动执行", "放开自动", "无需确认", "不用确认")):
        fields["state"] = "auto"
    elif any(k in t for k in ("需要确认", "要确认", "人工确认", "先确认", "审批")):
        fields["state"] = "confirm"

    # 缺失
    if route in ("perm_workbench", "perm_effective", "perm_exceptions"):
        if "capability" not in fields:
            missing.append({"key": "capability", "label": "操作", "question": "要查看或修改哪类操作？例如：查看日志 / 重启服务"})
    if route == "perm_workbench" and "state" not in fields:
        missing.append({"key": "state", "label": "策略", "question": "改成禁止、需要确认，还是自动执行？"})
    if route == "perm_defaults" and "capability" not in fields and "state" not in fields:
        missing.append({"key": "capability", "label": "操作", "question": "要统一配置哪类操作？例如：所有服务器「查看日志」自动、「重启服务」需确认"})

    return {
        "domain": "permissions",
        "route": route,
        "action": "fill",
        "fields": fields,
        "missing": missing,
        "notes": notes,
        "source": "rules",
    }


async def _llm_intent(
    llm: Any,
    *,
    domain: str,
    text: str,
    context: dict[str, Any],
    assets: list[str],
    capabilities: list[str],
    form_payload: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """(结果, 失败原因)。只出字段草稿，不碰执行。

    Prompt 不包含任何具体技术名词的标准答案；
    以真实表单定义 + 资产/能力上下文驱动模型自行推断。
    """
    if not llm or not getattr(llm, "enabled", False):
        return None, "llm_disabled"
    from . import formspec as fs

    payload = form_payload or fs.form_prompt_payload(
        domain, assets=assets, capabilities=capabilities, extra=context
    )
    system = (
        "你是 Ayana 运维控制台的表单填写助手。\n"
        "用户会用自然语言描述想监控/配置什么；你根据「表单定义 + 真实上下文」"
        "理解意图，推断技术对象，返回可填入真实表单的结构化 JSON。\n"
        "你不执行、不保存、不扩权。\n\n"
        "必须遵守：\n"
        "1. 字段名只能来自 form.fields；禁止编造端口/名称/命令/资产。\n"
        "2. 利用你自己的技术知识推断用户指的组件（容器运行时、网络插件、代理等），"
        "但必须把推断写进 inferred 并给出 confirm_question，等待用户确认。\n"
        "3. 遵守 form.constraints 与 capability_boundary："
        "检查类型必须落在系统实际支持的方式上；不要把无法映射到本表单能力的对象"
        "硬套进错误 kind。\n"
        "4. 资产只能来自 context.assets；能力名只能来自 context.capabilities。\n"
        "5. 信息不足 → missing 列出具体问题，不要用默认值冒充用户意图。\n"
        "6. 合理默认（如 interval_sec）可填 default，但须在 inferred 标注。\n"
        "7. 请求超出本表单能力 → unsupported，给出 alternatives。\n"
        "8. 只输出 JSON 对象，符合 output_schema，不要 Markdown。\n"
    )
    user = json.dumps(
        {"user_input": text[:800], "scene": payload},
        ensure_ascii=False,
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    raw = None
    err = ""
    # 优先 json_mode；失败再普通对话 + 修复
    for attempt in range(2):
        try:
            resp = await llm.chat_raw(
                messages, max_tokens=1600, json_mode=(attempt == 0), temperature=0.2
            )
        except Exception as e:
            err = f"chat_exception:{e}"
            continue
        if not resp or not resp.get("content"):
            err = err or "empty_content"
            continue
        raw = resp.get("content") or ""
        data = _extract_json_object(raw)
        if isinstance(data, dict):
            return data, ""
        err = "json_extract_failed"
        log.warning(
            "assist llm json extract failed attempt=%s head=%s",
            attempt,
            raw[:180].replace("\n", " "),
        )
    log.warning("assist llm intent failed: %s", err)
    return None, err or "unknown"


def _extract_json_object(raw: str) -> dict[str, Any] | None:
    """从模型输出提取 JSON：容错代码块、尾逗号、单引号、截断括号。"""
    if not raw:
        return None
    s = raw.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    m = re.search(r"\{[\s\S]*\}", s)
    blob = m.group(0) if m else (s if s.startswith("{") else "")
    if not blob:
        return None
    candidates = [
        blob,
        re.sub(r",\s*([}\]])", r"\1", blob),
        blob.replace("'", '"'),
    ]
    # 截断修复：按括号栈补齐缺失的 }"/ 项
    repaired = _repair_truncated_json(blob)
    if repaired:
        candidates.append(repaired)
        candidates.append(re.sub(r",\s*([}\]])", r"\1", repaired))
    for attempt in candidates:
        try:
            data = json.loads(attempt)
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return None


def _repair_truncated_json(blob: str) -> str | None:
    """尽力闭合因 max_tokens 截断的 JSON。"""
    if not blob or not blob.startswith("{"):
        return None
    out = []
    stack: list[str] = []
    in_str = False
    esc = False
    for ch in blob:
        out.append(ch)
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]":
            if stack and stack[-1] == ch:
                stack.pop()
    tail = "".join(out)
    # 未闭合字符串
    if in_str:
        tail += '"'
    # 去掉尾部悬挂逗号 / 半个字段
    tail = re.sub(r",\s*$", "", tail)
    # 若最后像 "key" 或 "key": 无值，截掉
    tail = re.sub(r',?\s*"[^"]*"?\s*:?\s*$', "", tail)
    tail = re.sub(r",\s*$", "", tail)
    for closer in reversed(stack):
        tail += closer
    try:
        data = json.loads(tail)
        return tail if isinstance(data, dict) else None
    except Exception:
        # 再试去尾逗号
        try:
            t2 = re.sub(r",\s*([}\]])", r"\1", tail)
            data = json.loads(t2)
            return t2 if isinstance(data, dict) else None
        except Exception:
            return None


def build_check_summary(fields: dict[str, Any]) -> str:
    """固定模板人话摘要（禁止 AI 生成）。"""
    kind = fields.get("kind") or "port"
    name = fields.get("name") or "（未命名）"
    asset = fields.get("asset_id") or "（未选主机）"
    interval = fields.get("interval_sec", 60)
    fails = fields.get("fail_threshold", 2)
    sev = fields.get("severity") or "warning"
    sev_zh = {"info": "提示", "warning": "警告", "critical": "严重"}.get(sev, sev)
    if kind == "port":
        target = f"端口 {fields.get('params.port', '?')}/{fields.get('params.proto', 'tcp')}"
    elif kind == "service":
        target = f"服务 {fields.get('params.unit', '?')}"
    else:
        target = f"命令 {fields.get('params.cmd', '?')}"
    return (
        f"将在「{asset}」上添加检查「{name}」：{target}；"
        f"每 {interval} 秒检测一次，连续 {fails} 次失败触发 {sev_zh} 告警。"
        f"点「添加检查」才会真正创建。"
    )


async def configure(
    *,
    domain: str,
    text: str,
    context: dict[str, Any] | None = None,
    llm: Any = None,
    assets: list[str] | None = None,
    capabilities: list[str] | None = None,
    existing_names: list[str] | None = None,
) -> dict[str, Any]:
    """统一辅助配置入口。返回可填表结果；绝不写库。"""
    ctx = context or {}
    assets = assets or []
    capabilities = capabilities or []
    existing_names = existing_names or []
    text = (text or "").strip()
    if not text:
        return {
            "ok": False,
            "error": "empty",
            "message": "请描述你想配置什么",
        }
    if domain not in ("checks", "permissions"):
        return {"ok": False, "error": "bad_domain", "message": "仅支持 checks / permissions"}

    # 1) LLM 优先（表单定义 + 真实上下文，无答案级示例）
    result: dict[str, Any] | None = None
    llm_error = ""
    llm_raw = None
    try:
        llm_raw, llm_error = await _llm_intent(
            llm,
            domain=domain,
            text=text,
            context=ctx,
            assets=assets,
            capabilities=capabilities,
        )
    except Exception as e:
        llm_raw = None
        llm_error = f"intent_exception:{str(e)[:120]}"

    if llm_raw and isinstance(llm_raw.get("fields"), dict):
        schema = CHECK_FIELDS if domain == "checks" else PERM_FIELDS
        nested = llm_raw.get("fields") or {}
        flat: dict[str, Any] = {}
        for k, v in nested.items():
            if isinstance(v, dict):
                flat.update(_flatten(k, v))
            else:
                flat[k] = v
        # 资产白名单：不允许凭空资产
        if domain == "checks" and flat.get("asset_id") and assets:
            if flat["asset_id"] not in assets:
                flat.pop("asset_id", None)
        if domain == "permissions" and flat.get("asset_id") and assets:
            if flat["asset_id"] not in assets:
                flat.pop("asset_id", None)
        fields, unknown = _validate_fields(flat, schema)
        missing = [
            {"key": str(m.get("field") or m.get("key") or ""), "label": str(m.get("label") or ""), "question": str(m.get("question") or "请补充信息")}
            for m in (llm_raw.get("missing") or [])
            if isinstance(m, dict) and (m.get("field") or m.get("key"))
        ]
        if domain == "checks" and "asset_id" not in fields:
            missing.append({"key": "asset_id", "label": "主机", "question": "要监控哪台主机？"})
        notes = [str(n) for n in (llm_raw.get("notes") or []) if n]
        if unknown:
            notes.append("已忽略无法识别的字段：" + ", ".join(unknown[:6]))
        # inferred 兼容字符串/对象
        inferred_raw = llm_raw.get("inferred") or []
        inferred = []
        inferred_detail = []
        for item in inferred_raw:
            if isinstance(item, str):
                inferred.append(item)
            elif isinstance(item, dict):
                fname = str(item.get("field") or item.get("key") or "")
                if fname:
                    inferred.append(fname)
                    inferred_detail.append(
                        {
                            "field": fname,
                            "reason": str(item.get("reason") or ""),
                            "confidence": str(item.get("confidence") or ""),
                        }
                    )
        confirm_q = str(llm_raw.get("confirm_question") or "").strip()
        unsup = llm_raw.get("unsupported")
        if isinstance(unsup, dict) and unsup.get("reason"):
            notes.append("不支持：" + str(unsup.get("reason")))
            alts = unsup.get("alternatives") or []
            if alts:
                notes.append("可选：" + ", ".join(str(a) for a in alts[:4]))
        result = {
            "ok": True,
            "domain": domain,
            "route": llm_raw.get("route") or ("checks_form" if domain == "checks" else "perm_workbench"),
            "action": "fill",
            "fields": fields,
            "inferred": inferred,
            "inferred_detail": inferred_detail,
            "confirm_question": confirm_q,
            "missing": missing,
            "notes": notes,
            "source": "llm",
            "llm_error": "",
        }

    # 2) 规则兜底 / 合并（不覆盖 LLM 已给出的 kind/目标，避免猜端口）
    if domain == "checks":
        rules = parse_checks_rules(text, assets=assets, existing_names=existing_names)
    else:
        rules = parse_perm_rules(text, assets=assets, capabilities=capabilities)

    if not result:
        result = dict(rules)
        result["ok"] = True
        result["inferred"] = []
        result["confirm_question"] = ""
        # 规则路径：若无法推断关键目标，明确说明，不冒充语义理解
        if domain == "checks":
            f = result.get("fields") or {}
            if f.get("kind") == "service" and not f.get("params.unit"):
                result.setdefault("notes", []).append(
                    "规则模式只能做关键词匹配，无法从技术描述推断组件名；配置 LLM 后可语义理解。"
                )
        if llm_error:
            result.setdefault("notes", []).append("语言模型解析失败（" + llm_error + "），已用规则解析。")
            result["llm_error"] = llm_error
        elif llm and getattr(llm, "enabled", False):
            result.setdefault("notes", []).append("语言模型未返回可用结果，已用规则解析。")
            result["llm_error"] = llm_error or "no_usable_result"
        elif not llm or not getattr(llm, "enabled", False):
            result.setdefault("notes", []).append("当前未启用语言模型，仅关键词解析。")
            result["llm_error"] = "llm_disabled"
    else:
        # LLM 缺的用规则补；但不把规则猜的 port 强加到 LLM 的 service/command 上
        llm_kind = (result.get("fields") or {}).get("kind")
        for k, v in rules.get("fields", {}).items():
            if llm_kind in ("service", "command") and k in ("kind", "params.port", "params.proto", "name"):
                continue
            result["fields"].setdefault(k, v)
        if rules.get("route") and not result.get("route"):
            result["route"] = rules["route"]
        have = {m.get("key") for m in result.get("missing") or []}
        for m in rules.get("missing") or []:
            if m["key"] not in have and m["key"] not in result["fields"]:
                result["missing"].append(m)
        # LLM 给了 confirm_question 时，保留并展示
        if not result.get("confirm_question"):
            result["confirm_question"] = ""

    if domain == "checks":
        result["summary"] = build_check_summary(result.get("fields") or {})
    else:
        result["summary"] = ""

    return result
