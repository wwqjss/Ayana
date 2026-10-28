"""真实表单的结构化定义（唯一来源）。

Prompt / 校验 / 前端字段说明都从这里取，避免多套维护。
不包含任何具体技术名词的「标准答案」。
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

UNIT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$"

# ── 业务检查：创建表单 ─────────────────────────────────────────
CHECKS_CREATE: dict[str, Any] = {
    "id": "checks.create",
    "title": "创建业务检查",
    "summary": "在指定资产上配置 Ayana 原生检查（不依赖 Prometheus）。",
    "submit_label": "添加检查",
    "ai_role": "只根据用户描述与表单定义填草稿；不保存、不执行。",
    "fields": [
        {
            "name": "asset_id",
            "type": "string",
            "required": True,
            "label": "所属主机",
            "help": "选择已添加到系统、且当前账号可以查看的主机。",
            "source": "assets",
        },
        {
            "name": "kind",
            "type": "enum",
            "required": True,
            "label": "检查类型",
            "values": ["port", "service", "command"],
            "help": "端口监听、systemd 服务运行状态或受限的只读命令检查。服务检查只支持 systemd，不支持 Docker 容器或 Kubernetes Pod。",
        },
        {
            "name": "name",
            "type": "string",
            "required": False,
            "label": "名称",
            "max_length": 64,
            "help": "给用户看的名称，可使用中文、空格和自然语言。未填写时根据主机与检查对象生成。内部唯一标识由系统生成。",
        },
        {
            "name": "params.port",
            "type": "integer",
            "required_if": "kind==port",
            "label": "端口",
            "minimum": 1,
            "maximum": 65535,
        },
        {
            "name": "params.proto",
            "type": "enum",
            "required_if": "kind==port",
            "label": "协议",
            "values": ["tcp", "udp"],
            "default": "tcp",
        },
        {
            "name": "params.unit",
            "type": "string",
            "required_if": "kind==service",
            "label": "服务名",
            "max_length": 64,
            "pattern": UNIT_PATTERN,
            "help": (
                "目标主机上实际存在的 systemd unit 名，例如 nginx 或 nginx.service。"
                "Docker 容器和 Kubernetes Pod 不能直接使用此类型。"
            ),
        },
        {
            "name": "params.cmd",
            "type": "string",
            "required_if": "kind==command",
            "label": "命令",
            "max_length": 500,
            "help": (
                "在目标资产上执行的探测命令（经受限通道）。"
                "必须匹配该资产可用执行方式；不能假设未登记的运行时接口存在。"
            ),
        },
        {
            "name": "expect.mode",
            "type": "enum",
            "required_if": "kind==command",
            "label": "期望",
            # P1-07: command 仅支持退出码，不再提供输出内容匹配
            "values": ["exit0"],
            "default": "exit0",
        },
        {
            "name": "expect.value",
            "type": "string",
            "required_if": "expect.mode in [contains,not_contains]",
            "label": "匹配串",
            "max_length": 200,
        },
        {
            "name": "interval_sec",
            "type": "integer",
            "label": "间隔秒",
            "minimum": 15,
            "maximum": 3600,
            "default": 60,
        },
        {
            "name": "fail_threshold",
            "type": "integer",
            "label": "连续失败次数",
            "minimum": 1,
            "maximum": 10,
            "default": 2,
        },
        {
            "name": "severity",
            "type": "enum",
            "label": "告警级别",
            "values": ["info", "warning", "critical"],
            "default": "warning",
        },
    ],
    "constraints": [
        "kind=port 必须提供 params.port；不需要 params.unit/params.cmd",
        "kind=service 用 params.unit 表示 systemd 服务；Docker 容器和 K8s Pod 不受此类型支持",
        "kind=command 必须提供 params.cmd，且命令须匹配目标资产现有执行能力（SSH 受限命令/本机），不得假设不存在的 API",
        "未知资产 id 不可创建，只能追问",
        "用户未提到的数值不要编造；可用 default，由系统标注默认值来源，不属于意图推断",
        "不支持的请求应写入 unsupported.reason，并给出系统实际支持的 alternative（port/service/command）",
    ],
    "capability_boundary": {
        "port": "在目标机检查 TCP/UDP 端口是否监听",
        "service": "仅使用 systemctl is-active 检查 systemd 服务是否运行，不支持 Docker 容器和 K8s Pod",
        "command": "执行白名单/受限通道命令；内容与可用执行方式必须匹配",
    },
}

FORMS: dict[str, dict[str, Any]] = {
    "checks.create": CHECKS_CREATE,
}

# 操作场景 → 表单 id
DOMAIN_FORM = {
    "checks": "checks.create",
}
DOMAIN_ROUTES = {
    "checks": ["checks_form"],
}


def condition_dependencies(condition: dict | None) -> list[str]:
    """条件引用的字段就是选项校验所需上下文，避免另维护一份依赖。"""
    if not condition:
        return []
    if "all" in condition:
        return list(dict.fromkeys(key for item in condition["all"] for key in condition_dependencies(item)))
    return [condition["field"]]

# 表单控件与提交字段的映射也属于契约，前端不再另写一套模型字段规则。
_CHECK_CONTROLS = {
    "asset_id": "chk-asset", "kind": "chk-kind", "name": "chk-name",
    "params.port": "chk-port", "params.proto": "chk-proto",
    "params.unit": "chk-unit", "params.cmd": "chk-cmd",
    "expect.mode": "chk-expect", "expect.value": "chk-expect-val",
    "interval_sec": "chk-interval", "fail_threshold": "chk-threshold",
    "severity": "chk-severity",
}
_VALUE_LABELS = {
    "kind": {"port": "端口监听", "service": "服务运行状态", "command": "只读命令"},
    "params.proto": {"tcp": "TCP", "udp": "UDP"},
    "expect.mode": {"exit0": "命令成功退出", "contains": "输出包含指定文字", "not_contains": "输出不包含指定文字"},
    "severity": {"info": "提示", "warning": "警告", "critical": "严重"},
}
_CHECK_APPLICABLE = {
    "params.port": {"field": "kind", "equals": "port"},
    "params.proto": {"field": "kind", "equals": "port"},
    "params.unit": {"field": "kind", "equals": "service"},
    "params.cmd": {"field": "kind", "equals": "command"},
    "expect.mode": {"field": "kind", "equals": "command"},
    "expect.value": {"all": [{"field": "kind", "equals": "command"},
                               {"field": "expect.mode", "in": ["contains", "not_contains"]}]},
}
for _field in CHECKS_CREATE["fields"]:
    _key = _field["name"]
    _field["control"] = _CHECK_CONTROLS[_key]
    _field["control_id"] = _CHECK_CONTROLS[_key]
    _field["submit_path"] = {"params.proto": "params.protocol", "params.cmd": "params.argv",
                             "expect.mode": "expect", "expect.value": "expect"}.get(_key, _key)
    if _key in {"expect.mode", "expect.value"}:
        _field["submit_adapter"] = "command_expectation"
    elif _key == "params.cmd":
        _field["submit_adapter"] = "command_argv"
    if _key in _CHECK_APPLICABLE:
        _field["applicable_if"] = _CHECK_APPLICABLE[_key]
        _field["validation_context"] = condition_dependencies(_field["applicable_if"])
        if _field.get("required_if"):
            _field["required_when"] = _CHECK_APPLICABLE[_key]
    if _key in _VALUE_LABELS:
        _field["value_labels"] = _VALUE_LABELS[_key]
def _issue(field: str, code: str, message: str, schema: dict[str, dict]) -> dict[str, str]:
    return {"field": field, "label": schema.get(field, {}).get("label", "配置项"), "code": code, "message": message}


def _flatten_fields(fields: Any, schema: dict[str, dict]) -> tuple[dict[str, Any], list[dict]]:
    """接受文档化的平铺字段或嵌套字段；重复、未知和错误结构不能丢弃。"""
    flat: dict[str, Any] = {}
    issues: list[dict] = []
    if not isinstance(fields, dict):
        return flat, [_issue("", "bad_fields", "配置内容必须是一组表单字段。", schema)]

    def visit(values: dict, prefix: str = "") -> None:
        for key, value in values.items():
            if not isinstance(key, str):
                issues.append(_issue("", "unknown_field", "配置中包含无法识别的配置项。", schema))
                continue
            path = f"{prefix}.{key}" if prefix else key
            if path in flat:
                issues.append(_issue(path, "duplicate_field", "同一配置项出现了多个值，请重新填写。", schema))
            elif path in schema:
                flat[path] = value
            elif isinstance(value, dict) and any(k.startswith(path + ".") for k in schema):
                visit(value, path)
            else:
                issues.append(_issue(path, "unknown_field", "配置中包含当前表单不支持的配置项。", schema))

    visit(fields)
    return flat, issues


def _asset_options(assets: list[Any] | None) -> dict[str, str] | None:
    if assets is None:
        return None
    result = {}
    for asset in assets:
        if isinstance(asset, str):
            result[asset] = asset
        elif isinstance(asset, dict) and asset.get("id") and asset.get("enabled", True):
            result[str(asset["id"])] = str(asset.get("display_name") or asset["id"])
    return result


def condition_matches(condition: dict | None, values: dict[str, Any]) -> bool:
    """受声明约束的条件表达式，供表单和校验使用；从不执行字符串。"""
    if not condition:
        return True
    if "all" in condition:
        return all(condition_matches(item, values) for item in condition["all"])
    value = values.get(condition["field"])
    if "equals" in condition:
        return value == condition["equals"]
    if "in" in condition:
        return value in condition["in"]
    return False


def condition_applicability(condition: dict | None, values: dict[str, Any]) -> bool | None:
    """尚未选择条件字段时保留未知，只有已知条件不匹配才排除澄清问题。"""
    if not condition:
        return True
    if "all" in condition:
        matches = [condition_applicability(item, values) for item in condition["all"]]
        if False in matches:
            return False
        return None if None in matches else True
    key = condition["field"]
    if key not in values or values[key] is None or values[key] == "":
        return None
    return condition_matches(condition, values)


def field_applicability(domain: str, key: str, values: dict[str, Any]) -> bool | None:
    """根据真实字段声明判断是否适用；未知选择不等同于不适用。"""
    field = next((field for field in get_form(domain)["fields"] if field["name"] == key), None)
    if field is None:
        return False
    return condition_applicability(field.get("applicable_if"), values)


def _required(field: dict, values: dict[str, Any]) -> bool:
    return bool(field.get("required")) or bool(field.get("required_when") and condition_matches(field["required_when"], values))


def _applicable(key: str, values: dict[str, Any]) -> bool:
    return condition_matches(_CHECK_APPLICABLE.get(key), values)


def _payload(values: dict[str, Any]) -> dict[str, Any]:
    kind = values["kind"]
    if kind == "port":
        params = {"port": values["params.port"], "protocol": values["params.proto"]}
        expect = {}
    elif kind == "service":
        params = {"unit": values["params.unit"]}
        expect = {"active_state": "active"}
    else:
        params = {"argv": values["params.cmd"].split()}
        # P1-07: 仅 exit0
        expect = {"exit_code": 0}
    return {"asset_id": values["asset_id"], "kind": kind, "name": values["name"],
            "params": params, "expect": expect, "interval_sec": values["interval_sec"],
            "fail_threshold": values["fail_threshold"], "severity": values["severity"]}


def validate_fields(
    domain: str,
    fields: Any,
    *,
    assets: list[Any] | None = None,
    capabilities: list[Any] | None = None,
    partial: bool = True,
) -> dict[str, Any]:
    """验证草稿与最终表单的共同契约，缺失信息和无效输出分别报告。

    不截断、不限制到边界、不猜检查类型；payload 仅在整个表单有效时生成。
    partial 说明调用者处在草稿阶段，缺失项仍保留并阻止生成提交内容。
    """
    form = get_form(domain)
    schema = {f["name"]: f for f in form["fields"]}
    raw, issues = _flatten_fields(fields, schema)
    values: dict[str, Any] = {}
    defaulted: list[str] = []
    additional_missing: list[dict] = []
    normalizations: list[dict] = []
    invalid: set[str] = {i["field"] for i in issues}
    for key, value in raw.items():
        field = schema[key]
        label = field["label"]
        if value is None or value == "":
            continue
        typ = field["type"]
        if typ == "integer":
            if isinstance(value, bool) or not (
                isinstance(value, int) or isinstance(value, str) and re.fullmatch(r"[+-]?\d{1,10}", value.strip())
            ):
                issues.append(_issue(key, "bad_integer", f"{label}必须填写整数。", schema))
                invalid.add(key)
                continue
            value = int(value)
            if not field["minimum"] <= value <= field["maximum"]:
                issues.append(_issue(key, "out_of_range", f"{label}必须在 {field['minimum']} 到 {field['maximum']} 之间。", schema))
                invalid.add(key)
                continue
        elif not isinstance(value, str):
            issues.append(_issue(key, "bad_type", f"{label}必须填写文字。", schema))
            invalid.add(key)
            continue
        else:
            if any(unicodedata.category(c) == "Cc" for c in value):
                issues.append(_issue(key, "control_character", f"{label}不能包含换行或控制字符。", schema))
                invalid.add(key)
                continue
            value = value.strip()
            if not value:
                continue
            if typ == "enum" and value not in field["values"]:
                issues.append(_issue(key, "bad_choice", f"{label}请选择表单提供的选项。", schema))
                invalid.add(key)
                continue
            if len(value) > field.get("max_length", 200):
                issues.append(_issue(key, "too_long", f"{label}最多可填写 {field.get('max_length', 200)} 个字符。", schema))
                invalid.add(key)
                continue
            if field.get("pattern") and not re.fullmatch(field["pattern"], value):
                issues.append(_issue(key, "bad_format", f"{label}格式不符合目标主机的要求，请确认实际服务名。", schema))
                invalid.add(key)
                continue
        values[key] = value

    if domain == "checks":
        for key in list(values):
            if values.get("kind") and not _applicable(key, values):
                issues.append(_issue(key, "irrelevant_field", "当前检查类型不使用此配置项，请调整检查类型或移除此项。", schema))
                invalid.add(key)
                values.pop(key)

    for key, field in schema.items():
        if key not in values and key not in invalid and "default" in field:
            if domain == "checks" and not _applicable(key, values):
                continue
            values[key] = field["default"]
            defaulted.append(key)

    asset_options = _asset_options(assets)
    if values.get("asset_id") and asset_options is not None and values["asset_id"] not in asset_options:
        issues.append(_issue("asset_id", "unknown_asset", "所选主机不存在、已停用或当前账号不可用，请重新选择主机。", schema))
        invalid.add("asset_id")
        values.pop("asset_id")
    if domain == "checks" and values.get("params.cmd"):
        from .checks import CheckError, validate_argv
        try:
            validate_argv(values["params.cmd"].split())
        except CheckError:
            issues.append(_issue("params.cmd", "unsafe_command", "命令不符合只读检查限制，请使用受支持的探测程序、参数和安全格式。", schema))
            invalid.add("params.cmd")
            values.pop("params.cmd")

    # P1-07: command 不支持输出内容匹配，必须显式拒绝，不得静默降级
    if domain == "checks" and values.get("kind") == "command":
        mode = values.get("expect.mode")
        if mode in ("contains", "not_contains"):
            issues.append(_issue(
                "expect.mode", "unsupported_expect",
                "命令检查不支持输出内容匹配，请选择退出码 0。",
                schema,
            ))
            invalid.add("expect.mode")
            values.pop("expect.mode", None)
            values.pop("expect.value", None)

    if domain == "checks" and "name" not in values and "name" not in invalid and values.get("asset_id") and values.get("kind"):
        asset_label = (asset_options or {}).get(values["asset_id"], values["asset_id"])
        asset_label = "".join(" " if unicodedata.category(c) == "Cc" else c for c in asset_label).strip() or values["asset_id"]
        kind = values["kind"]
        target = values.get("params.unit") if kind == "service" else values.get("params.port") if kind == "port" else values.get("params.cmd")
        if target:
            suffix = f"{target} 运行状态" if kind == "service" else f"{target}/{values.get('params.proto', 'tcp')} 端口" if kind == "port" else "命令检查"
            values["name"] = f"{asset_label} · {suffix}"[:schema["name"]["max_length"]]
            defaulted.append("name")

    missing = list(additional_missing)
    for key, field in schema.items():
        if _required(field, values) and key not in values and key not in invalid:
            item = {"field": key, "label": field["label"], "question": f"请补充{field['label']}。"}
            if field["type"] == "enum":
                choices = field["values"]
                labels = field.get("value_labels", {})
                item["options"] = [{"value": value, "label": labels.get(value, value)} for value in choices]
            elif key == "asset_id" and asset_options and len(asset_options) <= 12:
                item["options"] = [{"value": value, "label": label} for value, label in asset_options.items()]
            missing.append(item)
    # 名称虽可选，必须在目标明确后生成，不能给不完整草稿伪造一个可提交名称。
    valid = not issues and not missing
    payload = _payload(values) if domain == "checks" and valid else dict(values) if valid else None
    return {"fields": values, "issues": issues, "missing": missing, "defaulted": defaulted,
            "normalizations": normalizations, "payload": payload, "valid": valid}


def _validation_error(result: dict[str, Any]) -> None:
    from .checks import CheckError
    issues = result["issues"] + [
        {"field": m["field"], "label": m["label"], "code": "required", "message": m["question"]}
        for m in result["missing"]
    ]
    first = issues[0]
    raise CheckError(first["code"], first["message"], issues=issues)


def check_payload(fields: Any, *, assets: list[Any] | None = None) -> dict[str, Any]:
    result = validate_fields("checks", fields, assets=assets, partial=False)
    if not result["valid"]:
        _validation_error(result)
    return result["payload"]


def payload_to_fields(payload: Any) -> dict[str, Any]:
    """实际提交结构转回表单结构；拒绝不能无损表达的字段和期望组合。"""
    from .checks import CheckError
    schema = {f["name"]: f for f in CHECKS_CREATE["fields"]}
    issues = []
    if not isinstance(payload, dict):
        raise CheckError("bad_fields", "配置内容必须是一组表单字段。")
    allowed = {"asset_id", "kind", "name", "params", "expect", "interval_sec", "fail_threshold", "severity"}
    fields = {k: v for k, v in payload.items() if k in allowed and k not in ("params", "expect")}
    for key in set(payload) - allowed:
        issues.append(_issue(str(key), "unknown_field", "提交内容包含当前表单不支持的配置项。", schema))
    kind = payload.get("kind")
    params = payload.get("params", {})
    expect = payload.get("expect", {})
    if not isinstance(params, dict) or not isinstance(expect, dict):
        raise CheckError("bad_fields", "检查对象和期望结果必须采用正确的配置格式。")
    param_map = {"port": {"port": "params.port", "protocol": "params.proto"},
                 "service": {"unit": "params.unit"}, "command": {"argv": "params.cmd"}}.get(kind, {}) if isinstance(kind, str) else {}
    for key, value in params.items():
        if key not in param_map:
            issues.append(_issue(f"params.{key}", "unknown_field", "检查对象包含当前类型不支持的配置项。", schema))
        elif key == "argv":
            if not isinstance(value, list) or any(not isinstance(t, str) or not t or re.search(r"\s", t) for t in value):
                issues.append(_issue("params.cmd", "bad_argv", "命令参数格式不正确，请检查完整命令。", schema))
            else:
                fields["params.cmd"] = " ".join(value)
        else:
            fields[param_map[key]] = value
    if kind == "service":
        if expect and expect != {"active_state": "active"}:
            issues.append(_issue("expect.mode", "bad_expect", "服务检查目前仅支持判断服务正在运行。", schema))
    elif kind == "port":
        if expect:
            issues.append(_issue("expect.mode", "bad_expect", "端口检查使用端口监听状态判断，无需自定义期望结果。", schema))
    elif kind == "command":
        if not expect:
            fields["expect.mode"] = "exit0"
        elif set(expect) == {"exit_code"} and type(expect.get("exit_code")) is int and expect["exit_code"] == 0:
            fields["expect.mode"] = "exit0"
        elif set(expect) == {"output_contains"} or set(expect) == {"output_not_contains"}:
            issues.append(_issue("expect.mode", "unsupported_expect", "命令检查不支持输出内容匹配，请改用退出码 0。", schema))
        else:
            issues.append(_issue("expect.mode", "bad_expect", "期望结果必须为命令成功退出（exit 0）。", schema))
    elif expect:
        issues.append(_issue("expect.mode", "bad_expect", "请选择受支持的检查类型后配置期望结果。", schema))
    if issues:
        raise CheckError(issues[0]["code"], issues[0]["message"], issues=issues)
    return fields


def validate_check_payload(payload: Any, *, assets: list[Any] | None = None) -> dict[str, Any]:
    from .checks import CheckError
    try:
        fields = payload_to_fields(payload)
    except CheckError as exc:
        return {"fields": {}, "issues": exc.issues or [{"field": "", "label": "配置", "code": exc.code, "message": exc.detail}],
                "missing": [], "defaulted": [], "payload": None, "valid": False}
    return validate_fields("checks", fields, assets=assets, partial=False)


def get_form(domain: str) -> dict[str, Any]:
    fid = DOMAIN_FORM.get(domain)
    if not fid:
        raise KeyError(f"no form for domain: {domain}")
    form = FORMS[fid]
    if domain == "checks":
        from .checks import COMMAND_BOUNDARY, MAX_ARGV_TOKENS, _CMD_ALLOW
        command = next(f for f in form["fields"] if f["name"] == "params.cmd")
        command["allowed_programs"] = sorted(_CMD_ALLOW)
        command["max_tokens"] = MAX_ARGV_TOKENS
        command["max_token_length"] = 120
        form["command_boundary"] = COMMAND_BOUNDARY
    return form


def form_prompt_payload(
    domain: str,
    *,
    assets: list[Any],
    capabilities: list[Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构造给模型的「场景切片」：只含本表单 + 相关选项，不含整站。"""
    form = get_form(domain)
    field_names = [field["name"] for field in form["fields"]]
    field_enum = " | ".join(field_names)
    # 裁剪：只保留字段定义与约束
    slim_fields = []
    for f in form.get("fields") or []:
        slim_fields.append(
            {
                k: f[k]
                for k in (
                    "name",
                    "type",
                    "required",
                    "required_if",
                    "required_when",
                    "applicable_if",
                    "label",
                    "help",
                    "values",
                    "default",
                    "minimum",
                    "maximum",
                    "max_length",
                    "source",
                    "pattern",
                    "value_labels",
                    "allowed_programs",
                    "max_tokens",
                    "max_token_length",
                    "allowed_states_by_capability",
                    "value_labels_by_capability",
                    "validation_context",
                )
                if k in f
            }
        )
    payload = {
        "form": {
            "id": form.get("id"),
            "title": form.get("title"),
            "fields": slim_fields,
            "constraints": form.get("constraints") or [],
            "capability_boundary": form.get("capability_boundary") or {},
            "command_boundary": form.get("command_boundary") or {},
        },
        "context": {
            "assets": assets,
            "capabilities": capabilities or [],
            "extra": extra or {},
        },
        "interpretation_rules": [
            "先区分用户要配置或检查的实际目标与用途、所属工作负载等背景。功能描述和名称前缀是识别线索，不等于完整技术名称或已观察到的主机事实。",
            "尚不能确定实际目标时，保留能确定的字段并用 clarifications 澄清含义；真实表单必填值不确定时用 missing。不得把概念、线索或自由回答填入受约束字段。",
            "能力是否支持取决于实际目标及操作，不能只因背景描述出现某个技术词就判断不支持。目标含义不清时先询问，再判断能力边界。",
            "missing 和 inferred 的 field 只能是 field_names 中的完整名称。概念问题放入 clarifications；没有必要补充的信息不追问。",
            "missing.options 默认 mode=field_value，value 必须是该字段符合所有约束和上下文的实际值。自由回答或描述性选择使用 mode=answer，只作为对话补充，不直接赋值。",
            "clarifications 只表达含义澄清，id 为 1 到 64 个 ASCII 字母、数字、下划线或连字符且以字母开头。选项答案必须是非空文字；不确定或其他选择也可以作为对话回答。",
        ],
        "output_schema": {
            "route": " | ".join(DOMAIN_ROUTES[domain]),
            "field_names": field_names,
            "fields": "object，仅 form.fields 中出现的字段名（可用嵌套 params.* 或扁平 params.port）",
            "inferred": [{"field": field_enum, "reason": "推断依据", "confidence": "high|medium|low"}],
            "confirm_question": "需要用户确认推断时的一句话；可为空",
            "missing": [{"field": field_enum, "question": "只询问尚不能确定且适用的实际表单字段；多种合理选择时解释区别",
                         "options": [{"mode": "field_value | answer（省略时默认为 field_value）", "value": "field_value 为符合字段约束的实际值；answer 为非空文字回答，不直接填字段", "label": "用户可以理解的选项名称", "description": "此选择的区别或适用情况"}]}],
            "clarifications": [{"id": "ASCII slug，匹配 ^[A-Za-z][A-Za-z0-9_-]{0,63}$", "label": "用户理解的澄清主题",
                                "question": "尚不能确定的目标含义或用户意图；不用内部字段名",
                                "options": [{"value": "非空文字答案，仅用于后续对话，不直接填写字段", "label": "用户可以理解的选项名称", "description": "此选择的区别或适用情况"}]}],
            "unsupported": {"reason": "不支持原因", "alternatives": ["实际支持的操作"]} ,
            "notes": ["补充说明"],
        },
    }
    return payload
