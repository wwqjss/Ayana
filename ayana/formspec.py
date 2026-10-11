"""真实表单的结构化定义（唯一来源）。

Prompt / 校验 / 前端字段说明都从这里取，避免多套维护。
不包含任何具体技术名词的「标准答案」。
"""

from __future__ import annotations

from typing import Any

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
            "help": "必须是系统已登记资产 id",
            "source": "assets",
        },
        {
            "name": "kind",
            "type": "enum",
            "required": True,
            "label": "检查类型",
            "values": ["port", "service", "command"],
            "default": "port",
            "help": "port=端口监听；service=systemd 服务或容器运行状态；command=自定义命令",
        },
        {
            "name": "name",
            "type": "string",
            "required": False,
            "label": "名称",
            "max_length": 64,
            "pattern": "^[A-Za-z0-9_\\-]{1,64}$",
            "help": "检查名，便于识别",
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
            "label": "服务/容器名",
            "max_length": 64,
            "help": (
                "systemd unit 名，或 Docker 容器名。"
                "Kubernetes Pod 名不是 systemd 服务；若只能看 Pod，"
                "应说明限制，或改用能匹配你现有执行能力的 command 检查。"
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
            "values": ["exit0", "contains", "not_contains"],
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
        "kind=service 用 params.unit 表示 systemd 服务或 Docker 容器；K8s Pod 名不能直接当作 systemd 服务",
        "kind=command 必须提供 params.cmd，且命令须匹配目标资产现有执行能力（SSH 受限命令/本机），不得假设不存在的 API",
        "未知资产 id 不可创建，只能追问",
        "用户未提到的数值不要编造；可用 default 但须在 inferred 中标注",
        "不支持的请求应写入 unsupported.reason，并给出系统实际支持的 alternative（port/service/command）",
    ],
    "capability_boundary": {
        "port": "在目标机检查 TCP/UDP 端口是否监听",
        "service": "检查 systemd 服务或 Docker 容器是否运行；不等同于列 K8s Pod",
        "command": "执行白名单/受限通道命令；内容与可用执行方式必须匹配",
    },
}

# ── 权限：默认策略 ─────────────────────────────────────────────
PERM_DEFAULTS: dict[str, Any] = {
    "id": "permissions.defaults",
    "title": "默认授权策略",
    "summary": "按操作类型配置禁止 / 需要人工确认 / 允许自动执行；新资产自动继承。",
    "submit_label": "保存策略",
    "ai_role": "定位界面并填草稿；保存必须由用户确认。",
    "fields": [
        {
            "name": "capability",
            "type": "string",
            "required": True,
            "label": "操作类型",
            "source": "capabilities",
            "help": "系统能力目录中的 capability 名，不可发明",
        },
        {
            "name": "state",
            "type": "enum",
            "required": True,
            "label": "策略",
            "values": ["deny", "confirm", "auto"],
            "help": "deny=禁止；confirm=需要人工确认；auto=允许自动执行",
        },
        {
            "name": "scope",
            "type": "enum",
            "label": "范围",
            "values": ["default", "exception"],
            "default": "default",
        },
        {
            "name": "asset_id",
            "type": "string",
            "required_if": "scope==exception",
            "label": "资产",
            "source": "assets",
        },
        {
            "name": "object_id",
            "type": "string",
            "label": "对象",
            "default": "*",
        },
    ],
    "constraints": [
        "capability 必须来自系统能力目录",
        "scope=default 表示全局默认；scope=exception 必须指定 asset_id",
        "不得创建新资产；不得扩大主机侧 commands.json/sudoers 边界",
        "用户未明确的 state 不要猜，放进 missing",
    ],
}

FORMS: dict[str, dict[str, Any]] = {
    "checks.create": CHECKS_CREATE,
    "permissions.defaults": PERM_DEFAULTS,
}

# 操作场景 → 表单 id
DOMAIN_FORM = {
    "checks": "checks.create",
    "permissions": "permissions.defaults",
}


def get_form(domain: str) -> dict[str, Any]:
    fid = DOMAIN_FORM.get(domain)
    if not fid:
        raise KeyError(f"no form for domain: {domain}")
    return FORMS[fid]


def form_prompt_payload(
    domain: str,
    *,
    assets: list[str],
    capabilities: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构造给模型的「场景切片」：只含本表单 + 相关选项，不含整站。"""
    form = get_form(domain)
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
                    "label",
                    "help",
                    "values",
                    "default",
                    "minimum",
                    "maximum",
                    "max_length",
                    "source",
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
        },
        "context": {
            "assets": assets,
            "capabilities": capabilities or [],
            "extra": extra or {},
        },
        "output_schema": {
            "route": "checks_form | perm_defaults | perm_exceptions | perm_effective | perm_workbench | perm_ceiling",
            "fields": "object，仅 form.fields 中出现的字段名（可用嵌套 params.* 或扁平 params.port）",
            "inferred": [{"field": "字段名", "reason": "推断依据", "confidence": "high|medium|low"}],
            "confirm_question": "需要用户确认推断时的一句话；可为空",
            "missing": [{"field": "字段名", "question": "具体问题"}],
            "unsupported": {"reason": "不支持原因", "alternatives": ["实际支持的操作"]} ,
            "notes": ["补充说明"],
        },
    }
    return payload
