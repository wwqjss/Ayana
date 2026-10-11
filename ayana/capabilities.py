"""固定能力目录：输入输出、风险、通道、模板参数。

不允许配置上传任意执行模板；能力只映射到登记对象上的固定动作。
执行目标只能来自登记对象，客户端 params 不得覆盖 unit/container/name。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class Capability:
    name: str
    kind: str  # read|write
    object_kinds: tuple[str, ...]
    risk: str
    description: str
    write_tokens: Callable[[dict], list[str]] | None = None
    probe_tokens: Callable[[dict], list[list[str]]] = field(default_factory=lambda: (lambda o: []))
    timeout_sec: float = 10.0
    max_output: int = 8000
    auto_allowed: bool = False
    # 写能力对应的后置验证能力（可选）
    verify_capability: str = ""


class ObjectBindingError(ValueError):
    """对象未登记或与能力不匹配。"""


def resolve_object_name(obj: dict) -> str:
    """只认登记对象；禁止 params 覆盖。"""
    name = (obj.get("unit") or obj.get("container") or obj.get("name") or "").strip()
    if not name or any(ch in name for ch in " ;|&$`\n\t") or len(name) > 64:
        raise ObjectBindingError("invalid registered object name")
    return name


def _obj_name(obj: dict) -> str:
    return resolve_object_name(obj)


def _obj_container(obj: dict) -> str:
    name = (obj.get("container") or obj.get("name") or "").strip()
    if not name or any(ch in name for ch in " ;|&$`\n\t") or len(name) > 64:
        raise ObjectBindingError("invalid container name")
    return name


CAPABILITIES: dict[str, Capability] = {}


def _reg(c: Capability) -> None:
    CAPABILITIES[c.name] = c


_reg(
    Capability(
        name="asset.summary",
        kind="read",
        object_kinds=("*",),
        risk="read",
        description="资产摘要（uptime/负载/磁盘/内存/监听）",
        probe_tokens=lambda o: [
            ["uptime"],
            ["df", "-h"],
            ["free", "-m"],
            ["ss", "-lntu"],
        ],
    )
)

# service.status / service.logs 对 systemd 与 container 表达不同事实
def _svc_status_tokens(o: dict) -> list[list[str]]:
    name = _obj_name(o)
    if o.get("kind") == "container" or o.get("container"):
        return [["docker", "inspect", "--format",
                 "{{.State.Status}} {{.State.Running}} {{.State.ExitCode}}",
                 _obj_container(o)]]
    # systemd：active/enabled/MainPID 分开观察，不是 pgrep
    return [
        ["systemctl", "is-active", name],
        ["systemctl", "is-enabled", name],
        ["systemctl", "show", name, "--property=MainPID,SubState,ActiveState,UnitFileState",
         "--value"],
    ]


def _svc_logs_tokens(o: dict) -> list[list[str]]:
    name = _obj_name(o)
    if o.get("kind") == "container" or o.get("container"):
        return [["docker", "logs", "--tail", "40", _obj_container(o)]]
    # 真实有限 journal 日志，不用 pgrep 冒充
    return [["journalctl", "-u", name, "-n", "40", "--no-pager", "-o", "short-iso"]]


_reg(
    Capability(
        name="service.status",
        kind="read",
        object_kinds=("service", "container"),
        risk="read",
        description="登记服务/容器状态（systemd is-active/is-enabled/show 或 docker inspect）",
        probe_tokens=_svc_status_tokens,
    )
)

_reg(
    Capability(
        name="service.logs",
        kind="read",
        object_kinds=("service", "container"),
        risk="read",
        description="有限日志（journalctl -u / docker logs，固定尾数）",
        probe_tokens=_svc_logs_tokens,
        max_output=6000,
    )
)

def _port_listen_tokens(o: dict) -> list[list[str]]:
    proto = (o.get("protocol") or "tcp").lower()
    port = o.get("port")
    flag = ["ss", "-lnu"] if proto == "udp" else ["ss", "-lnt"]
    if port:
        try:
            p = int(port)
        except Exception:
            return [flag]
        # ss 过滤器拆成安全 argv（每 token 无空格/元字符）
        return [flag + ["sport", "=", f":{p}"], flag]
    return [flag]


_reg(
    Capability(
        name="port.listen",
        kind="read",
        # service 对象可自带 port 字段，表达“该服务期望端口是否在听”
        object_kinds=("port", "service"),
        risk="read",
        description="登记端口监听状态",
        probe_tokens=_port_listen_tokens,
    )
)

_reg(
    Capability(
        name="disk.usage",
        kind="read",
        object_kinds=("filesystem", "*"),
        risk="read",
        description="磁盘使用率",
        probe_tokens=lambda o: [["df", "-h"]],
    )
)

_reg(
    Capability(
        name="memory.available",
        kind="read",
        object_kinds=("*",),
        risk="read",
        description="内存可用量",
        probe_tokens=lambda o: [["free", "-m"]],
    )
)

_reg(
    Capability(
        name="load.current",
        kind="read",
        object_kinds=("*",),
        risk="read",
        description="当前负载",
        probe_tokens=lambda o: [["uptime"]],
    )
)

_reg(
    Capability(
        name="probe.status",
        kind="read",
        object_kinds=("probe", "*"),
        risk="read",
        description="外部探测结果（经 Prometheus）",
    )
)

_reg(
    Capability(
        name="service.restart",
        kind="write",
        object_kinds=("service",),
        risk="write",
        description="登记业务服务受限重启",
        write_tokens=lambda o: ["systemctl", "restart", _obj_name(o)],
        auto_allowed=True,
        verify_capability="probe.status",
    )
)

_reg(
    Capability(
        name="service.start",
        kind="write",
        object_kinds=("service",),
        risk="write",
        description="登记业务服务启动（人工）",
        write_tokens=lambda o: ["systemctl", "start", _obj_name(o)],
        verify_capability="probe.status",
    )
)

_reg(
    Capability(
        name="service.stop",
        kind="write",
        object_kinds=("service",),
        risk="write",
        description="登记业务服务停止（人工）",
        write_tokens=lambda o: ["systemctl", "stop", _obj_name(o)],
    )
)

_reg(
    Capability(
        name="container.restart",
        kind="write",
        object_kinds=("container",),
        risk="write",
        description="登记容器受限重启",
        write_tokens=lambda o: ["docker", "restart", _obj_container(o)],
        auto_allowed=True,
        verify_capability="probe.status",
    )
)

_reg(
    Capability(
        name="shell.interactive",
        kind="write",
        object_kinds=("*",),
        risk="shell",
        description="人工 Web SSH 交互终端（不授予 Agent）",
        write_tokens=None,
        auto_allowed=False,
    )
)

# ---- Prometheus 配置管理（v0.6.x）----
# 写路径走 PromConfigService 固定命令，不经自由 write_tokens；此处仅登记能力供 Policy 使用。

_reg(
    Capability(
        name="promconfig.read",
        kind="read",
        object_kinds=("*",),
        risk="read",
        description="读取 Prometheus 配置、抓取目标与告警规则",
        probe_tokens=lambda o: [],
    )
)

_reg(
    Capability(
        name="promconfig.write",
        kind="write",
        object_kinds=("*",),
        risk="write",
        description="修改 Prometheus 配置/目标/规则（备份+promtool+热重载）",
        write_tokens=None,
        auto_allowed=False,
    )
)

_reg(
    Capability(
        name="node_exporter.status",
        kind="read",
        object_kinds=("*",),
        risk="read",
        description="检查 Node Exporter 安装/运行/9100 监听",
        probe_tokens=lambda o: [],
    )
)

_reg(
    Capability(
        name="node_exporter.manage",
        kind="write",
        object_kinds=("*",),
        risk="write",
        description="安装/启动/停止 Node Exporter（固定模板，默认 127.0.0.1:9100）",
        write_tokens=None,
        auto_allowed=False,
    )
)

# ---- 业务检查（轻量默认，不依赖 Prometheus）----

_reg(
    Capability(
        name="checks.read",
        kind="read",
        object_kinds=("*",),
        risk="read",
        description="查看业务检查与最近结果",
        probe_tokens=lambda o: [],
    )
)

_reg(
    Capability(
        name="checks.write",
        kind="write",
        object_kinds=("*",),
        risk="write",
        description="增删改业务检查（端口/服务/固定命令）",
        write_tokens=None,
        auto_allowed=False,
    )
)


def get_capability(name: str) -> Capability:
    c = CAPABILITIES.get(name)
    if not c:
        raise KeyError(name)
    return c


def assert_within_ceiling(name: str) -> Capability:
    """Node capability ceiling：运行时只允许已登记能力。

    Policy / PermissionChange / Agent 不得发明新能力（如 shell.root）。
    能力定义只存在于本模块源码，不由数据库或 LLM 写入。
    """
    if not isinstance(name, str) or not name:
        raise ObjectBindingError("capability name required")
    if name not in CAPABILITIES:
        raise ObjectBindingError(f"capability not in node ceiling: {name}")
    return CAPABILITIES[name]


def ceiling() -> list[str]:
    return sorted(CAPABILITIES.keys())


def list_capabilities() -> list[dict[str, Any]]:
    return [
        {
            "name": c.name,
            "kind": c.kind,
            "risk": c.risk,
            "description": c.description,
            "object_kinds": list(c.object_kinds),
            "auto_allowed": c.auto_allowed,
            "timeout_sec": c.timeout_sec,
            "verify_capability": c.verify_capability,
        }
        for c in CAPABILITIES.values()
    ]


def object_matches_capability(capability: str, obj: dict) -> None:
    c = get_capability(capability)
    kind = obj.get("kind") or ""
    kinds = c.object_kinds
    if "*" in kinds:
        return
    if kind and kind not in kinds:
        raise ObjectBindingError(f"capability {capability} does not accept object kind {kind}")


def build_write_tokens(capability: str, obj: dict) -> list[str]:
    """目标完全来自登记对象；params 不参与。"""
    c = get_capability(capability)
    if c.kind != "write" or not c.write_tokens:
        raise ValueError(f"not a write capability: {capability}")
    object_matches_capability(capability, obj)
    tokens = c.write_tokens(obj)
    if not tokens or not all(isinstance(t, str) and t for t in tokens):
        raise ValueError("empty write tokens")
    if tokens[0] not in ("systemctl", "docker"):
        raise ValueError("program not allowed")
    if tokens[1] not in ("start", "stop", "restart"):
        raise ValueError("verb not allowed")
    if len(tokens) != 3:
        raise ValueError("exactly one name argument required")
    name = tokens[2]
    if not name or any(ch in name for ch in " ;|&$`\n\t") or len(name) > 64:
        raise ValueError("bad name")
    # 二次确认：目标名必须等于登记对象解析结果
    if name != resolve_object_name(obj) and name != (obj.get("container") or ""):
        raise ObjectBindingError("write target diverges from registered object")
    return tokens


def build_probe_plans(capability: str, obj: dict) -> list[list[str]]:
    c = get_capability(capability)
    if c.kind != "read":
        raise ValueError(f"not a read capability: {capability}")
    object_matches_capability(capability, obj)
    plans = c.probe_tokens(obj) or []
    out = []
    for tokens in plans:
        if not tokens:
            continue
        if not all(isinstance(t, str) and t and not any(ch in t for ch in " ;|&$`\n") for t in tokens):
            raise ValueError("unsafe probe tokens")
        out.append(tokens)
    return out
