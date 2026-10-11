"""Prometheus 可视化配置管理（v0.6.x）。

原则：
- 兼容手写配置：始终保留原文；无法无损写回则拒绝修改。
- 新增目标优先 file_sd_configs；不重写既有 static_configs / 复杂规则。
- 写操作：备份 → promtool 校验 → 原子写入 → 热重载；失败回滚并核实运行态。
- 不绕过 Policy / 审批 / 审计；路径沙箱禁止任意文件路径。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .db import Database, new_id, now

# ---------------------------------------------------------------------------
# 路径沙箱
# ---------------------------------------------------------------------------

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
_SAFE_REL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")


class PromConfigError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def _python_exec_token(script: str) -> str:
    """Encode fixed Python scripts as one token accepted by SSHTransport."""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return f"exec(__import__('base64').b64decode({encoded!r}))"


def _listens_on_9100(result: Any) -> bool:
    if not getattr(result, "ok", False):
        return False
    for line in (getattr(result, "output", "") or "").splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "LISTEN" and fields[3].endswith(":9100"):
            return True
    return False


def safe_rel_path(rel: str) -> str:
    """只允许受控相对路径；拒绝 ..、绝对路径、元字符。"""
    rel = (rel or "").replace("\\", "/").strip()
    if not rel or rel.startswith("/") or rel.startswith("~"):
        raise PromConfigError("bad_path", rel)
    if ".." in rel.split("/") or "\\" in rel:
        raise PromConfigError("bad_path", rel)
    if not _SAFE_REL_RE.fullmatch(rel):
        raise PromConfigError("bad_path", rel)
    return rel


def safe_file_name(name: str) -> str:
    name = (name or "").strip()
    if not _SAFE_NAME_RE.fullmatch(name):
        raise PromConfigError("bad_file_name", name)
    return name


def is_private_host(host: str) -> bool:
    """目标地址是否为本机/内网（避免 9100 默认暴露公网）。"""
    h = (host or "").strip().lower()
    if not h:
        return False
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return h != "0.0.0.0"
    # IPv4 私网 / 环回
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", h)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a == 10 or a == 127:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        return False
    # 主机名：默认视为内网（由部署环境保证），拒绝明显公网监听写法
    return not h.startswith("0.")


def assert_safe_listen_address(addr: str, *, allow_non_private: bool = False) -> str:
    """严格校验 node_exporter 监听地址：仅 IP:port，禁止公网/控制字符/额外参数。"""
    import ipaddress

    raw = addr or ""
    if any(ord(c) < 32 for c in raw) or any(c in raw for c in " \t\n\r;|&$`\"'"):
        raise PromConfigError("bad_listen_address", "illegal_chars")
    addr = raw.strip()
    if not addr:
        raise PromConfigError("bad_listen_address", "empty")
    if addr.count(":") < 1:
        raise PromConfigError("bad_listen_address", addr)
    # [ipv6]:port 或 ipv4:port / host:port
    if addr.startswith("["):
        if "]" not in addr or "]: " in addr:
            raise PromConfigError("bad_listen_address", addr)
        host_part, _, port_s = addr[1:].partition("]:")
        host = host_part
    else:
        host, _, port_s = addr.rpartition(":")
    try:
        port = int(port_s)
    except ValueError as e:
        raise PromConfigError("bad_listen_port", port_s) from e
    if not (1 <= port <= 65535):
        raise PromConfigError("bad_listen_port", port_s)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as e:
        # 域名默认拒绝，避免公网域名被当内网
        raise PromConfigError("listen_host_not_ip", host) from e
    if ip.is_unspecified:  # 0.0.0.0 / ::
        if not allow_non_private:
            raise PromConfigError("listen_public_forbidden", addr)
        return addr

    def _ok_listen(a) -> bool:
        if a.is_loopback:
            return True
        if a.version == 4:
            # RFC1918，排除链路本地/保留
            return bool(a.is_private and not a.is_link_local and not a.is_reserved)
        # IPv6 仅 ULA fc00::/7
        s = a.compressed.lower()
        return s.startswith("fd") or s.startswith("fc")

    if not allow_non_private:
        if ip.version == 6 and ip.ipv4_mapped is not None:
            if not _ok_listen(ip.ipv4_mapped):
                raise PromConfigError("listen_public_forbidden", addr)
        elif not _ok_listen(ip):
            raise PromConfigError("listen_public_forbidden", addr)
    # 规范化输出
    if ip.version == 6:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


# ---------------------------------------------------------------------------
# 迷你 YAML（读结构 / 写自有文件 / 外科插入）
# ---------------------------------------------------------------------------

def _scalar(tok: str) -> Any:
    t = tok.strip()
    if not t:
        return ""
    if t.startswith("[") or t.startswith("{"):
        try:
            return json.loads(t.replace("'", '"'))
        except Exception:
            # 简单拆分 flow list
            if t.startswith("[") and t.endswith("]"):
                inner = t[1:-1].strip()
                if not inner:
                    return []
                parts = [p.strip() for p in inner.split(",") if p.strip()]
                return [_scalar(p) for p in parts]
            return t
    if t.startswith('"') and t.endswith('"') and len(t) >= 2:
        try:
            return json.loads(t)
        except Exception:
            return t[1:-1]
    if t.startswith("'") and t.endswith("'") and len(t) >= 2:
        return t[1:-1]
    if t in ("true", "True", "yes", "Yes"):
        return True
    if t in ("false", "False", "no", "No"):
        return False
    if t in ("null", "Null", "~"):
        return None
    try:
        if re.fullmatch(r"-?\d+", t):
            return int(t)
        if re.fullmatch(r"-?\d+\.\d+", t):
            return float(t)
    except Exception:
        pass
    return t


def parse_simple_yaml(text: str) -> Any:
    """解析 Prometheus 常用 YAML 子集（映射/列表/标量）。

    不支持锚点、多文档、复杂流式集合；遇到无法安全解析的结构抛
    PromConfigError(yaml_unsupported)，调用方应降级为只读原文。
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # 去掉纯注释/空行后建立缩进栈
    cleaned: list[tuple[int, str]] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        cleaned.append((indent, raw.strip()))

    def parse_block(idx: int, indent: int) -> tuple[Any, int]:
        if idx >= len(cleaned):
            return None, idx
        # 列表？
        if cleaned[idx][1].startswith("- ") or cleaned[idx][1] == "-":
            items: list[Any] = []
            while idx < len(cleaned) and cleaned[idx][0] == indent and (
                cleaned[idx][1].startswith("- ") or cleaned[idx][1] == "-"
            ):
                body = cleaned[idx][1][1:].strip()
                if not body:
                    # 嵌套块在下一层
                    val, idx = parse_block(idx + 1, indent + 2)
                    items.append(val)
                    continue
                if (
                    ":" in body
                    and not body.startswith("{")
                    and not body.startswith("[")
                    and not re.match(r"^[A-Za-z0-9._\[\]]+:\d+", body)
                    and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", body)
                ):
                    # 行内 map 起始：- key: val  可能跟缩进子键
                    # 重建一个临时块
                    key, _, rest = body.partition(":")
                    key = key.strip()
                    rest = rest.strip()
                    item: dict[str, Any] = {}
                    if rest:
                        item[key] = _scalar(rest)
                        # 同层后续键
                        idx += 1
                        while idx < len(cleaned) and cleaned[idx][0] > indent and not cleaned[idx][1].startswith("- "):
                            sub_indent = cleaned[idx][0]
                            if cleaned[idx][1].startswith("- "):
                                break
                            k2, _, r2 = cleaned[idx][1].partition(":")
                            if not r2.strip() and idx + 1 < len(cleaned) and cleaned[idx + 1][0] > sub_indent:
                                val, idx = parse_block(idx + 1, cleaned[idx + 1][0])
                                item[k2.strip()] = val
                            else:
                                item[k2.strip()] = _scalar(r2)
                                idx += 1
                        items.append(item)
                    else:
                        # 值是嵌套块
                        idx += 1
                        child_indent = None
                        if idx < len(cleaned) and cleaned[idx][0] > indent:
                            child_indent = cleaned[idx][0]
                            val, idx = parse_block(idx, child_indent)
                            item[key] = val
                        else:
                            item[key] = None
                        # 同层 map 其余键
                        while idx < len(cleaned) and cleaned[idx][0] > indent and not cleaned[idx][1].startswith("- "):
                            k2, _, r2 = cleaned[idx][1].partition(":")
                            if not r2.strip() and idx + 1 < len(cleaned) and cleaned[idx + 1][0] > cleaned[idx][0]:
                                val, idx = parse_block(idx + 1, cleaned[idx + 1][0])
                                item[k2.strip()] = val
                            else:
                                item[k2.strip()] = _scalar(r2)
                                idx += 1
                        items.append(item)
                else:
                    items.append(_scalar(body))
                    idx += 1
            return items, idx

        # 映射
        obj: dict[str, Any] = {}
        while idx < len(cleaned) and cleaned[idx][0] == indent and not cleaned[idx][1].startswith("- "):
            line = cleaned[idx][1]
            if ":" not in line:
                raise PromConfigError("yaml_unsupported", line[:80])
            key, _, rest = line.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest.startswith("{") or rest.startswith("["):
                # 流式集合：尝试 json
                try:
                    obj[key] = json.loads(rest.replace("'", '"'))
                except Exception:
                    obj[key] = _scalar(rest)
                idx += 1
                continue
            if rest:
                obj[key] = _scalar(rest)
                idx += 1
                continue
            # 嵌套
            idx += 1
            if idx < len(cleaned) and cleaned[idx][0] > indent:
                val, idx = parse_block(idx, cleaned[idx][0])
                obj[key] = val
            else:
                obj[key] = None
        return obj, idx

    if not cleaned:
        return {}
    val, _ = parse_block(0, cleaned[0][0])
    return val


def dump_simple_yaml(data: Any, indent: int = 0) -> str:
    """输出自有文件的 YAML（规则文件等）。不用于改写用户原文。"""
    pad = "  " * indent
    if isinstance(data, dict):
        if not data:
            return pad + "{}\n"
        out = []
        for k, v in data.items():
            if isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{k}:\n")
                out.append(dump_simple_yaml(v, indent + 1))
            elif isinstance(v, dict):
                out.append(f"{pad}{k}: {{}}\n")
            elif isinstance(v, list):
                out.append(f"{pad}{k}: []\n")
            else:
                out.append(f"{pad}{k}: {_yaml_scalar(v)}\n")
        return "".join(out)
    if isinstance(data, list):
        if not data:
            return pad + "[]\n"
        out = []
        for item in data:
            if isinstance(item, dict):
                # 列表项：第一行用 - ，其余缩进
                body = dump_simple_yaml(item, indent + 1)
                lines = body.splitlines(True)
                if not lines:
                    out.append(f"{pad}-\n")
                    continue
                first = lines[0]
                # 把第一键放到 "- key:"
                out.append(f"{pad}- {first.lstrip()}")
                out.extend(lines[1:])
            elif isinstance(item, list):
                out.append(f"{pad}-\n")
                out.append(dump_simple_yaml(item, indent + 1))
            else:
                out.append(f"{pad}- {_yaml_scalar(item)}\n")
        return "".join(out)
    return pad + _yaml_scalar(data) + "\n"


def _rule_to_prom_dict(rule: dict[str, Any]) -> dict[str, Any]:
    """只保留 Prometheus rulefmt 允许的字段，避免元数据写回。"""
    out: dict[str, Any] = {}
    if rule.get("alert"):
        out["alert"] = rule["alert"]
    if rule.get("record"):
        out["record"] = rule["record"]
    if rule.get("expr") is not None:
        out["expr"] = rule["expr"]
    if rule.get("for"):
        out["for"] = rule["for"]
    labels = rule.get("labels") or {}
    if labels:
        out["labels"] = {str(k): str(v) for k, v in labels.items()}
    annotations = rule.get("annotations") or {}
    if annotations:
        out["annotations"] = {str(k): str(v) for k, v in annotations.items()}
    return out


def _rules_doc(rules: list[dict[str, Any]], group_name: str = "ayana-node-alerts") -> dict[str, Any]:
    return {
        "groups": [
            {
                "name": group_name,
                "rules": [_rule_to_prom_dict(r) for r in rules],
            }
        ]
    }


def _redact_secrets(text: str) -> str:
    """读取展示时脱敏常见内联秘密。"""
    if not text:
        return text
    patterns = [
        (re.compile(r"(password\s*[=:]\s*)\S+", re.I), r"\1***"),
        (re.compile(r"(passwd\s*[=:]\s*)\S+", re.I), r"\1***"),
        (re.compile(r"(token\s*[=:]\s*)\S+", re.I), r"\1***"),
        (re.compile(r"(secret\s*[=:]\s*)\S+", re.I), r"\1***"),
        (re.compile(r"(api[_-]?key\s*[=:]\s*)\S+", re.I), r"\1***"),
        (re.compile(r"(authorization\s*[=:]\s*)\S+", re.I), r"\1***"),
    ]
    out = text
    for rx, rep in patterns:
        out = rx.sub(rep, out)
    return out


def _yaml_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "" or s != s.strip() or any(c in s for c in ":#{}[]&*!|>'\"%@`\n\r\t") or s.lower() in (
        "true",
        "false",
        "null",
        "yes",
        "no",
        "on",
        "off",
    ):
        return json.dumps(s, ensure_ascii=False)
    return s


def ensure_rule_files_entry(raw: str, rule_path: str) -> tuple[str, bool]:
    """若 rule_files 缺少 rule_path 则外科插入；返回 (new_raw, changed)。"""
    if rule_path in raw:
        return raw, False
    basename = rule_path.rstrip("/").split("/")[-1]
    for ln in raw.splitlines():
        s = ln.strip()
        if s.startswith("- ") and basename in s and not s.startswith("- job_"):
            return raw, False
    lines = raw.splitlines(keepends=True)
    rf_idx = None
    rf_indent = 0
    for i, ln in enumerate(lines):
        m = re.match(r"^(\s*)rule_files\s*:", ln)
        if m:
            rf_idx = i
            rf_indent = len(m.group(1))
            break
    item = f'{" " * (rf_indent + 2)}- {rule_path}\n'
    if rf_idx is not None:
        # 插入到 rule_files 列表末尾（下一顶层键之前）
        j = rf_idx + 1
        while j < len(lines):
            ln = lines[j]
            if ln.strip() and not ln.startswith(" " * (rf_indent + 1)) and not ln.startswith("\t"):
                # 顶层或更浅
                cur_indent = len(ln) - len(ln.lstrip(" "))
                if ln.strip() and cur_indent <= rf_indent and not ln.lstrip().startswith("#"):
                    break
            if ln.strip().startswith("- ") or ln.strip() == "-":
                j += 1
                continue
            if not ln.strip() or ln.lstrip().startswith("#"):
                j += 1
                continue
            cur_indent = len(ln) - len(ln.lstrip(" "))
            if cur_indent <= rf_indent:
                break
            j += 1
        lines.insert(j, item)
        return "".join(lines), True
    # 无 rule_files：在文件末尾追加
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.append("rule_files:\n")
    lines.append(item)
    return "".join(lines), True


def ensure_file_sd_job(
    raw: str,
    *,
    job_name: str = "ayana-nodes",
    file_sd_path: str = "file_sd/ayana-nodes.json",
    interval: str = "30s",
) -> tuple[str, bool]:
    """确保存在使用 file_sd 的抓取任务；只追加，不改既有 job。"""
    if re.search(rf"job_name\s*:\s*[\"']?{re.escape(job_name)}[\"']?", raw):
        return raw, False
    lines = raw.splitlines(keepends=True)
    sc_idx = None
    sc_indent = 0
    for i, ln in enumerate(lines):
        m = re.match(r"^(\s*)scrape_configs\s*:", ln)
        if m:
            sc_idx = i
            sc_indent = len(m.group(1))
            break
    job_block = (
        f'{" " * (sc_indent + 2)}- job_name: {job_name}\n'
        f'{" " * (sc_indent + 4)}scrape_interval: {interval}\n'
        f'{" " * (sc_indent + 4)}file_sd_configs:\n'
        f'{" " * (sc_indent + 6)}- files:\n'
        f'{" " * (sc_indent + 8)}- {file_sd_path}\n'
    )
    if sc_idx is not None:
        j = sc_idx + 1
        while j < len(lines):
            ln = lines[j]
            if not ln.strip() or ln.lstrip().startswith("#"):
                j += 1
                continue
            cur_indent = len(ln) - len(ln.lstrip(" "))
            if cur_indent <= sc_indent and not ln.lstrip().startswith("-"):
                break
            j += 1
        lines.insert(j, job_block)
        return "".join(lines), True
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.append("scrape_configs:\n")
    lines.append(job_block)
    return "".join(lines), True


# ---------------------------------------------------------------------------
# 配置文件系统
# ---------------------------------------------------------------------------

class ConfigFS(Protocol):
    async def read_text(self, rel: str) -> str: ...
    async def write_text(self, rel: str, content: str) -> None: ...
    async def list_dir(self, rel: str) -> list[str]: ...
    async def exists(self, rel: str) -> bool: ...
    async def mkdir(self, rel: str) -> None: ...
    def describe(self) -> dict[str, Any]: ...


class LocalConfigFS:
    def __init__(self, base_dir: str | Path):
        self.base = Path(base_dir).resolve()
        # 启动不强制建目录；仅写入时创建

    def _path(self, rel: str) -> Path:
        rel = safe_rel_path(rel)
        base = self.base.resolve()
        p = (base / rel)
        # 允许路径尚不存在：对父目录做 containment，再拒绝符号链接逃逸
        resolved_parent = p.parent.resolve()
        try:
            resolved_parent.relative_to(base)
        except ValueError as e:
            raise PromConfigError("bad_path", rel) from e
        if p.is_symlink():
            target = p.resolve()
            try:
                target.relative_to(base)
            except ValueError as e:
                raise PromConfigError("symlink_escape", rel) from e
        # 最终路径词法上也不得越界
        try:
            p.resolve().relative_to(base) if p.exists() else None
        except ValueError as e:
            raise PromConfigError("bad_path", rel) from e
        return p

    async def read_text(self, rel: str) -> str:
        p = self._path(rel)
        if not p.exists():
            raise PromConfigError("not_found", rel)
        return p.read_text(encoding="utf-8")

    async def write_text(self, rel: str, content: str) -> None:
        p = self._path(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        # 同目录临时文件 + fsync + 原子替换 + 目录同步
        tmp = p.with_name(p.name + f".tmp.{secrets.token_hex(4)}")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
        try:
            dfd = os.open(str(p.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass

    async def list_dir(self, rel: str) -> list[str]:
        p = self._path(rel) if rel not in ("", ".") else self.base
        if not p.exists():
            return []
        return sorted(x.name for x in p.iterdir())

    async def exists(self, rel: str) -> bool:
        try:
            return self._path(rel).exists()
        except PromConfigError:
            return False

    async def mkdir(self, rel: str) -> None:
        self._path(rel).mkdir(parents=True, exist_ok=True)

    def describe(self) -> dict[str, Any]:
        return {"mode": "local", "base_dir": str(self.base)}


class SSHConfigFS:
    """经受控 SSH 读写远端 Prometheus 目录。相对路径 + 沙箱。"""

    def __init__(self, asset_id: str, transport: Any, remote_base: str):
        if not asset_id:
            raise PromConfigError("ssh_asset_required")
        self.asset_id = asset_id
        self.transport = transport
        base = (remote_base or "").strip()
        if not base.startswith("/") or ".." in base.split("/"):
            raise PromConfigError("bad_remote_base", remote_base)
        self.remote_base = base.rstrip("/")

    def _remote(self, rel: str) -> str:
        rel = safe_rel_path(rel)
        return f"{self.remote_base}/{rel}"

    async def read_text(self, rel: str) -> str:
        remote = self._remote(rel)
        # 固定命令形态：cat + 受控路径（路径来自沙箱，不含元字符）
        res = await self.transport.probe(self.asset_id, ["cat", remote], timeout=15)
        if not getattr(res, "ok", False):
            out = getattr(res, "output", "") or ""
            if "No such file" in out or "cannot open" in out:
                raise PromConfigError("not_found", rel)
            raise PromConfigError("ssh_read_failed", out[:300])
        return getattr(res, "output", "")

    async def write_text(self, rel: str, content: str) -> None:
        # 无 shell 元字符/空格的固定 argv 写入（兼容 SSHTransport 严格 token 校验）
        import base64 as _b64

        remote = self._remote(rel)
        parent = remote.rsplit("/", 1)[0]
        # mkdir -p <parent>
        r1 = await self.transport.exec(self.asset_id, ["mkdir", "-p", parent], timeout=15)
        if not getattr(r1, "ok", False):
            raise PromConfigError("ssh_mkdir_failed", (getattr(r1, "output", "") or "")[:200])
        b64 = _b64.b64encode(content.encode("utf-8")).decode("ascii")
        # python3 -c 无空格脚本：写临时文件并原子替换
        tmp = f"{remote}.tmp.{secrets.token_hex(4)}"
        script = (
            "import base64,os\n"
            f"p={remote!r}\n"
            f"t={tmp!r}\n"
            f"with open(t,'wb') as f: f.write(base64.b64decode({b64!r}))\n"
            "os.replace(t,p)"
        )
        code = _python_exec_token(script)
        # 安全：code 作为单一 argv，不含空格/元字符（repr 路径与 base64 无空格）
        if any(c in code for c in " \t\n;|&$`"):
            # 路径或内容意外引入空白时降级拒绝，避免放开 sh -c
            raise PromConfigError("ssh_write_token_unsafe", rel)
        res = await self.transport.exec(self.asset_id, ["python3", "-c", code], timeout=25)
        if not getattr(res, "ok", False):
            raise PromConfigError("ssh_write_failed", (getattr(res, "output", "") or "")[:300])

    async def list_dir(self, rel: str) -> list[str]:
        remote = self._remote(rel) if rel not in ("", ".") else self.remote_base
        res = await self.transport.probe(self.asset_id, ["ls", "-1", remote], timeout=12)
        if not getattr(res, "ok", False):
            return []
        out = getattr(res, "output", "") or ""
        return sorted(x for x in out.splitlines() if x.strip())

    async def exists(self, rel: str) -> bool:
        try:
            await self.read_text(rel)
            return True
        except PromConfigError as e:
            if e.code == "not_found":
                return False
            # 目录等
            return False

    async def mkdir(self, rel: str) -> None:
        remote = self._remote(rel)
        await self.transport.exec(self.asset_id, ["mkdir", "-p", remote], timeout=12)

    def describe(self) -> dict[str, Any]:
        return {
            "mode": "ssh",
            "asset_id": self.asset_id,
            "remote_base": self.remote_base,
        }


# ---------------------------------------------------------------------------
# 规则模板
# ---------------------------------------------------------------------------

@dataclass
class AlertTemplate:
    id: str
    name: str
    metric: str
    default_expr: str
    default_for: str
    default_severity: str
    description: str
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)


ALERT_TEMPLATES: list[AlertTemplate] = [
    AlertTemplate(
        id="cpu_high",
        name="CPU 使用率过高",
        metric="cpu",
        default_expr='100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80',
        default_for="5m",
        default_severity="warning",
        description="Node CPU 空闲率过低（默认阈值 80%）",
        annotations={
            "summary": "CPU 使用率过高 {{ $labels.instance }}",
            "description": "CPU 使用率 {{ $value | printf \"%.1f\" }}% 持续超过阈值",
        },
    ),
    AlertTemplate(
        id="mem_high",
        name="内存使用率过高",
        metric="memory",
        default_expr='(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 85',
        default_for="5m",
        default_severity="warning",
        description="可用内存不足（默认阈值 85%）",
        annotations={
            "summary": "内存使用率过高 {{ $labels.instance }}",
            "description": "内存使用率 {{ $value | printf \"%.1f\" }}%",
        },
    ),
    AlertTemplate(
        id="disk_high",
        name="磁盘使用率过高",
        metric="disk",
        default_expr='(1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"}) * 100 > 85',
        default_for="10m",
        default_severity="warning",
        description="文件系统使用率过高（默认阈值 85%）",
        annotations={
            "summary": "磁盘使用率过高 {{ $labels.instance }} {{ $labels.mountpoint }}",
            "description": "磁盘使用率 {{ $value | printf \"%.1f\" }}%",
        },
    ),
    AlertTemplate(
        id="load_high",
        name="系统负载过高",
        metric="load",
        default_expr='node_load15 / count without (cpu, mode) (node_cpu_seconds_total{mode="idle"}) > 2',
        default_for="10m",
        default_severity="warning",
        description="15 分钟负载 / CPU 核数过高（默认 2.0）",
        annotations={
            "summary": "系统负载过高 {{ $labels.instance }}",
            "description": "load15/核数 = {{ $value | printf \"%.2f\" }}",
        },
    ),
    AlertTemplate(
        id="host_down",
        name="主机离线",
        metric="up",
        default_expr='up{job="ayana-nodes"} == 0',
        default_for="2m",
        default_severity="critical",
        description="Node Exporter / 抓取目标离线",
        annotations={
            "summary": "主机离线 {{ $labels.instance }}",
            "description": "up == 0 持续超过 for 时长",
        },
    ),
]


def build_rule_yaml_from_template(
    tpl: AlertTemplate,
    *,
    enabled: bool = True,
    threshold: float | None = None,
    duration: str | None = None,
    severity: str | None = None,
    group_name: str = "ayana-node-alerts",
) -> tuple[str, dict[str, Any]]:
    """生成自有规则文件 YAML。返回 (yaml_text, rule_meta)。"""
    expr = tpl.default_expr
    if threshold is not None and tpl.id != "host_down":
        # 将表达式中最后一个比较阈值替换
        expr = re.sub(r"(>=?|<=?)\s*([0-9.]+)\s*$", f"> {threshold}", expr.strip())
    for_dur = duration or tpl.default_for
    sev = severity or tpl.default_severity
    rule = {
        "alert": _template_alert_name(tpl),
        "expr": expr,
        "for": for_dur,
        "labels": {**tpl.labels, "severity": sev, "managed_by": "ayana"},
        "annotations": dict(tpl.annotations),
    }
    doc = {
        "groups": [
            {
                "name": group_name,
                "rules": [rule] if enabled else [],
            }
        ]
    }
    meta = {
        "template_id": tpl.id,
        "alert": rule["alert"],
        "expr": expr,
        "for": for_dur,
        "severity": sev,
        "enabled": enabled,
        "threshold": threshold,
        "raw_editable": True,
        "managed_by": "ayana",
    }
    return dump_simple_yaml(doc), meta


def _template_alert_name(tpl: AlertTemplate) -> str:
    return {
        "cpu_high": "NodeCpuHigh",
        "mem_high": "NodeMemoryHigh",
        "disk_high": "NodeDiskHigh",
        "load_high": "NodeLoadHigh",
        "host_down": "NodeHostDown",
    }.get(tpl.id, f"Node{tpl.id.title().replace('_', '')}")


# ---------------------------------------------------------------------------
# 服务
# ---------------------------------------------------------------------------

MANAGED_FILE_SD = "file_sd/ayana-nodes.json"
MANAGED_RULES = "rules/ayana-node-alerts.yml"
MANAGED_JOB = "ayana-nodes"
CONFIG_FILE = "prometheus.yml"
# 配置文件内引用路径前缀：与本环境 alerts.yml 的 /etc/prometheus/... 一致
CONFIG_PATH_PREFIX = "/etc/prometheus/"


def _config_ref(rel: str, prefix: str | None = None) -> str:
    """生成 prometheus.yml 里引用的路径。前缀可配置，必须是绝对路径前缀。"""
    rel = safe_rel_path(rel)
    p = (prefix or CONFIG_PATH_PREFIX)
    if not p.endswith("/"):
        p += "/"
    if not p.startswith("/"):
        raise PromConfigError("bad_path_prefix", p)
    return p + rel


def _resolve_send_file(transport: Any):
    """多层 transport 包装时，找到真正的 send_file。"""
    if transport is None:
        return None
    fn = getattr(transport, "send_file", None)
    if callable(fn):
        return fn
    for attr in ("_ssh", "ssh", "inner", "_transport", "transport"):
        inner = getattr(transport, attr, None)
        if inner is not None and inner is not transport:
            fn = getattr(inner, "send_file", None)
            if callable(fn):
                return fn
    return None


async def _retry_exec(transport: Any, asset_id: str, tokens: list[str], *, timeout: float = 20.0, tries: int = 3):
    """SSH 偶发 kex reset：短重试。"""
    last = None
    for i in range(tries):
        try:
            r = await transport.exec(asset_id, tokens, timeout=timeout)
            if getattr(r, "ok", False) or i == tries - 1:
                return r
            last = r
        except Exception as e:
            last = e
        await asyncio.sleep(1.5 * (i + 1))
    if isinstance(last, Exception):
        raise last
    return last


class PromConfigService:
    def __init__(
        self,
        db: Database,
        fs: ConfigFS,
        *,
        prom: Any | None = None,
        transport: Any | None = None,
        promtool_bin: str = "promtool",
        reload_url: str = "",
        config_path_prefix: str = "/etc/prometheus/",
        local_assets: list[str] | None = None,
        require_promtool: bool = True,
    ):
        self.db = db
        self.fs = fs
        self.prom = prom
        self.transport = transport
        self.promtool_bin = promtool_bin or "promtool"
        self.reload_url = (reload_url or "").rstrip("/")
        self.config_path_prefix = config_path_prefix if config_path_prefix.endswith("/") else config_path_prefix + "/"
        self.local_assets = [str(a).strip() for a in (local_assets or []) if str(a).strip()]
        self.require_promtool = bool(require_promtool)
        self._write_lock = asyncio.Lock()
        self._last_good: dict[str, str] = {}  # path -> content
        self._txn_seq = 0

    def cfg_local_assets(self) -> list[str]:
        return list(self.local_assets)

    # ---- 审计 ----

    def _audit(self, actor_type: str, actor_id: str, entry: str, detail: dict | None = None) -> None:
        self.db.audit(
            actor_type,
            actor_id,
            entry,
            detail=detail or {},
            channel="web",
        )

    def _version(self, kind: str, payload: dict, actor: str) -> int:
        cur = self.db.execute(
            "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
            " VALUES(?,?,?,?)",
            (kind, json.dumps(payload, ensure_ascii=False), now(), actor),
        )
        return int(cur.lastrowid or 0)

    # ---- 读取 ----

    async def overview(self) -> dict[str, Any]:
        info = self.fs.describe()
        files = {}
        for name in (CONFIG_FILE, MANAGED_FILE_SD, MANAGED_RULES):
            try:
                text = await self.fs.read_text(name)
                files[name] = {"exists": True, "size": len(text)}
            except PromConfigError:
                files[name] = {"exists": False}
        for d in ("file_sd", "rules"):
            try:
                entries = await self.fs.list_dir(d)
            except Exception:
                entries = []
            files[f"{d}/"] = entries
        live = {}
        if self.prom:
            try:
                targets = await self.prom.targets()
                live["targets_total"] = len(targets)
                live["targets_up"] = sum(1 for t in targets if t.get("health") == "up")
                live["targets_down"] = sum(1 for t in targets if t.get("health") != "up")
            except Exception as e:
                live["error"] = str(e)[:200]
        return {
            "fs": info,
            "files": files,
            "live": live,
            "managed_job": MANAGED_JOB,
            "managed_file_sd": MANAGED_FILE_SD,
            "managed_rules": MANAGED_RULES,
        }

    async def read_config(self) -> dict[str, Any]:
        """读取 prometheus.yml：原文 + 结构化摘要。"""
        try:
            raw = await self.fs.read_text(CONFIG_FILE)
        except PromConfigError as e:
            return {"ok": False, "error": e.code, "detail": e.detail}
        structured: dict[str, Any] = {}
        parse_error = ""
        try:
            data = parse_simple_yaml(raw)
            if isinstance(data, dict):
                structured = data
        except PromConfigError as e:
            parse_error = e.detail or e.code
        except Exception as e:
            parse_error = str(e)[:200]

        jobs = []
        scrape = structured.get("scrape_configs") if isinstance(structured, dict) else None
        if isinstance(scrape, list):
            for j in scrape:
                if not isinstance(j, dict):
                    continue
                jobs.append(_summarize_job(j))

        rule_files = structured.get("rule_files") if isinstance(structured, dict) else None
        if not isinstance(rule_files, list):
            rule_files = []
        return {
            "ok": True,
            "raw": _redact_secrets(raw),
            "jobs": jobs,
            "rule_files": rule_files,
            "global": structured.get("global") if isinstance(structured, dict) else {},
            "parse_error": parse_error,
            "structured_editable": not parse_error,
        }

    async def read_rules(self) -> dict[str, Any]:
        """读取规则文件：简单规则结构化，复杂规则只读原文。"""
        out_files: list[dict[str, Any]] = []
        try:
            names = await self.fs.list_dir("rules")
        except Exception:
            names = []
        # 也收集 prometheus.yml rule_files 指向的路径
        cfg = await self.read_config()
        candidates = [f"rules/{n}" for n in names if n.endswith((".yml", ".yaml"))]
        for rf in cfg.get("rule_files") or []:
            rel = self._map_rule_ref_to_rel(str(rf))
            if not rel or rel in candidates:
                continue
            candidates.append(rel)
        for rel in candidates:
            try:
                raw = await self.fs.read_text(rel)
            except PromConfigError:
                continue
            parsed, complex_reason = _parse_rules_file(raw)
            out_files.append(
                {
                    "path": rel,
                    "managed_by": "ayana" if rel == MANAGED_RULES else "",
                    "raw": raw,
                    "groups": parsed,
                    "editable": not complex_reason,
                    "complex_reason": complex_reason,
                }
            )
        return {"ok": True, "files": out_files, "templates": _templates_public()}

    # ---- 目标（file_sd）----

    async def list_targets(self) -> dict[str, Any]:
        cfg = await self.read_config()
        config_targets: list[dict[str, Any]] = []
        for job in cfg.get("jobs") or []:
            for t in job.get("targets") or []:
                config_targets.append({**t, "job": job.get("job_name"), "via": job.get("via")})
        # file_sd 文件
        sd_targets: list[dict[str, Any]] = []
        try:
            names = await self.fs.list_dir("file_sd")
        except Exception:
            names = []
        for n in names:
            if not n.endswith(".json"):
                continue
            rel = f"file_sd/{n}"
            try:
                raw = await self.fs.read_text(rel)
                data = json.loads(raw)
            except Exception:
                continue
            for item in data if isinstance(data, list) else []:
                if not isinstance(item, dict):
                    continue
                labels = item.get("labels") or {}
                for tgt in item.get("targets") or []:
                    sd_targets.append(
                        {
                            "address": tgt,
                            "labels": labels,
                            "file": rel,
                            "managed_by": "ayana" if rel == MANAGED_FILE_SD else "",
                        }
                    )
        live: list[dict[str, Any]] = []
        if self.prom:
            try:
                for t in await self.prom.targets():
                    live.append(
                        {
                            "scrapeUrl": t.get("scrapeUrl") or "",
                            "labels": t.get("labels") or {},
                            "health": t.get("health") or "",
                            "lastError": t.get("lastError") or "",
                            "lastScrape": t.get("lastScrape") or "",
                            "job": (t.get("labels") or {}).get("job") or "",
                        }
                    )
            except Exception as e:
                live = [{"error": str(e)[:200]}]
        return {
            "ok": True,
            "config_targets": config_targets,
            "file_sd_targets": sd_targets,
            "live_targets": live,
            "parse_error": cfg.get("parse_error") or "",
        }

    async def add_target(
        self,
        *,
        address: str,
        labels: dict[str, str] | None = None,
        actor: str = "web",
        job: str = MANAGED_JOB,
        interval: str = "30s",
    ) -> dict[str, Any]:
        address = _validate_target_address(address)
        labels = _clean_labels(labels or {})
        if job != MANAGED_JOB:
            raise PromConfigError("job_not_managed", job)
        items = await self._load_file_sd()
        for it in items:
            if address in (it.get("targets") or []):
                raise PromConfigError("target_exists", address)
        items.append({"targets": [address], "labels": labels})
        await self._write_file_sd(items, actor, action="target_add", detail={"address": address, "labels": labels})
        await self._ensure_job_and_rules_entry(actor)
        return {"ok": True, "address": address, "labels": labels}

    async def update_target(
        self,
        *,
        address: str,
        new_address: str | None = None,
        labels: dict[str, str] | None = None,
        actor: str = "web",
    ) -> dict[str, Any]:
        address = _validate_target_address(address)
        new_address = _validate_target_address(new_address) if new_address else address
        labels = _clean_labels(labels or {}) if labels is not None else None
        items = await self._load_file_sd()
        found = False
        # 新地址冲突检查
        if new_address and new_address != address:
            for it in items:
                if new_address in (it.get("targets") or []):
                    raise PromConfigError("target_exists", new_address)
        for it in items:
            tgts = it.get("targets") or []
            if address in tgts:
                found = True
                tgts = [new_address if t == address else t for t in tgts]
                it["targets"] = tgts
                if labels is not None:
                    it["labels"] = labels
        if not found:
            raise PromConfigError("target_not_found", address)
        await self._write_file_sd(
            items, actor, action="target_update", detail={"address": address, "new": new_address, "labels": labels}
        )
        return {"ok": True}

    async def delete_target(self, *, address: str, actor: str = "web") -> dict[str, Any]:
        address = _validate_target_address(address)
        items = await self._load_file_sd()
        new_items = []
        found = False
        for it in items:
            tgts = [t for t in (it.get("targets") or []) if t != address]
            if len(tgts) != len(it.get("targets") or []):
                found = True
            if tgts:
                it = dict(it)
                it["targets"] = tgts
                new_items.append(it)
        if not found:
            raise PromConfigError("target_not_found", address)
        await self._write_file_sd(new_items, actor, action="target_delete", detail={"address": address})
        return {"ok": True}

    async def _load_file_sd(self) -> list[dict[str, Any]]:
        try:
            raw = await self.fs.read_text(MANAGED_FILE_SD)
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except PromConfigError as e:
            if e.code == "not_found":
                return []
            raise
        except json.JSONDecodeError:
            raise PromConfigError("file_sd_invalid_json", MANAGED_FILE_SD)

    async def _write_file_sd(self, items: list[dict], actor: str, *, action: str, detail: dict) -> None:
        content = json.dumps(items, ensure_ascii=False, indent=2) + "\n"
        await self.fs.mkdir("file_sd")
        await self._apply_write(
            actor,
            action,
            writes={MANAGED_FILE_SD: content},
            detail=detail,
        )

    async def _apply_write(
        self,
        actor: str,
        action: str,
        *,
        writes: dict[str, str | None],
        detail: dict | None = None,
    ) -> dict[str, Any]:
        """事务写入：备份 → 提交 → promtool → reload；失败恢复并拒绝报告成功。"""
        async with self._write_lock:
            originals: dict[str, str | None] = {}
            for rel in writes:
                try:
                    originals[rel] = await self.fs.read_text(rel)
                except PromConfigError:
                    originals[rel] = None
            for rel, orig in originals.items():
                if orig is not None:
                    await self._backup_if_exists(rel, actor, action)
            check: dict[str, Any] = {}
            relr: dict[str, Any] = {}
            try:
                for rel, content in writes.items():
                    if content is None:
                        continue
                    await self.fs.write_text(rel, content)
                if self.require_promtool:
                    check = await self._run_promtool_check()
                    if not check.get("ok"):
                        raise PromConfigError("promtool_failed", str(check)[:400])
                relr = await self._try_reload()
                if not relr.get("ok"):
                    raise PromConfigError("reload_failed", str(relr)[:400])
                for rel, content in writes.items():
                    if content is not None:
                        self._last_good[rel] = content
                self._txn_seq += 1
                self._audit(
                    "web_user",
                    actor,
                    f"promconfig_{action}",
                    {
                        **(detail or {}),
                        "paths": list(writes.keys()),
                        "txn": self._txn_seq,
                        "promtool_ok": bool(check.get("ok")) if check else None,
                        "reload_ok": True,
                    },
                )
                return {"ok": True, "promtool": check, "reload": relr, "txn": self._txn_seq}
            except Exception as e:
                for rel, orig in originals.items():
                    if orig is not None:
                        try:
                            await self.fs.write_text(rel, orig)
                        except Exception:
                            pass
                try:
                    await self._try_reload()
                except Exception:
                    pass
                self._audit(
                    "web_user",
                    actor,
                    f"promconfig_{action}_failed",
                    {"detail": str(e)[:300], "paths": list(writes.keys())},
                )
                raise

    async def _ensure_job_and_rules_entry(self, actor: str) -> None:
        """确保 prometheus.yml 含 ayana-nodes job 与规则文件引用；外科插入。"""
        try:
            raw = await self.fs.read_text(CONFIG_FILE)
        except PromConfigError:
            return
        new_raw, ch1 = ensure_file_sd_job(
            raw,
            job_name=MANAGED_JOB,
            file_sd_path=_config_ref(MANAGED_FILE_SD, self.config_path_prefix),
            interval="30s",
        )
        new_raw, ch2 = ensure_rule_files_entry(new_raw, _config_ref(MANAGED_RULES, self.config_path_prefix))
        # 兼容：若只写了相对路径也算已链接
        if not ch2 and MANAGED_RULES not in new_raw:
            new_raw, ch2 = ensure_rule_files_entry(new_raw, MANAGED_RULES)
        if not (ch1 or ch2):
            return
        await self._apply_write(
            actor,
            "config_link_managed",
            writes={CONFIG_FILE: new_raw},
            detail={"job_added": ch1, "rule_files_added": ch2},
        )

    # ---- 规则 ----

    async def list_templates(self) -> list[dict[str, Any]]:
        return _templates_public()

    async def apply_template(
        self,
        *,
        template_id: str,
        enabled: bool = True,
        threshold: float | None = None,
        duration: str | None = None,
        severity: str | None = None,
        actor: str = "web",
    ) -> dict[str, Any]:
        tpl = next((t for t in ALERT_TEMPLATES if t.id == template_id), None)
        if not tpl:
            raise PromConfigError("unknown_template", template_id)
        if severity and severity not in ("info", "warning", "critical"):
            raise PromConfigError("bad_severity", severity)
        if duration and not re.fullmatch(r"\d+[smhd]", duration):
            raise PromConfigError("bad_duration", duration)
        yaml_text, meta = build_rule_yaml_from_template(
            tpl, enabled=enabled, threshold=threshold, duration=duration, severity=severity
        )
        # 合并进 managed rules 文件：按 template_id 替换单条
        await self._upsert_managed_rule(meta, yaml_text, actor)
        await self._ensure_job_and_rules_entry(actor)
        return {"ok": True, "rule": meta}

    async def _upsert_managed_rule(self, meta: dict, yaml_text: str, actor: str) -> None:
        """managed 规则文件：按 alert 名合并，保留其他 managed 规则。"""
        existing_raw = ""
        try:
            existing_raw = await self.fs.read_text(MANAGED_RULES)
        except PromConfigError:
            existing_raw = ""
        rules = []
        if existing_raw:
            parsed, reason = _parse_rules_file(existing_raw)
            if reason:
                raise PromConfigError("rule_file_complex", reason)
            for g in parsed:
                for r in g.get("rules") or []:
                    if r.get("unknown_keys") or not r.get("simple_editable", True):
                        raise PromConfigError("rule_file_complex", "non_simple_rule")
                    if r.get("alert") != meta.get("alert"):
                        rules.append(r)
        if meta.get("enabled"):
            # 从 yaml_text 解析出新规则体
            parsed_new, _ = _parse_rules_file(yaml_text)
            for g in parsed_new:
                for r in g.get("rules") or []:
                    r = dict(r)
                    r["managed_by"] = "ayana"
                    r["template_id"] = meta.get("template_id")
                    rules.append(r)
        doc = _rules_doc(rules)
        content = dump_simple_yaml(doc)
        await self.fs.mkdir("rules")
        await self._apply_write(
            actor,
            "rules_apply_template",
            writes={MANAGED_RULES: content},
            detail={
                "template_id": meta.get("template_id"),
                "enabled": meta.get("enabled"),
                "alert": meta.get("alert"),
            },
        )

    async def update_rule(
        self,
        *,
        file_path: str,
        alert: str,
        expr: str | None = None,
        duration: str | None = None,
        severity: str | None = None,
        enabled: bool | None = None,
        actor: str = "web",
    ) -> dict[str, Any]:
        """结构化编辑简单规则；复杂/无法无损写回则拒绝。"""
        rel = safe_rel_path(file_path)
        if rel != MANAGED_RULES:
            # 非 Ayana 托管文件：默认拒绝写回，避免破坏手写配置
            raise PromConfigError("file_not_managed", rel)
        if duration and not re.fullmatch(r"\d+[smhd]", duration):
            raise PromConfigError("bad_duration", duration)
        if severity and severity not in ("info", "warning", "critical"):
            raise PromConfigError("bad_severity", severity)
        raw = await self.fs.read_text(rel)
        parsed, reason = _parse_rules_file(raw)
        if reason:
            raise PromConfigError("rule_file_complex", reason)
        new_rules: list[dict] = []
        found = False
        for g in parsed:
            for r in g.get("rules") or []:
                if r.get("alert") == alert:
                    found = True
                    if enabled is False:
                        continue
                    r = dict(r)
                    if expr is not None:
                        r["expr"] = expr
                    if duration is not None:
                        r["for"] = duration
                    if severity is not None:
                        labels = dict(r.get("labels") or {})
                        labels["severity"] = severity
                        r["labels"] = labels
                    new_rules.append(r)
                else:
                    new_rules.append(r)
        if not found:
            raise PromConfigError("rule_not_found", alert)
        for g in parsed:
            for r in g.get("rules") or []:
                if r.get("alert") == alert and not r.get("simple_editable", True):
                    raise PromConfigError("rule_not_simple", alert)
        doc = _rules_doc(new_rules)
        content = dump_simple_yaml(doc)
        await self._apply_write(
            actor,
            "rule_update",
            writes={rel: content},
            detail={"file": rel, "alert": alert, "enabled": enabled, "severity": severity},
        )
        return {"ok": True}

    # ---- 安全应用 ----

    async def _backup_if_exists(self, rel: str, actor: str, tag: str) -> str | None:
        try:
            text = await self.fs.read_text(rel)
        except PromConfigError:
            return None
        backup_rel = f"backups/{int(time.time())}-{tag}-{safe_file_name(Path(rel).name)}"
        # backups 下再分层
        backup_rel = safe_rel_path(backup_rel)
        await self.fs.mkdir("backups")
        await self.fs.write_text(backup_rel, text)
        self._version(
            "promconfig_backup",
            {"path": rel, "backup": backup_rel, "content": text, "tag": tag},
            actor,
        )
        return backup_rel

    async def rollback_last(self, *, path: str, actor: str = "web") -> dict[str, Any]:
        """恢复最近成功运行版本（优先 last_good），否则最近备份；必须校验+重载成功。"""
        rel = safe_rel_path(path)
        # 优先恢复变更前备份（撤销最近一次修改）；无备份时退回 last_good
        row = self.db.query_one(
            "SELECT payload_json FROM config_versions WHERE kind='promconfig_backup'"
            " AND json_extract(payload_json, '$.path')=? ORDER BY id DESC LIMIT 1",
            (rel,),
        )
        content = None
        source = ""
        backup_id = ""
        if row:
            payload = json.loads(row["payload_json"])
            content = payload.get("content")
            source = "backup"
            backup_id = str(payload.get("backup") or "")
        if content is None:
            content = self._last_good.get(rel)
            source = "last_good"
        if content is None:
            raise PromConfigError("no_backup", rel)
        async with self._write_lock:
            try:
                await self.fs.write_text(rel, content)
                if self.require_promtool:
                    check = await self._run_promtool_check()
                    if not check.get("ok"):
                        raise PromConfigError("promtool_failed", str(check)[:300])
                relr = await self._try_reload()
                if not relr.get("ok"):
                    raise PromConfigError("reload_failed", str(relr)[:300])
            except Exception as e:
                self._audit(
                    "web_user",
                    actor,
                    "promconfig_rollback_failed",
                    {"path": rel, "error": str(e)[:300]},
                )
                raise
            self._last_good[rel] = content
            self._audit(
                "web_user",
                actor,
                "promconfig_rollback",
                {"path": rel, "source": source, "backup": backup_id},
            )
        return {"ok": True, "path": rel, "source": source}

    async def validate_and_reload(self, *, actor: str = "web") -> dict[str, Any]:
        """promtool 校验 + 热重载（不写文件）。"""
        return await self._promtool_and_reload(actor, write_check=True)

    async def _promtool_and_reload(self, actor: str, write_check: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {"promtool": "skipped", "reload": "skipped"}
        # 本地模式可跑 promtool；SSH 模式在远端跑
        if write_check:
            try:
                check = await self._run_promtool_check()
                result["promtool"] = check
                if not check.get("ok"):
                    return {"ok": False, "error": "promtool_failed", "detail": check}
            except Exception as e:
                result["promtool"] = {"ok": False, "error": str(e)[:300]}
                return {"ok": False, "error": "promtool_failed", "detail": result["promtool"]}
        try:
            rel = await self._try_reload()
            result["reload"] = rel
            if not rel.get("ok"):
                return {"ok": False, "error": "reload_failed", "detail": rel, **result}
        except Exception as e:
            result["reload"] = {"ok": False, "error": str(e)[:300]}
            return {"ok": False, "error": "reload_failed", "detail": result["reload"], **result}
        return {"ok": True, **result}

    async def _run_promtool_check(self) -> dict[str, Any]:
        """在配置所在环境执行 promtool check config / rules。"""
        mode = self.fs.describe().get("mode")
        if mode == "local":
            return await self._promtool_local()
        return await self._promtool_remote()

    def _promtool_candidates(self) -> list[list[str]]:
        """promtool 命令候选：配置路径 → 常见安装位置 → 容器内。"""
        bins = []
        if self.promtool_bin and self.promtool_bin not in ("promtool", ""):
            bins.append(self.promtool_bin)
        bins.extend(
            [
                "promtool",
                "/usr/local/bin/promtool",
                "/usr/bin/promtool",
                "/bin/promtool",
            ]
        )
        seen: set[str] = set()
        out: list[list[str]] = []
        for b in bins:
            if b in seen:
                continue
            seen.add(b)
            out.append([b])
        # Docker 常见容器名（只读校验，不改容器）
        for cname in ("prometheus", "prometheus-server", "prom"):
            out.append(["docker", "exec", cname, "promtool"])
        return out

    async def _promtool_local(self) -> dict[str, Any]:
        base = Path(self.fs.describe()["base_dir"])
        cfg_path = base / CONFIG_FILE
        if not cfg_path.exists():
            return {"ok": False, "error": "config_missing"}
        # 容器路径与宿主路径可能不同：宿主绝对路径 / 容器内路径 / docker exec
        host_arg = str(cfg_path)
        container_arg = f"/etc/prometheus/{CONFIG_FILE}"
        last_err = ""
        # 优先 docker exec（与 Prometheus 进程同视角，rule_files 绝对路径可解析）
        for cname in ("prometheus", "prometheus-server", "prom"):
            cmd = ["docker", "exec", cname, "promtool", "check", "config", container_arg]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=25)
                text = ((out_b or b"") + (err_b or b"")).decode("utf-8", "replace")
                if proc.returncode == 0:
                    return {"ok": True, "output": text[:1000], "returncode": 0, "cmd": "docker exec " + cname}
                if "no such" in text.lower() or "not found" in text.lower() or "error response" in text.lower():
                    last_err = text[:160]
                    continue
                # promtool 在容器内运行但配置有错 → 真实失败
                return {"ok": False, "output": text[:1000], "returncode": proc.returncode, "cmd": "docker exec " + cname}
            except FileNotFoundError:
                last_err = "docker_not_found"
                break
            except Exception as e:
                last_err = str(e)[:160]
                continue
        for prefix in self._promtool_candidates():
            if prefix[0] == "docker":
                continue  # 上面已试
            for arg in (host_arg, container_arg):
                cmd = [*prefix, "check", "config", arg]
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=str(base),
                    )
                    out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=25)
                except FileNotFoundError:
                    last_err = f"not_found:{cmd[0]}"
                    break
                except Exception as e:
                    last_err = str(e)[:160]
                    continue
                text = ((out_b or b"") + (err_b or b"")).decode("utf-8", "replace")
                if proc.returncode == 0:
                    return {
                        "ok": True,
                        "output": text[:1000],
                        "returncode": 0,
                        "cmd": " ".join(cmd[:3]),
                    }
                last_err = text[:200]
                if "no such file" in text.lower() or "does not point" in text.lower():
                    continue
                return {
                    "ok": False,
                    "output": text[:1000],
                    "returncode": proc.returncode,
                    "cmd": " ".join(cmd[:3]),
                }
        return {
            "ok": not self.require_promtool,
            "skipped": "promtool_not_found" if not self.require_promtool else "",
            "error": "promtool_not_found" if self.require_promtool else "",
            "detail": last_err,
        }

    async def _promtool_remote(self) -> dict[str, Any]:
        if not self.transport:
            return {"ok": not self.require_promtool, "error": "no_transport" if self.require_promtool else ""}
        asset = self.fs.describe().get("asset_id")
        remote_cfg = self.fs.describe().get("remote_base") + "/" + CONFIG_FILE
        res = await self.transport.exec(
            asset, [self.promtool_bin, "check", "config", remote_cfg], timeout=25
        )
        out = getattr(res, "output", "") or ""
        return {"ok": bool(getattr(res, "ok", False)), "output": out[:1000]}

    async def _try_reload(self) -> dict[str, Any]:
        """POST /-/reload 热重载；失败返回错误。"""
        base = ""
        if getattr(self, "reload_url", ""):
            base = self.reload_url.rstrip("/")
        elif self.prom and getattr(self.prom, "base_url", ""):
            base = self.prom.base_url.rstrip("/")
        if not base:
            return {"ok": False, "error": "no_reload_url"}
        url = base + "/-/reload"
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=8)
            ) as session:
                async with session.post(url) as resp:
                    text = await resp.text()
                    ok = resp.status in (200, 202)
                    return {"ok": ok, "status": resp.status, "body": text[:200], "url": url}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200], "url": url}

    def _map_rule_ref_to_rel(self, ref: str) -> str:
        """把配置里的 rule_files 路径映射为本地相对路径。

        容器内 /etc/prometheus/xxx → xxx（local_dir 即配置根）。
        """
        ref = (ref or "").strip()
        if not ref:
            return ""
        # 已是相对路径
        if not ref.startswith("/") and not ref.startswith("~"):
            try:
                return safe_rel_path(ref)
            except PromConfigError:
                return ""
        # 绝对路径：去掉常见容器前缀
        for prefix in (
            "/etc/prometheus/",
            "/prometheus/",
            "/etc/alertmanager/",
        ):
            if ref.startswith(prefix):
                rel = ref[len(prefix) :]
                try:
                    return safe_rel_path(rel)
                except PromConfigError:
                    return ""
        # 其它绝对路径：取文件名（保守）
        name = ref.rstrip("/").split("/")[-1]
        try:
            return safe_rel_path(name)
        except PromConfigError:
            return ""

    # ---- Node Exporter ----

    async def _ensure_node_exporter_user(self, asset_id: str, transport: Any) -> None:
        result = await transport.probe(asset_id, ["id", "-u", "node_exporter"], timeout=10)
        if getattr(result, "ok", False):
            return
        result = await transport.exec(
            asset_id,
            ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "node_exporter"],
            timeout=20,
        )
        if not getattr(result, "ok", False):
            raise PromConfigError("node_exporter_user_failed", (getattr(result, "output", "") or "")[:200])

    async def node_exporter_status(self, asset_id: str, transport: Any) -> dict[str, Any]:
        out: dict[str, Any] = {
            "asset_id": asset_id,
            "installed": False,
            "active": False,
            "port_9100": False,
            "mode": "",
        }
        # 优先识别 Docker 容器（常见：node-exporter / node_exporter）
        for cname in ("node-exporter", "node_exporter"):
            try:
                r = await transport.probe(
                    asset_id,
                    ["docker", "inspect", "-f", "{{.State.Running}}", cname],
                    timeout=10,
                )
                txt = (getattr(r, "output", "") or "").strip()
                if getattr(r, "ok", False) and txt in ("true", "false"):
                    out["mode"] = f"docker:{cname}"
                    out["installed"] = True
                    out["active"] = txt == "true"
                    break
            except Exception:
                continue
        if not out["mode"]:
            try:
                r1 = await transport.probe(asset_id, ["systemctl", "is-active", "node_exporter"], timeout=10)
                out["active"] = bool(getattr(r1, "ok", False)) and (getattr(r1, "output", "") or "").strip() == "active"
                out["mode"] = "systemd"
            except Exception as e:
                out["error_active"] = str(e)[:120]
        try:
            r2 = await transport.probe(
                asset_id, ["ss", "-H", "-lnt", "sport", "=", "9100"], timeout=10
            )
            out["port_9100"] = _listens_on_9100(r2)
        except Exception as e:
            out["error_port"] = str(e)[:120]
        if out["mode"] == "systemd":
            try:
                r3 = await transport.probe(
                    asset_id, ["systemctl", "show", "node_exporter", "--property=LoadState,UnitFileState", "--value"],
                    timeout=10,
                )
                txt = (getattr(r3, "output", "") or "").strip()
                out["load_state"] = txt
                out["installed"] = bool(getattr(r3, "ok", False)) and "not-found" not in txt and bool(txt)
            except Exception as e:
                out["error_load"] = str(e)[:120]
        out["running"] = bool(out.get("active") and out.get("port_9100"))
        return out

    async def node_exporter_control(
        self,
        *,
        asset_id: str,
        action: str,
        transport: Any,
        actor: str = "web",
        listen_address: str = "127.0.0.1:9100",
        allow_non_private: bool = False,
    ) -> dict[str, Any]:
        """安装/启动/停止 Node Exporter。命令固定，禁止任意参数。"""
        if action not in ("install", "start", "stop", "check"):
            raise PromConfigError("bad_action", action)
        if action == "check":
            return await self.node_exporter_status(asset_id, transport)
        if action == "install":
            listen_address = assert_safe_listen_address(
                listen_address, allow_non_private=allow_non_private
            )
        # 写操作审计
        self._audit(
            "web_user",
            actor,
            f"node_exporter_{action}",
            {"asset_id": asset_id, "listen": listen_address if action == "install" else ""},
        )
        if action in ("start", "stop"):
            verb = action
            st = await self.node_exporter_status(asset_id, transport)
            mode = st.get("mode") or ""
            if mode.startswith("docker:"):
                cname = mode.split(":", 1)[1]
                # 固定容器名白名单
                if cname not in ("node-exporter", "node_exporter"):
                    raise PromConfigError("bad_container", cname)
                res = await transport.exec(asset_id, ["docker", verb, cname], timeout=20)
            else:
                res = await transport.exec(asset_id, ["systemctl", verb, "node_exporter"], timeout=20)
            ok = bool(getattr(res, "ok", False))
            if not ok:
                raise PromConfigError("node_exporter_ctl_failed", (getattr(res, "output", "") or "")[:200])
            return {
                "ok": True,
                "action": action,
                "mode": mode,
                "output": (getattr(res, "output", "") or "")[:200],
            }

        # install：固定步骤；默认监听 127.0.0.1:9100
        steps: list[dict[str, Any]] = []
        # 1) 已存在则不重复安装
        st = await self.node_exporter_status(asset_id, transport)
        if st.get("installed") and st.get("active"):
            return {"ok": True, "skipped": "already_installed", "status": st}
        if (st.get("mode") or "").startswith("docker:"):
            # Docker 已装：只启动，不写 systemd unit
            cname = st["mode"].split(":", 1)[1]
            res = await transport.exec(asset_id, ["docker", "start", cname], timeout=20)
            steps.append(
                {
                    "step": "docker_start",
                    "ok": bool(getattr(res, "ok", False)),
                    "output": (getattr(res, "output", "") or "")[:200],
                }
            )
            if steps[-1]["ok"]:
                return {
                    "ok": True,
                    "action": "install",
                    "skipped": "docker_already_present",
                    "steps": steps,
                    "status": await self.node_exporter_status(asset_id, transport),
                }
            raise PromConfigError("node_exporter_install_failed", steps[-1]["output"])
        if st.get("installed") and not st.get("active") and st.get("mode") == "systemd":
            res = await transport.exec(asset_id, ["systemctl", "start", "node_exporter"], timeout=20)
            if not getattr(res, "ok", False):
                raise PromConfigError("node_exporter_ctl_failed", (getattr(res, "output", "") or "")[:200])
            return {
                "ok": True,
                "action": "install",
                "skipped": "already_installed_start_only",
                "status": await self.node_exporter_status(asset_id, transport),
            }
        # 2) 优先 docker run（本地已有镜像则不拉外网）
        dr = await transport.exec(
            asset_id,
            [
                "docker",
                "run",
                "-d",
                "--name",
                "node-exporter",
                "--restart",
                "unless-stopped",
                "--net",
                "host",
                "prom/node-exporter:latest",
            ],
            timeout=90,
        )
        steps.append(
            {
                "step": "docker_run",
                "ok": bool(getattr(dr, "ok", False)),
                "output": (getattr(dr, "output", "") or "")[:300],
            }
        )
        if steps[-1]["ok"]:
            return {
                "ok": True,
                "action": "install",
                "method": "docker",
                "steps": steps,
                "status": await self.node_exporter_status(asset_id, transport),
            }
        # 3) 本机二进制 + systemd
        bin_path = ""
        for p in (
            "/usr/local/bin/node_exporter",
            "/usr/bin/node_exporter",
            "/bin/node_exporter",
        ):
            rchk = await transport.probe(asset_id, ["test", "-x", p], timeout=8)
            if getattr(rchk, "ok", False):
                bin_path = p
                break
        if not bin_path:
            raise PromConfigError(
                "node_exporter_binary_missing",
                "need docker image prom/node-exporter or /usr/local/bin/node_exporter",
            )
        # 2) 写 unit 文件（固定内容，监听地址经校验）；固定 argv，无 sh -c
        await self._ensure_node_exporter_user(asset_id, transport)
        unit = _node_exporter_unit(listen_address, bin_path)
        res = await transport.exec(asset_id, _node_exporter_write_tokens(unit), timeout=25)
        steps.append(
            {
                "step": "install_unit",
                "ok": bool(getattr(res, "ok", False)),
                "output": (getattr(res, "output", "") or "")[:400],
            }
        )
        if not steps[-1]["ok"]:
            raise PromConfigError("node_exporter_install_failed", steps[-1]["output"])
        for cmd in (
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "node_exporter"],
            ["systemctl", "start", "node_exporter"],
        ):
            r = await transport.exec(asset_id, cmd, timeout=20)
            steps.append(
                {
                    "step": cmd[0] + "_" + cmd[1],
                    "ok": bool(getattr(r, "ok", False)),
                    "output": (getattr(r, "output", "") or "")[:200],
                }
            )
            if not steps[-1]["ok"]:
                raise PromConfigError("node_exporter_install_failed", steps[-1]["output"])
        st2 = await self.node_exporter_status(asset_id, transport)
        return {"ok": True, "action": "install", "steps": steps, "status": st2}

    async def register_node_target(
        self,
        *,
        asset_id: str,
        address: str,
        labels: dict[str, str] | None = None,
        actor: str = "web",
    ) -> dict[str, Any]:
        """将已有 Node Exporter 注册为监控目标（file_sd）。"""
        labels = dict(labels or {})
        labels.setdefault("asset", asset_id)
        labels.setdefault("job_type", "node_exporter")
        return await self.add_target(address=address, labels=labels, actor=actor)

    async def detect_exporter(self, asset_id: str, transport: Any) -> dict[str, Any]:
        """检测目标机安装条件：Docker / 二进制 / systemd。"""
        out: dict[str, Any] = {
            "asset_id": asset_id,
            "docker": False,
            "binary": "",
            "systemd": False,
            "port_9100": False,
            "running": False,
            "recommend": "binary",
            "reason": "",
        }
        # docker?
        try:
            r = await transport.probe(asset_id, ["docker", "version", "--format", "{{.Server.Version}}"], timeout=10)
            out["docker"] = bool(getattr(r, "ok", False))
        except Exception:
            out["docker"] = False
        # 本机二进制？
        for p in (
            "/usr/local/bin/node_exporter",
            "/usr/bin/node_exporter",
            "/bin/node_exporter",
        ):
            try:
                r = await transport.probe(asset_id, ["test", "-x", p], timeout=8)
                if getattr(r, "ok", False):
                    version = await transport.probe(asset_id, [p, "--version"], timeout=8)
                    if getattr(version, "ok", False):
                        out["binary"] = p
                        break
                    out["binary_error"] = f"{p}: version check failed"
            except Exception:
                continue
        try:
            r = await transport.probe(asset_id, ["systemctl", "--version"], timeout=8)
            out["systemd"] = bool(getattr(r, "ok", False))
        except Exception:
            out["systemd"] = False
        try:
            r = await transport.probe(asset_id, ["ss", "-H", "-lnt", "sport", "=", "9100"], timeout=8)
            out["port_9100"] = _listens_on_9100(r)
        except Exception:
            pass
        st = await self.node_exporter_status(asset_id, transport)
        out["running"] = bool(st.get("running"))
        out["status"] = st
        # 推荐
        if out["running"] or (out["port_9100"] and out["binary"]):
            out["recommend"] = "none"
            out["reason"] = "already_running" if out["running"] else "already_listening"
        elif out["docker"]:
            out["recommend"] = "docker"
            out["reason"] = "docker_available"
        elif out["binary"] or self.package_binary():
            out["recommend"] = "binary"
            out["reason"] = "binary_available" if out["binary"] else "package_available"
        else:
            out["recommend"] = "none"
            out["reason"] = "no_docker_no_binary"
        return out

    def package_binary(self) -> str:
        """管理机统一安装包路径（可选配置）。"""
        for p in (
            getattr(self, "package_dir", "") or "",
            "/data/ayana/packages/node_exporter/node_exporter",
            "/opt/ayana/packages/node_exporter/node_exporter",
        ):
            if p and Path(p).is_file():
                return p
        return ""

    async def install_exporter(
        self,
        *,
        asset_id: str,
        method: str,
        transport: Any,
        actor: str = "web",
        listen_address: str = "0.0.0.0:9100",
        allow_non_private: bool = True,
    ) -> dict[str, Any]:
        """按推荐方式安装：docker | binary | auto。"""
        det = await self.detect_exporter(asset_id, transport)
        if det.get("running") or (det.get("port_9100") and det.get("binary")):
            return {
                "ok": True,
                "skipped": "already_running",
                "detect": det,
                "status": det.get("status") or {},
            }
        if method in ("", "auto"):
            method = det.get("recommend") or "binary"
        if method == "none":
            raise PromConfigError("no_install_method", det.get("reason") or "")
        existing = det.get("status") or {}
        can_start_existing = str(existing.get("mode") or "").startswith("docker:")
        if existing.get("installed") and not existing.get("active") and can_start_existing:
            await self.node_exporter_control(
                asset_id=asset_id, action="start", transport=transport, actor=actor
            )
            return {"ok": True, "method": method, "skipped": "already_installed_start_only", "status": await self.node_exporter_status(asset_id, transport), "detect": det}
        steps: list[dict[str, Any]] = []
        self._audit(
            "web_user",
            actor,
            "node_exporter_install",
            {"asset_id": asset_id, "method": method, "listen": listen_address},
        )
        if method == "docker":
            listen = assert_safe_listen_address(listen_address, allow_non_private=allow_non_private)
            res = await transport.exec(
                asset_id,
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    "node-exporter",
                    "--restart",
                    "unless-stopped",
                    "--net",
                    "host",
                    "prom/node-exporter:latest",
                    "--web.listen-address=" + listen,
                ],
                timeout=90,
            )
            steps.append({"step": "docker_run", "ok": bool(getattr(res, "ok", False)), "output": (getattr(res, "output", "") or "")[:300]})
            if not steps[-1]["ok"]:
                raise PromConfigError("install_failed", steps[-1]["output"])
        elif method == "binary":
            bin_path = det.get("binary") or ""
            if not bin_path:
                for p in (
                    "/usr/local/bin/node_exporter",
                    "/usr/bin/node_exporter",
                    "/bin/node_exporter",
                ):
                    try:
                        rk = await transport.probe(asset_id, ["test", "-x", p], timeout=10)
                        if getattr(rk, "ok", False):
                            version = await transport.probe(asset_id, [p, "--version"], timeout=10)
                            if getattr(version, "ok", False):
                                bin_path = p
                                break
                    except Exception:
                        continue
            if not bin_path:
                local = self.package_binary()
                if not local:
                    raise PromConfigError("package_missing", "node_exporter binary not in package store")
                send = _resolve_send_file(transport)
                if not send:
                    raise PromConfigError(
                        "send_file_unsupported",
                        f"transport cannot push binary ({type(transport).__name__})",
                    )
                remote = "/usr/local/bin/node_exporter"
                # 先推到 /tmp 再 mv，避开 SELinux/直接写系统路径问题
                r = await send(asset_id, local, "/tmp/node_exporter", timeout=180)
                steps.append({"step": "push_binary", "ok": bool(getattr(r, "ok", False)), "output": (getattr(r, "output", "") or "")[:300]})
                if not steps[-1]["ok"]:
                    raise PromConfigError("push_binary_failed", steps[-1]["output"])
                expected_hash = hashlib.sha256(Path(local).read_bytes()).hexdigest()
                checksum = await transport.probe(asset_id, ["sha256sum", "/tmp/node_exporter"], timeout=20)
                actual_hash = (getattr(checksum, "output", "") or "").split()
                if not getattr(checksum, "ok", False) or not actual_hash or actual_hash[0] != expected_hash:
                    raise PromConfigError("binary_checksum_failed", "uploaded node_exporter does not match package")
                for cmd in (
                    ["chmod", "755", "/tmp/node_exporter"],
                    ["mv", "/tmp/node_exporter", remote],
                    ["chmod", "755", remote],
                    ["chcon", "-t", "bin_t", remote],
                ):
                    rr = await transport.exec(asset_id, cmd, timeout=20)
                    steps.append({"step": cmd[0], "ok": bool(getattr(rr, "ok", False)), "output": (getattr(rr, "output", "") or "")[:120]})
                    if cmd[0] != "chcon" and not steps[-1]["ok"]:
                        raise PromConfigError("install_failed", steps[-1]["output"])
                    if cmd == ["chmod", "755", "/tmp/node_exporter"]:
                        version = await transport.probe(asset_id, ["/tmp/node_exporter", "--version"], timeout=10)
                        if not getattr(version, "ok", False):
                            raise PromConfigError("binary_invalid", "node_exporter package cannot run on target host")
                bin_path = remote
            listen = assert_safe_listen_address(listen_address, allow_non_private=allow_non_private)
            await self._ensure_node_exporter_user(asset_id, transport)
            unit = _node_exporter_unit(listen, bin_path)
            res = await transport.exec(asset_id, _node_exporter_write_tokens(unit), timeout=25)
            steps.append({"step": "write_unit", "ok": bool(getattr(res, "ok", False)), "output": (getattr(res, "output", "") or "")[:200]})
            if not steps[-1]["ok"]:
                raise PromConfigError("install_failed", steps[-1]["output"])
            for cmd in (
                ["systemctl", "daemon-reload"],
                ["systemctl", "enable", "node_exporter"],
                ["systemctl", "reset-failed", "node_exporter"],
                ["systemctl", "restart" if existing.get("active") else "start", "node_exporter"],
            ):
                r = await transport.exec(asset_id, cmd, timeout=20)
                steps.append({"step": cmd[1], "ok": bool(getattr(r, "ok", False)), "output": (getattr(r, "output", "") or "")[:150]})
                if not steps[-1]["ok"]:
                    raise PromConfigError("install_failed", steps[-1]["output"])
        else:
            raise PromConfigError("bad_method", method)
        st = await self.node_exporter_status(asset_id, transport)
        return {"ok": True, "method": method, "steps": steps, "status": st, "detect": det}

    async def adopt_node(
        self,
        *,
        asset_id: str,
        address: str = "",
        transport: Any,
        actor: str = "web",
        listen_address: str = "127.0.0.1:9100",
        allow_non_private: bool = False,
    ) -> dict[str, Any]:
        """一键接入监控：检查 → 必要时安装/启动 → 注册目标。"""
        steps: list[dict[str, Any]] = []
        det = await self.detect_exporter(asset_id, transport)
        st = det.get("status") or {}
        steps.append({"step": "check", "ok": True, "detail": st})
        if not (det.get("running") or (det.get("port_9100") and det.get("binary"))):
            inst = await self.install_exporter(
                asset_id=asset_id,
                method="auto",
                transport=transport,
                actor=actor,
                listen_address=listen_address,
                allow_non_private=allow_non_private,
            )
            steps.append({"step": "install", "ok": bool(inst.get("ok")), "detail": inst})
            st = await self.node_exporter_status(asset_id, transport)
            steps.append({"step": "recheck", "ok": True, "detail": st})
        if not address:
            raise PromConfigError("address_required", asset_id)
        try:
            reg = await self.register_node_target(
                asset_id=asset_id, address=address, labels={"asset": asset_id, "name": f"{asset_id}-node"}, actor=actor
            )
            steps.append({"step": "register", "ok": True, "detail": reg})
        except PromConfigError as e:
            if e.code == "target_exists":
                steps.append({"step": "register", "ok": True, "detail": {"skipped": "already_registered"}})
            else:
                raise
        scrape = await self._verify_scrape(address, asset_id=asset_id, wait_sec=30.0)
        # 无指标 → 不得报成功
        if not scrape.get("has_metrics"):
            return {
                "ok": False,
                "error": "no_metrics",
                "asset_id": asset_id,
                "address": address,
                "status": st,
                "steps": steps,
                "scrape": scrape,
                "hint": scrape.get("hint") or "已写入监控配置，但未采到指标，不能算成功。",
            }
        return {
            "ok": True,
            "asset_id": asset_id,
            "address": address,
            "status": st,
            "steps": steps,
            "scrape": scrape,
            "hint": "已注册且指标正常。",
        }

    async def _verify_scrape(
        self, address: str, *, asset_id: str = "", wait_sec: float = 30.0
    ) -> dict[str, Any]:
        """Wait for the first real scrape, which may start after target registration."""
        deadline = time.monotonic() + min(60.0, max(0.0, wait_sec))
        while True:
            result = await self._scrape_snapshot(address, asset_id=asset_id)
            if result.get("has_metrics") or not self.prom:
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return result
            await asyncio.sleep(min(2.0, remaining))

    async def _scrape_snapshot(
        self, address: str, *, asset_id: str = ""
    ) -> dict[str, Any]:
        """关联验证：配置目标 → 实时抓取 → 是否真的有指标。"""
        out: dict[str, Any] = {
            "address": address,
            "found_target": False,
            "health": "unknown",
            "error": "",
            "has_metrics": False,
            "samples": 0,
            "hint": "",
        }
        if not self.prom:
            out["hint"] = "未接 Prometheus API，无法验证抓取"
            return out
        target = None
        try:
            for t in await self.prom.targets():
                url = t.get("scrapeUrl") or ""
                labels = t.get("labels") or {}
                inst = labels.get("instance") or ""
                if address and (address in url or inst == address):
                    target = t
                    break
        except Exception as e:
            out["error"] = str(e)[:160]
            out["hint"] = "无法查询 Prometheus targets"
            return out
        if not target:
            out["hint"] = "目标未出现在 Prometheus 抓取列表，请检查配置是否已热重载"
            return out
        out["found_target"] = True
        out["health"] = target.get("health") or "unknown"
        out["error"] = (target.get("lastError") or "")[:240]
        # 是否有指标：up 或 node_uname_info
        try:
            inst = (target.get("labels") or {}).get("instance") or address
            q = f'up{{instance="{inst}"}}'
            data = await self.prom.query(q)
            samples = data.get("result") or []
            out["samples"] = len(samples)
            val = None
            if samples:
                val = samples[0].get("value")
            if val == 1 or (isinstance(val, (int, float)) and val == 1):
                out["has_metrics"] = True
            elif samples and val == 0:
                out["has_metrics"] = False
        except Exception as e:
            out["error"] = (out["error"] + " " + str(e)[:100]).strip()
        if out["has_metrics"]:
            out["hint"] = ""
        elif out["health"] == "up":
            out["hint"] = "抓取显示 up 但未查到 up 指标，请稍后再试"
        else:
            err = (out["error"] or "").lower()
            if "timeout" in err or "deadline" in err or "refused" in err or "no route" in err:
                out["hint"] = (
                    "网络不通或被拦截：请检查防火墙/云安全组是否放行 "
                    "Prometheus → 该主机:9100，以及 node_exporter 是否监听 0.0.0.0/内网 IP"
                )
            elif "context" in err and "canceled" in err:
                out["hint"] = "抓取超时：检查主机负载或安全设备拦截"
            else:
                out["hint"] = "抓取失败：确认 node_exporter 已启动且 9100 可达"
        return out


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _summarize_job(j: dict[str, Any]) -> dict[str, Any]:
    name = j.get("job_name") or ""
    interval = j.get("scrape_interval") or j.get("scrape_timeout") or ""
    static = j.get("static_configs")
    file_sd = j.get("file_sd_configs")
    targets: list[dict[str, Any]] = []
    via = "other"
    if isinstance(static, list):
        via = "static_configs"
        for sc in static:
            if not isinstance(sc, dict):
                continue
            labels = sc.get("labels") or {}
            for t in sc.get("targets") or []:
                targets.append({"address": t, "labels": labels, "via": "static_configs"})
    if isinstance(file_sd, list):
        via = "file_sd_configs" if via == "other" else via + "+file_sd"
        for fs in file_sd:
            if not isinstance(fs, dict):
                continue
            files = fs.get("files") or []
            for f in files:
                targets.append({"address": f"(file_sd:{f})", "labels": {}, "via": "file_sd_configs"})
    return {
        "job_name": name,
        "scrape_interval": interval,
        "via": via,
        "targets": targets,
        "keys": sorted(j.keys()),
        "raw_job": j,
    }


def _parse_rules_file(raw: str) -> tuple[list[dict[str, Any]], str]:
    """解析规则文件为结构化；无法安全解析时返回 (partial, reason)。"""
    try:
        data = parse_simple_yaml(raw)
    except PromConfigError as e:
        return [], e.detail or e.code
    except Exception as e:
        return [], str(e)[:120]
    if not isinstance(data, dict) or "groups" not in data:
        return [], "missing_groups"
    groups = data.get("groups")
    if not isinstance(groups, list):
        return [], "bad_groups"
    out: list[dict[str, Any]] = []
    for g in groups:
        if not isinstance(g, dict):
            return [], "bad_group_item"
        rules = g.get("rules")
        if not isinstance(rules, list):
            return [], "bad_rules"
        parsed_rules = []
        for r in rules:
            if not isinstance(r, dict):
                return [], "bad_rule_item"
            if "alert" not in r and "record" not in r:
                return [], "rule_missing_name"
            # 复杂规则（record 或未知键过多）仍展示，但标记
            known = {"alert", "record", "expr", "for", "labels", "annotations", "managed_by", "template_id"}
            unknown = [k for k in r.keys() if k not in known]
            simple = "record" not in r and not unknown
            parsed_rules.append(
                {
                    "alert": r.get("alert") or "",
                    "record": r.get("record") or "",
                    "expr": r.get("expr") or "",
                    "for": r.get("for") or "",
                    "labels": r.get("labels") or {},
                    "annotations": r.get("annotations") or {},
                    "unknown_keys": unknown,
                    "simple_editable": simple,
                }
            )
        out.append({"name": g.get("name") or "", "rules": parsed_rules})
    return out, ""


def _templates_public() -> list[dict[str, Any]]:
    return [
        {
            "id": t.id,
            "name": t.name,
            "metric": t.metric,
            "default_expr": t.default_expr,
            "default_for": t.default_for,
            "default_severity": t.default_severity,
            "description": t.description,
            "alert": _template_alert_name(t),
        }
        for t in ALERT_TEMPLATES
    ]


def _validate_target_address(address: str) -> str:
    address = (address or "").strip()
    if not address or len(address) > 200:
        raise PromConfigError("bad_target_address", address)
    # host:port，允许 IPv6 简单形式
    if any(ch in address for ch in " ;|&$`\n\t{}"):
        raise PromConfigError("bad_target_address", address)
    if ":" not in address:
        raise PromConfigError("bad_target_address", address)
    host, _, port_s = address.rpartition(":")
    try:
        port = int(port_s)
    except ValueError as e:
        raise PromConfigError("bad_target_port", port_s) from e
    if not (1 <= port <= 65535):
        raise PromConfigError("bad_target_port", port_s)
    return address


def _clean_labels(labels: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (labels or {}).items():
        k = str(k).strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,60}", k):
            raise PromConfigError("bad_label_key", k)
        vs = str(v).strip()
        if len(vs) > 200 or any(c in vs for c in "\n\t"):
            raise PromConfigError("bad_label_value", vs[:40])
        out[k] = vs
    return out


def _node_exporter_unit(listen_address: str, bin_path: str = "/usr/local/bin/node_exporter") -> str:
    """固定 systemd unit；默认不暴露公网。"""
    bin_path = bin_path if bin_path.startswith("/") else "/usr/local/bin/node_exporter"
    return f"""[Unit]
Description=Node Exporter (managed by Ayana)
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart={bin_path} --web.listen-address={listen_address}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


def _node_exporter_write_tokens(unit: str) -> list[str]:
    # Only this fixed service path can be written by the exporter installer.
    encoded = base64.b64encode(unit.encode("utf-8")).decode("ascii")
    script = (
        "import base64,os\n"
        "p='/etc/systemd/system/node_exporter.service'\n"
        "t=p+'.tmp'\n"
        f"with open(t,'wb') as f: f.write(base64.b64decode({encoded!r}))\n"
        "os.replace(t,p)"
    )
    return ["python3", "-c", _python_exec_token(script)]


class LocalExecTransport:
    """本机执行（Ayana 与目标同机时）。命令 tokens 仍由调用方固定。"""

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self.calls: list[tuple[str, list[str]]] = []

    async def _run(self, asset_id: str, tokens: list[str], timeout: float | None = None):
        from .ntsafe import NTResult

        self.calls.append((asset_id, list(tokens)))
        if not tokens or not all(isinstance(t, str) and t and not any(c in t for c in "\n;|&$`") for t in tokens):
            return NTResult(ok=False, output="unsafe_tokens", returncode=-1)
        t = max(3.0, float(timeout or self.timeout))
        try:
            proc = await asyncio.create_subprocess_exec(
                *tokens,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=t)
        except FileNotFoundError:
            return NTResult(ok=False, output="command_not_found", returncode=127)
        except Exception as e:
            return NTResult(ok=False, output=str(e)[:200], returncode=-1)
        text = ((out_b or b"") if proc.returncode == 0 else ((err_b or b"") or (out_b or b""))).decode(
            "utf-8", "replace"
        )
        return NTResult(ok=proc.returncode == 0, output=text, returncode=proc.returncode)

    async def send_file(self, asset_id: str, local_path: str, remote_path: str, *, timeout: float = 60.0):
        """本机复制（目标即 Ayana 主机）。"""
        from .ntsafe import NTResult

        try:
            if not remote_path.startswith("/") or any(c in remote_path for c in " \t\n;|&$`"):
                return NTResult(ok=False, output="bad_remote_path", returncode=2)
            src = Path(local_path)
            if not src.is_file():
                return NTResult(ok=False, output="local_file_missing", returncode=2)
            Path(remote_path).parent.mkdir(parents=True, exist_ok=True)
            data = src.read_bytes()
            tmp = remote_path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, remote_path)
            os.chmod(remote_path, 0o755)
            return NTResult(ok=True, output="copied", returncode=0)
        except Exception as e:
            return NTResult(ok=False, output=str(e)[:200], returncode=-1)

    async def probe(self, asset_id: str, tokens: list[str], timeout: float | None = None):
        return await self._run(asset_id, tokens, timeout=timeout)

    async def exec(self, asset_id: str, tokens: list[str], timeout: float | None = None):
        return await self._run(asset_id, tokens, timeout=timeout)


def build_prom_config_service(
    db: Database,
    cfg: dict[str, Any],
    *,
    prom: Any | None = None,
    transport: Any | None = None,
) -> PromConfigService:
    """按配置构建服务：优先 SSH 资产，否则本地目录。"""
    pc = cfg.get("prometheus_config") or {}
    if not isinstance(pc, dict):
        pc = {}
    ssh_asset = str(pc.get("ssh_asset_id") or cfg.get("prometheus_config_ssh_asset") or "")
    remote_base = str(pc.get("remote_base") or cfg.get("prometheus_config_ssh_path") or "/etc/prometheus")
    local_dir = str(pc.get("local_dir") or cfg.get("prometheus_config_dir") or "prometheus")
    if ssh_asset and transport is not None:
        fs: ConfigFS = SSHConfigFS(ssh_asset, transport, remote_base)
    else:
        base = Path(cfg.get("base_dir") or ".")
        path = Path(local_dir)
        if not path.is_absolute():
            path = base / local_dir
        fs = LocalConfigFS(path)
    svc = PromConfigService(
        db,
        fs,
        prom=prom,
        transport=transport,
        promtool_bin=str(pc.get("promtool") or cfg.get("promtool_bin") or "promtool"),
        reload_url=str(pc.get("reload_url") or ""),
        config_path_prefix=str(pc.get("config_path_prefix") or "/etc/prometheus/"),
        local_assets=list(pc.get("local_assets") or []),
        require_promtool=bool(pc.get("require_promtool", True)),
    )
    svc.package_dir = str(pc.get("package_dir") or "/data/ayana/packages/node_exporter")
    return svc
