"""Read-only runtime inventory and versioned settings for the Web settings center.

Secrets and execution permissions are deliberately outside this module. Prompt
versions share the existing config_versions table; no schema migration is needed.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from .db import now

PROJECT_URL = "https://github.com/wwqjss/Ayana"
RELEASE_URL = "https://api.github.com/repos/wwqjss/Ayana/releases/latest"
PROMPT_KINDS = {"investigation": "mimo_investigation_prompt", "decision": "mimo_decision_prompt", "constraints": "ops_constraints"}
PROMPT_LABELS = {"investigation": "调查提示词", "decision": "处置提示词", "constraints": "运维软约束"}


def prompt_default(key: str) -> str:
    if key == "constraints":
        from .ops_constraints import DEFAULT_CONSTRAINTS
        return DEFAULT_CONSTRAINTS
    from .auto_investigate import CONCLUSION_PROMPT, DECISION_PROMPT
    if key == "investigation": return CONCLUSION_PROMPT
    if key == "decision": return DECISION_PROMPT
    raise ValueError("invalid_prompt_key")


class PromptSettings:
    def __init__(self, db: Any):
        self.db = db

    @staticmethod
    def kind(key: str) -> str:
        if not isinstance(key, str) or key not in PROMPT_KINDS:
            raise ValueError("invalid_prompt_key")
        return PROMPT_KINDS[key]

    def _rows(self, key: str, limit: int | None = None) -> list[dict]:
        sql = "SELECT id,payload_json,created_at,created_by FROM config_versions WHERE kind=? ORDER BY id DESC"
        params: tuple = (self.kind(key),)
        if limit is not None:
            sql += " LIMIT ?"; params += (limit,)
        output = []
        for row in self.db.query(sql, params):
            try: payload = json.loads(row["payload_json"] or "{}")
            except (ValueError, TypeError): continue
            if not isinstance(payload, dict) or not isinstance(payload.get("text"), str) or not payload["text"].strip(): continue
            output.append({"id": row["id"], "version": row["id"], "text": payload["text"],
                           "active": payload.get("active") is True, "created_at": row["created_at"],
                           "created_by": row["created_by"] or "", "change_note": str(payload.get("change_note") or "")[:300],
                           "is_default": payload.get("is_default") is True})
        return output

    def current(self, key: str) -> dict:
        self.kind(key)
        active = next((row for row in self._rows(key) if row["active"]), None)
        return active or {"id": 0, "version": 0, "text": prompt_default(key), "active": True,
                          "created_at": 0, "created_by": "system", "change_note": "默认版本", "is_default": True}

    def overview(self) -> dict:
        return {"ok": True, "effect": "next_call", "message": "保存后用于下一次调查或决策调用，已经发出的请求继续使用原内容。执行权限和硬保护由程序控制。",
                "items": [{"key": key, "label": PROMPT_LABELS[key], "current": self.current(key),
                           "versions": self._rows(key, 20)} for key in PROMPT_KINDS]}

    def save(self, key: str, text: str, *, actor: str, change_note: str = "", is_default: bool = False) -> dict:
        kind = self.kind(key)
        if not isinstance(text, str) or not text.strip(): raise ValueError("empty_prompt")
        if len(text) > 20000: raise ValueError("prompt_too_long")
        if "\x00" in text: raise ValueError("invalid_prompt")
        if not isinstance(change_note, str) or len(change_note) > 300: raise ValueError("invalid_change_note")
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("SELECT id,payload_json FROM config_versions WHERE kind=?", (kind,)).fetchall()
            for row in rows:
                try: payload = json.loads(row["payload_json"] or "{}")
                except (ValueError, TypeError): continue
                if isinstance(payload, dict) and payload.get("active"):
                    payload["active"] = False
                    conn.execute("UPDATE config_versions SET payload_json=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), row["id"]))
            payload = {"text": text, "active": True, "version": 0, "change_note": change_note, "is_default": is_default}
            cursor = conn.execute("INSERT INTO config_versions(kind,payload_json,created_at,created_by) VALUES(?,?,?,?)",
                                  (kind, json.dumps(payload, ensure_ascii=False), now(), actor))
            payload["version"] = int(cursor.lastrowid)
            conn.execute("UPDATE config_versions SET payload_json=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), cursor.lastrowid))
            self.db.audit("web_user", actor, "settings_prompt_saved", detail={"key": key, "version_id": cursor.lastrowid, "restored_default": is_default}, channel="web")
        return self.current(key)

    def restore(self, key: str, version_id: int, *, actor: str) -> dict:
        self.kind(key)
        if type(version_id) is not int or version_id < 0: raise ValueError("invalid_version_id")
        if version_id == 0:
            return self.save(key, prompt_default(key), actor=actor, change_note="恢复默认版本", is_default=True)
        row = next((row for row in self._rows(key) if row["id"] == version_id), None)
        if row is None: raise ValueError("version_not_found")
        return self.save(key, row["text"], actor=actor, change_note=f"恢复 v{version_id}", is_default=row["is_default"])


def discover_skills(*, home: Path | None = None, workdir: Path | None = None) -> dict:
    """Inventory only: discovering a SKILL.md is not evidence of model loading it."""
    home = Path(home or Path.home()).resolve()
    workdir = Path(workdir or Path(__file__).resolve().parents[1]).resolve()
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") if home == Path.home().resolve() else home / ".config"
    candidates = [
        ("MiMoCode 全局", xdg / "mimocode" / "skills"),
        ("MiMoCode 兼容全局", home / ".mimocode" / "skills"),
        ("Agents 全局", home / ".agents" / "skills"),
        ("Claude 全局", home / ".claude" / "skills"),
        ("Codex 全局", home / ".codex" / "skills"),
        ("MiMoCode 项目", workdir / ".mimocode" / "skills"),
        ("Agents 项目", workdir / ".agents" / "skills"),
        ("Claude 项目", workdir / ".claude" / "skills"),
        ("Codex 项目", workdir / ".codex" / "skills"),
    ]
    roots = []; items = []; seen = set(); scanned = 0; truncated = False
    for source, candidate in candidates:
        exists = candidate.is_dir() and not candidate.is_symlink() and (candidate.resolve().is_relative_to(home) or candidate.resolve().is_relative_to(workdir))
        roots.append({"source": source, "path": str(candidate), "exists": exists})
        if not exists: continue
        root = candidate.resolve()
        for directory, subdirs, files in os.walk(root, followlinks=False):
            scanned += 1
            if scanned > 1000 or len(items) >= 200: truncated = True; break
            current = Path(directory)
            depth = len(current.relative_to(root).parts)
            subdirs[:] = sorted(name for name in subdirs if not (current/name).is_symlink()) if depth < 3 else []
            if "SKILL.md" not in files: continue
            path = current / "SKILL.md"
            if path.is_symlink() or not path.resolve().is_relative_to(root) or path in seen: continue
            try:
                if path.stat().st_size > 65536: continue
                raw = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError): continue
            seen.add(path)
            front = raw.split("---", 2)[1] if raw.startswith("---") and len(raw.split("---", 2)) == 3 else ""
            def field(name: str) -> str:
                match = re.search(r"(?m)^"+name+r":\s*(.*?)\s*$", front)
                value = match.group(1).strip().strip("\"'") if match else ""
                return value if value not in ("|", ">") else ""
            name = field("name")[:120] or current.name
            description = field("description")[:400] or "未提供单行说明，可在服务端技能文件中查看详情。"
            items.append({"id": hashlib.sha256(str(path).encode()).hexdigest()[:20], "name": name, "description": description,
                          "source": source, "path": str(path), "status": "discovered", "loaded": None})
        if truncated: break
    return {"ok": True, "items": sorted(items, key=lambda item: (item["source"], item["name"])), "roots": roots,
            "truncated": truncated, "message": "以下为服务账号目录中实际发现的技能。目录发现不代表当前会话已经加载；加载状态尚未由运行时核验。兼容目录能否加载取决于当前 MiMoCode 配置。"}


def _version(value: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value or "")
    return tuple(map(int, match.groups())) if match else None


async def check_update(current_version: str) -> dict:
    """Query a fixed public GitHub endpoint; never install or execute an update."""
    import aiohttp
    from .llm import PublicAPIResolver
    fixed = {"current_version": current_version, "project_url": PROJECT_URL}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12), connector=aiohttp.TCPConnector(resolver=PublicAPIResolver())) as client:
            async with client.get(RELEASE_URL, headers={"Accept": "application/vnd.github+json", "User-Agent": "Ayana-update-check"}, allow_redirects=False) as response:
                if response.status == 404: return {"ok": True, "result": "no_release", "message": "项目尚未发布正式版本，可在项目地址查看最新进展。", **fixed}
                if response.status != 200: return {"ok": False, "error": "update_check_failed", "message": "暂时无法检查更新，请稍后重试或打开项目地址。", **fixed}
                try: raw = await response.content.readexactly(65537)
                except asyncio.IncompleteReadError as error: raw = error.partial
                if len(raw) > 65536: raise ValueError()
                data = json.loads(raw)
                if not isinstance(data, dict) or not isinstance(data.get("tag_name"), str): raise ValueError()
                latest = data["tag_name"][:80]
                a, b = _version(current_version), _version(latest)
                available = b > a if a is not None and b is not None else None
                result = "available" if available is True else "up_to_date" if available is False else "version_unknown"
                message = "发现新版本，可打开项目地址查看更新说明。" if available is True else "当前已是最新正式版本。" if available is False else "已查到正式版本，请在项目地址核对当前版本。"
                return {"ok": True, "result": result, "latest_version": latest, "update_available": available, "message": message, **fixed}
    except Exception:
        return {"ok": False, "error": "update_check_failed", "message": "暂时无法检查更新，请稍后重试或打开项目地址。", **fixed}
