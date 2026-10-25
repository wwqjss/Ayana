"""MiMoCode 管理面：状态、启停、日志、用量。不接触模型明文凭据。

MiMoCode 与 Ayana 独立运行；本模块只做进程/健康/只读观测与会话入口。
模型与 Provider 配置在 mimocode 自身配置；Ayana 只展示只读摘要。
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Any

log = __import__("logging").getLogger("ayana.mimo_admin")


class MimoAdmin:
    def __init__(
        self,
        *,
        mimo_bin: str = "mimo",
        workdir: str = "",
        serve_url: str = "",
        unit_name: str = "",
    ):
        self.mimo_bin = mimo_bin or "mimo"
        self.workdir = workdir or ""
        self.serve_url = serve_url or ""
        self.unit_name = unit_name or ""

    def _bin(self) -> str:
        return shutil.which(self.mimo_bin) or self.mimo_bin

    async def _run(self, args: list[str], timeout: float = 15.0) -> dict[str, Any]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.workdir or None,
            )
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": (out_b or b"").decode("utf-8", "replace")[:8000],
                "stderr": (err_b or b"").decode("utf-8", "replace")[:2000],
            }
        except FileNotFoundError:
            return {"ok": False, "error": "mimo_not_found", "stdout": "", "stderr": ""}
        except asyncio.TimeoutError:
            return {"ok": False, "error": "timeout", "stdout": "", "stderr": ""}

    async def status(self) -> dict[str, Any]:
        """健康与版本：mimo 是否存在、systemd（若配置）、serve URL。"""
        bin_path = self._bin()
        exists = bool(shutil.which(self.mimo_bin)) or Path(bin_path).exists()
        version = ""
        if exists:
            v = await self._run([bin_path, "--version"], timeout=8.0)
            version = (v.get("stdout") or v.get("stderr") or "").strip().splitlines()[:1]
            version = version[0] if version else ""
        unit = {"configured": bool(self.unit_name), "active": None, "detail": ""}
        if self.unit_name:
            u = await self._run(["systemctl", "is-active", self.unit_name], timeout=6.0)
            unit["active"] = (u.get("stdout") or "").strip() == "active"
            unit["detail"] = (u.get("stdout") or u.get("stderr") or "").strip()
        return {
            "ok": exists,
            "binary": bin_path,
            "exists": exists,
            "version": version,
            "workdir": self.workdir,
            "serve_url": self.serve_url,
            "unit": unit,
        }

    async def start(self) -> dict[str, Any]:
        if not self.unit_name:
            return {"ok": False, "error": "unit_not_configured"}
        return await self._run(["systemctl", "start", self.unit_name], timeout=20.0)

    async def stop(self) -> dict[str, Any]:
        if not self.unit_name:
            return {"ok": False, "error": "unit_not_configured"}
        return await self._run(["systemctl", "stop", self.unit_name], timeout=20.0)

    async def restart(self) -> dict[str, Any]:
        if not self.unit_name:
            return {"ok": False, "error": "unit_not_configured"}
        return await self._run(["systemctl", "restart", self.unit_name], timeout=30.0)

    async def logs(self, lines: int = 80) -> dict[str, Any]:
        lines = max(10, min(500, int(lines or 80)))
        if self.unit_name:
            return await self._run(
                ["journalctl", "-u", self.unit_name, "-n", str(lines), "--no-pager"],
                timeout=12.0,
            )
        return await self._run([self._bin(), "debug", "--help"], timeout=8.0)

    async def stats(self) -> dict[str, Any]:
        """用量统计：mimo stats（只读）。不含 API Key。"""
        return await self._run([self._bin(), "stats"], timeout=15.0)

    async def models(self) -> dict[str, Any]:
        return await self._run([self._bin(), "models"], timeout=15.0)

    def provider_summary(self, config_dir: str = "") -> dict[str, Any]:
        """只读展示 mimocode 配置中的 provider/model 名，不读密钥。"""
        base = Path(config_dir or (Path.home() / ".mimocode"))
        out: dict[str, Any] = {"ok": True, "config_dir": str(base), "providers": []}
        cfg = base / "config.json"
        if not cfg.exists():
            cfg = base / "config.jsonc"
        if not cfg.exists():
            out["ok"] = False
            out["error"] = "config_not_found"
            return out
        try:
            raw = cfg.read_text(encoding="utf-8")
            # 宽松提取非密钥字段
            data = json.loads(raw) if raw.lstrip().startswith("{") else {}
        except Exception:
            data = {}
        providers = data.get("providers") or data.get("provider") or {}
        if isinstance(providers, dict):
            for name, conf in providers.items():
                if not isinstance(conf, dict):
                    continue
                out["providers"].append(
                    {
                        "name": name,
                        "models": conf.get("models") or conf.get("model") or [],
                        "baseURL": conf.get("baseURL") or conf.get("base_url") or "",
                        # 绝不输出 apiKey / token
                    }
                )
        elif isinstance(providers, list):
            for conf in providers:
                if isinstance(conf, dict):
                    out["providers"].append(
                        {
                            "name": conf.get("name") or conf.get("id") or "",
                            "models": conf.get("models") or [],
                            "baseURL": conf.get("baseURL") or conf.get("base_url") or "",
                        }
                    )
        return out
