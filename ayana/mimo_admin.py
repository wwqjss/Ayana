"""MiMoCode 管理面：状态、启停、日志、用量。不接触模型明文凭据。

MiMoCode 与 Ayana 独立运行；本模块只做进程/健康/只读观测与会话入口。
模型与 Provider 配置在 mimocode 自身配置；Ayana 只展示只读摘要。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
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

    def config_path(self, config_dir: str = "") -> Path:
        """官方布局：~/.config/mimocode/mimocode.jsonc；兼容旧 ~/.mimocode。"""
        if config_dir:
            base = Path(config_dir)
            for name in ("mimocode.jsonc", "mimocode.json", "config.jsonc", "config.json"):
                p = base / name
                if p.exists():
                    return p
            return base / "mimocode.jsonc"
        xdg = Path.home() / ".config" / "mimocode"
        for name in ("mimocode.jsonc", "mimocode.json"):
            p = xdg / name
            if p.exists():
                return p
        legacy = Path.home() / ".mimocode"
        for name in ("mimocode.jsonc", "mimocode.json", "config.jsonc", "config.json"):
            p = legacy / name
            if p.exists():
                return p
        return xdg / "mimocode.jsonc"

    def provider_summary(self, config_dir: str = "") -> dict[str, Any]:
        """只读展示 mimocode 配置中的 provider/model 名，不读密钥。"""
        path = self.config_path(config_dir)
        out: dict[str, Any] = {"ok": True, "config_dir": str(path.parent), "providers": [], "path": str(path)}
        if not path.exists():
            out["ok"] = False
            out["error"] = "config_not_found"
            return out
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.lstrip().startswith("{") else {}
        except Exception:
            data = {}
        providers = data.get("providers") or data.get("provider") or {}
        if isinstance(providers, dict):
            for name, conf in providers.items():
                if not isinstance(conf, dict):
                    continue
                opts = conf.get("options") if isinstance(conf.get("options"), dict) else {}
                out["providers"].append(
                    {
                        "name": name,
                        "models": conf.get("models") or conf.get("model") or [],
                        "baseURL": opts.get("baseURL") or conf.get("baseURL") or "",
                        "key_set": bool(opts.get("apiKey")),
                    }
                )
        out["model"] = data.get("model") or ""
        return out

    def verification_state(self, db: Any = None) -> dict[str, Any]:
        """连接验证状态（不含密钥）。未验证不得宣称可用。"""
        row = None
        if db is not None:
            try:
                row = db.query_one("SELECT value FROM meta WHERE key='mimo_provider_state'")
            except Exception:
                row = None
        if row and row["value"]:
            try:
                st = json.loads(row["value"])
            except Exception:
                st = {}
        else:
            st = {}
        return {
            "verified": bool(st.get("verified")),
            "last_test_at": st.get("last_test_at") or 0,
            "last_result": st.get("last_result") or "",
            "last_message": (st.get("last_message") or "")[:200],
            "provider_id": st.get("provider_id") or "",
            "model": st.get("model") or "",
            "base_url": st.get("base_url") or "",
        }

    def save_verification_state(self, db: Any, state: dict[str, Any]) -> None:
        if db is None:
            return
        try:
            db.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('mimo_provider_state', ?)",
                (json.dumps(state, ensure_ascii=False),),
            )
        except Exception:
            pass

    @staticmethod
    def classify_api_response(status: int, body: str, timed_out: bool = False) -> dict[str, Any]:
        """区分：成功 / 认证失败 / 额度不足 / 超时 / 其它。"""
        text = body or ""
        low = text.lower()
        if timed_out:
            return {"ok": False, "result": "timeout", "message": "请求超时"}
        if status in (200, 201):
            return {"ok": True, "result": "success", "message": "连接成功"}
        if status in (401, 403):
            return {"ok": False, "result": "auth_failed", "message": "认证失败：API Key 无效或无权限"}
        if status == 429:
            if any(x in low for x in ("quota", "exhaust", "limitation", "insufficient", "余额", "额度")):
                return {"ok": False, "result": "quota_exhausted", "message": "额度不足或已用尽"}
            return {"ok": False, "result": "rate_limited", "message": "触发限流，请稍后再试"}
        if status >= 500:
            return {"ok": False, "result": "server_error", "message": f"服务端错误 HTTP {status}"}
        return {"ok": False, "result": "http_error", "message": f"HTTP {status}"}

    def test_connection(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """真实调用模型接口做连通性验证。不落盘密钥，不写日志明文。"""
        import urllib.error
        import urllib.request

        base = (base_url or "").strip().rstrip("/")
        key = (api_key or "").strip()
        model = (model or "").strip()
        if not base or not key or not model:
            return {"ok": False, "result": "bad_request", "message": "base_url / api_key / model 均必填"}
        if not base.startswith(("http://", "https://")):
            return {"ok": False, "result": "bad_request", "message": "base_url 必须是 http(s)"}
        url = base + "/chat/completions"
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
            "max_tokens": 8,
            "temperature": 0,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(4000).decode("utf-8", "replace")
                out = self.classify_api_response(int(resp.status), body)
                out["http_status"] = int(resp.status)
                return out
        except urllib.error.HTTPError as e:
            try:
                body = e.read(2000).decode("utf-8", "replace")
            except Exception:
                body = ""
            out = self.classify_api_response(int(e.code or 0), body)
            out["http_status"] = int(e.code or 0)
            return out
        except TimeoutError:
            return {"ok": False, "result": "timeout", "message": "请求超时"}
        except Exception as e:  # noqa: BLE001
            name = type(e).__name__
            if "timed out" in str(e).lower() or name in ("TimeoutError", "URLError"):
                return {"ok": False, "result": "timeout", "message": "请求超时或网络不可达"}
            return {"ok": False, "result": "connection_error", "message": f"{name}: {str(e)[:120]}"}

    def apply_provider(
        self,
        *,
        provider_id: str = "xiaomi",
        api_key: str = "",
        base_url: str = "",
        model: str = "",
        config_dir: str = "",
        verified: bool = False,
    ) -> dict[str, Any]:
        """把用户在 Ayana 填写的密钥/端点写入 mimocode。密钥不回显、不进审计明文。"""
        if not api_key:
            raise ValueError("api_key_required")
        if not provider_id or not re.fullmatch(r"[a-z][a-z0-9_-]{0,32}", provider_id):
            raise ValueError("bad_provider_id")
        path = self.config_path(config_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        data: dict[str, Any] = {}
        if path.exists():
            try:
                raw = path.read_text(encoding="utf-8")
                data = json.loads(raw) if raw.lstrip().startswith("{") else {}
            except Exception:
                data = {}
        if not isinstance(data, dict):
            data = {}
        providers = data.get("provider") or {}
        if not isinstance(providers, dict):
            providers = {}
        conf = dict(providers.get(provider_id) or {})
        conf.setdefault("name", provider_id)
        conf.setdefault("npm", "@ai-sdk/openai-compatible")
        conf["options"] = dict(conf.get("options") or {})
        conf["options"]["apiKey"] = api_key
        if base_url:
            conf["options"]["baseURL"] = base_url
        models = conf.get("models")
        if not isinstance(models, dict):
            models = {}
        if model:
            models[model] = {"name": model}
        conf["models"] = models
        providers[provider_id] = conf
        data["provider"] = providers
        if model:
            data["model"] = f"{provider_id}/{model}"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return {
            "ok": True,
            "path": str(path),
            "provider": provider_id,
            "model": model,
            "verified": bool(verified),
            "key_len": len(api_key),
        }

    def clear_provider(self, provider_id: str = "xiaomi", config_dir: str = "") -> dict[str, Any]:
        """移除已写入的 apiKey（配置未验证/更换密钥时）。"""
        path = self.config_path(config_dir)
        if not path.exists():
            return {"ok": True, "cleared": False}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        providers = data.get("provider") or {}
        conf = providers.get(provider_id) or {}
        opts = conf.get("options") or {}
        opts.pop("apiKey", None)
        conf["options"] = opts
        providers[provider_id] = conf
        data["provider"] = providers
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return {"ok": True, "cleared": True, "path": str(path)}
