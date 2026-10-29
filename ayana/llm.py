"""LLM 适配器：可选分析，失败不影响主链路。"""

from __future__ import annotations

import json
import logging
import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from aiohttp.resolver import DefaultResolver

from .transport import is_blocked_ssrf_host

log = logging.getLogger("ayana.llm")

DEFAULT_SYSTEM = (
    "你是运维分析助手。只做事实分析和建议，不执行任何操作。"
    "输出简洁中文。"
)


class PublicAPIResolver(DefaultResolver):
    """Resolve once at connection time and reject private/metadata addresses."""
    async def resolve(self, host, port=0, family=socket.AF_INET):
        if is_blocked_ssrf_host(host, purpose="webhook"):
            raise OSError("blocked provider endpoint")
        addresses = await super().resolve(host, port, family)
        if not addresses or any(not ipaddress.ip_address(row["host"]).is_global for row in addresses):
            raise OSError("blocked provider endpoint")
        return addresses


class LLMClient:
    def __init__(self, api_key: str, base_url: str, model: str, timeout: float = 30.0, *, secure_network: bool = False):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.secure_network = secure_network

    def _connector(self):
        return aiohttp.TCPConnector(resolver=PublicAPIResolver()) if self.secure_network else None

    def _endpoint_allowed(self) -> bool:
        if not self.secure_network:
            return True
        parts = urlsplit(self.base_url)
        if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                or parts.query or parts.fragment or is_blocked_ssrf_host(parts.hostname, purpose="webhook")):
            return False
        try:
            return ipaddress.ip_address(parts.hostname).is_global
        except ValueError:
            return True

    async def list_models(self) -> dict[str, Any]:
        """Read-only account discovery; return model IDs or a sanitized failure."""
        if not self.enabled:
            return {"ok": False, "error": "llm_disabled", "models": []}
        if not self._endpoint_allowed():
            return {"ok": False, "error": "llm_blocked_endpoint", "models": []}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout), connector=self._connector()) as session:
                async with session.get(f"{self.base_url}/models", headers={"Authorization": f"Bearer {self.api_key}"}, allow_redirects=False) as response:
                    if response.status != 200:
                        return {"ok": False, "error": "llm_http_error", "status": response.status, "models": []}
                    data = await response.json()
                    models = data.get("data") if isinstance(data, dict) else None
                    if not isinstance(models, list) or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in models):
                        return {"ok": False, "error": "llm_response_format", "models": []}
                    return {"ok": True, "error": "", "models": [row["id"] for row in models]}
        except asyncio.TimeoutError:
            return {"ok": False, "error": "llm_timeout", "models": []}
        except Exception:
            return {"ok": False, "error": "llm_connection_error", "models": []}

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.base_url)

    async def chat(self, messages: list[dict], *, max_tokens: int = 512) -> str | None:
        """返回文本；失败返回 None。"""
        raw = await self.chat_raw(messages, max_tokens=max_tokens)
        return raw.get("content") if raw else None

    async def chat_raw(
        self,
        messages: list[dict],
        *,
        max_tokens: int = 512,
        json_mode: bool = False,
        temperature: float = 0.2,
    ) -> dict[str, Any] | None:
        """调用 chat/completions，保留失败分类和截断状态供填表链路判断。"""
        if not self.enabled:
            return {"content": None, "error": "llm_disabled", "status": 0}
        if not self._endpoint_allowed():
            return {"content": None, "error": "llm_blocked_endpoint", "status": 0}
        url = f"{self.base_url}/chat/completions"
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout), connector=self._connector()
            ) as s:
                async with s.post(
                    url,
                    json=body,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    allow_redirects=not self.secure_network,
                ) as r:
                    text = await r.text()
                    if r.status != 200:
                        log.warning("llm http %s", r.status)
                        return {"content": None, "error": "llm_http_error", "status": r.status}
                    try:
                        data = json.loads(text)
                    except Exception as e:
                        log.warning("llm bad response json: %s", type(e).__name__)
                        return {"content": None, "error": "llm_response_format", "status": r.status}
                    choices = data.get("choices") if isinstance(data, dict) else None
                    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                        return {"content": None, "error": "llm_response_format", "status": r.status}
                    choice = choices[0]
                    message = choice.get("message") or {}
                    content = message.get("content") if isinstance(message, dict) else None
                    return {"content": content, "raw": data, "status": r.status,
                            "finish_reason": choice.get("finish_reason")}
        except asyncio.TimeoutError:
            log.warning("llm request timed out")
            return {"content": None, "error": "llm_timeout", "status": 0}
        except Exception as e:
            log.warning("llm error: %s", type(e).__name__)
            return {"content": None, "error": "llm_connection_error", "status": 0}

def make_llm(cfg: dict) -> LLMClient:
    return LLMClient(
        api_key=cfg.get("llm_api_key", ""),
        base_url=cfg.get("llm_base_url", ""),
        model=cfg.get("llm_model", "mimo-v2.6-flash"),
    )
