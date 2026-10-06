"""LLM 适配器：可选分析，失败不影响主链路。"""

from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp

log = logging.getLogger("ayana.llm")

DEFAULT_SYSTEM = (
    "你是运维分析助手。只做事实分析和建议，不执行任何操作。"
    "输出简洁中文。"
)


class LLMClient:
    def __init__(self, api_key: str, base_url: str, model: str, timeout: float = 30.0):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.base_url)

    async def chat(self, messages: list[dict], *, max_tokens: int = 512) -> str | None:
        """返回文本；失败返回 None。"""
        if not self.enabled:
            return None
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as s:
                async with s.post(
                    url,
                    json=body,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                ) as r:
                    if r.status != 200:
                        text = await r.text()
                        log.warning("llm http %s: %s", r.status, text[:200])
                        return None
                    data = await r.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as e:
            log.warning("llm error: %s", e)
            return None

    async def analyze_incident(
        self, *, title: str, evidence_text: str, alertname: str = ""
    ) -> dict[str, Any] | None:
        """分析事件，返回摘要/分类/建议。仅分析，不执行。"""
        user = (
            f"事件: {title}\n"
            f"告警类型: {alertname}\n"
            f"证据:\n{evidence_text[:3000]}\n\n"
            "请用 JSON 回答:\n"
            '{"summary": "一句话结论", "category": "服务退出/网络/磁盘/内存/其他",'
            ' "confidence": "high/medium/low", "suggestion": "建议处置(仅建议)", "need_human": true/false}'
        )
        resp = await self.chat(
            [
                {"role": "system", "content": DEFAULT_SYSTEM},
                {"role": "user", "content": user},
            ],
            max_tokens=300,
        )
        if not resp:
            return None
        try:
            start = resp.find("{")
            end = resp.rfind("}")
            if start >= 0 and end > start:
                return json.loads(resp[start : end + 1])
        except Exception:
            pass
        return {"summary": resp[:200], "category": "其他", "confidence": "low", "need_human": True}


def make_llm(cfg: dict) -> LLMClient:
    return LLMClient(
        api_key=cfg.get("llm_api_key", ""),
        base_url=cfg.get("llm_base_url", ""),
        model=cfg.get("llm_model", "mimo-v2.6-flash"),
    )
