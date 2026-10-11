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
        """调用 chat/completions。返回 {content, raw, status}；失败打日志后 None。"""
        if not self.enabled:
            return None
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
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as s:
                async with s.post(
                    url,
                    json=body,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                ) as r:
                    text = await r.text()
                    if r.status != 200:
                        log.warning("llm http %s: %s", r.status, text[:300])
                        return None
                    try:
                        data = json.loads(text)
                    except Exception as e:
                        log.warning("llm bad response json: %s body=%s", e, text[:300])
                        return None
                    content = (
                        data.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content")
                    )
                    return {"content": content, "raw": data, "status": r.status}
        except Exception as e:
            log.warning("llm error: %s", e)
            return None

    async def analyze_incident(
        self,
        *,
        title: str,
        evidence_text: str,
        alertname: str = "",
        knowledge_text: str = "",
    ) -> dict[str, Any] | None:
        """分析事件，返回摘要/分类/建议。仅分析，不执行。"""
        knol_block = f"\n运维知识（长期语义，非实时状态）:\n{knowledge_text[:2500]}\n" if knowledge_text else ""
        user = (
            f"事件: {title}\n"
            f"告警类型: {alertname}\n"
            f"{knol_block}"
            f"证据:\n{evidence_text[:3000]}\n\n"
            "请结合知识中的依赖关系判断：若多个探测同时失败，优先考虑共同依赖。\n"
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

    async def propose_next_tools(
        self,
        *,
        asset_id: str,
        object_id: str,
        evidence_brief: list[dict],
        hypotheses: list[dict],
        missing: list[str],
        knowledge_text: str = "",
        extra_failures: list[str] | None = None,
        allowed_capabilities: list[str] | None = None,
    ) -> str | None:
        """只提出下一步想获取什么证据；不执行、不扩权。

        返回原始文本（由 Investigation 解析并验证）；失败返回 None。
        """
        if not self.enabled:
            return None
        caps = ", ".join(allowed_capabilities or [])
        user = (
            f"资产: {asset_id}\n对象: {object_id}\n"
            f"相关异常对象: {', '.join(extra_failures or []) or '-'}\n"
            f"运维知识（非实时、不授执行权）:\n{(knowledge_text or '')[:1200]}\n"
            f"已有证据摘要:\n{json.dumps(evidence_brief, ensure_ascii=False)[:2500]}\n"
            f"当前假设: {json.dumps(hypotheses, ensure_ascii=False)[:800]}\n"
            f"缺失证据: {json.dumps(missing, ensure_ascii=False)[:500]}\n"
            f"允许的只读 capability: {caps}\n\n"
            "请用 JSON 回答（不要写 shell）:\n"
            '{"facts": ["..."],'
            ' "hypotheses": [{"text": "...", "confidence": "high|medium|low",'
            ' "supporting": ["ev_id"], "contradicting": ["ev_id"]}],'
            ' "missing_evidence": ["..."],'
            ' "next_tools": [{"capability": "service.status", "object_id": "frps", "why": "..."}],'
            ' "stop": false, "stop_reason": ""}\n'
            "stop_reason 取值之一: enough_evidence/need_more_evidence/need_human/"
            "transport_unavailable/deadline_reached/tool_budget_exhausted/no_progress。"
            "下一步工具最多 2 个，且必须来自允许列表和已登记对象。"
        )
        return await self.chat(
            [
                {"role": "system", "content": DEFAULT_SYSTEM},
                {"role": "user", "content": user},
            ],
            max_tokens=500,
        )


def make_llm(cfg: dict) -> LLMClient:
    return LLMClient(
        api_key=cfg.get("llm_api_key", ""),
        base_url=cfg.get("llm_base_url", ""),
        model=cfg.get("llm_model", "mimo-v2.6-flash"),
    )
