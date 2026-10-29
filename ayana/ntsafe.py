"""NT 兼容层已退役。共享结果类型在 exec_facts；现役 SSH 走 transport。"""
from __future__ import annotations

from .exec_facts import NTError, NTResult

__all__ = ["NTError", "NTResult"]
