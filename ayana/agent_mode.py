"""Explicit choice of the task engine; existing installations keep MiMo."""
from __future__ import annotations

from typing import Any


def agent_mode(config: dict[str, Any]) -> str:
    mode = config.get("agent_mode", "mimo")
    if mode not in ("mimo", "lite"):
        raise ValueError("agent_mode must be mimo or lite")
    return mode
