"""One verified provider/MCP configuration shared by Web and native runtime."""
from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Any


def runtime_paths(cfg: dict[str, Any]) -> dict[str, str]:
    home = str(cfg.get("agent_runtime_home") or ("/var/lib/ayana" if os.name == "posix" else Path.home()))
    workdir = str(cfg.get("mimo_workdir") or Path(home) / "agent-workspace")
    state = str(cfg.get("agent_runtime_state_dir") or Path(home) / "agent-runtime")
    return {"home": home, "workdir": workdir, "state_dir": state, "attestation": str(Path(state) / "attestation.json")}


def verified_runtime(cfg: dict[str, Any], db: Any, admin: Any) -> dict[str, Any]:
    runtime = admin.runtime_configuration(db)
    root = str(Path(__file__).resolve().parents[1])
    base = str(Path(cfg.get("base_dir") or root).resolve())
    paths = runtime_paths(cfg)
    # Web and the independent runtime must attest the same configuration even
    # when systemd starts them with different inherited Python search paths.
    environment = {"AYANA_MCP_DB_PATH": str(Path(db.path).resolve()), "PYTHONPATH": root}
    overlay = dict(runtime.get("config") or {})
    overlay["mcp"] = {
        **(overlay.get("mcp") or {}),
        "ayana": {"type": "local", "enabled": True,
                  "command": [sys.executable, "-m", "ayana.mcp_server", base],
                  "environment": {**environment, "AYANA_MCP_READONLY": "1"}},
    }
    port = int(cfg.get("mimo_serve_port") or 6290)
    password = str(cfg.get("mimo_serve_password") or cfg.get("webhook_token") or "")
    if not password:
        raise ValueError("runtime_auth_required")
    return {**runtime, "cwd": paths["workdir"], "runtime_attestation_path": paths["attestation"], "config": overlay,
            "environment": environment, "serve_url": f"http://127.0.0.1:{port}",
            "serve_username": "mimocode", "serve_password": password}
