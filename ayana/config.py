"""配置与秘密加载。

配置 2 层优先级（P2-4）：
  1. 启动态：config.json + DEFAULTS ← secrets.json ← AYANA_* 环境变量（本模块 load_config）
     同键优先级：AYANA_* env > secrets.json > config.json > DEFAULTS
  2. 运行态：DB meta（Web 控制台可写的少量键，如 prometheus_url / alertmanager_url / llm_*）
     启动后覆盖启动态同名键；见 main.py 的 meta 回填。

config.json 不入库（.gitignore 已挡，含 self_id/admin_qq 等个人信息）。
参考 config.example.json 做模板；秘密进 secrets.json 或环境变量（不入库）。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

log_name = "ayana.config"

DEFAULTS: dict[str, Any] = {
    "ws_host": "127.0.0.1",
    "ws_port": 6199,
    "ws_path": "/ws",
    "http_host": "127.0.0.1",
    "http_port": 6200,
    "log_level": "INFO",
    "log_file": "ayana.log",
    "self_id": 0,
    # 企业微信长期授权仅接受显式列出的管理员；普通审批仍检查主体权限。
    "admin_wecom_users": [],
    "db_path": "ayana.db",
    "web_session_ttl_sec": 12 * 3600,
    "web_max_failed_logins": 8,
    "web_lockout_sec": 900,
    "alertmanager_webhook_path": "/hooks/alertmanager",
    "prometheus_url": "http://127.0.0.1:9090",
    "alertmanager_url": "http://127.0.0.1:9093",
    "verify_window_sec": 90,
    "verify_timeout_sec": 300,
    "action_ttl_sec": 1800,
    "auto_remediation_enabled": False,
    # P4.0 总闸：旧自治后台链（AgentLoop / AutonomyEngine）默认关闭。
    # 仅显式开启才启动；Web 不能绕过本开关重新启用。
    "legacy_agent_loop": False,
    # 新自治 Agent 使用独立按量 API 凭据；不复用旧 LLM / Token Plan Key。
    "autonomous_agent": {"enabled": False, "budget_cny": 100.0},
    # Prometheus 配置管理（可选）：ssh_asset_id 为空则用本地目录
    "prometheus_config": {
        "local_dir": "prometheus",
        "ssh_asset_id": "",
        "remote_base": "/etc/prometheus",
        "promtool": "promtool",
        "reload_url": "",
        "config_path_prefix": "/etc/prometheus/",
        "local_assets": [],
        "require_promtool": True,
    },
    # 监控 required checks / 自动 runbook：由部署方配置，发行版默认为空
    # 格式见 docs/migration-monitor-v073.md；不得把特定环境数据写进代码默认值
    "required_checks": {},
    "runbook_rules": [],
    # 节点标识（watch_ping 等场景），默认取 hostname
    "node_name": "",
}

# 秘密键：优先环境变量 AYANA_<KEY>，其次 secrets.json
# 注：llm_* 可来自 secrets/env，也可由运行态 meta 覆盖（见模块 docstring 两层优先级）。
#     gen-secrets.py 只生成需要随机值的键（不含 llm_* 与预留项）。
SECRET_KEYS = (
    "onewbot_token",
    "webhook_token",
    "web_auth_pepper",
    # "session_signing_key",  # 预留：当前会话用 HttpOnly Cookie + 服务端 session 表，未使用签名密钥
    "totp_encrypt_key",
    "ssh_credential_key",
    "notify_channel_key",
    "llm_api_key",
    "llm_base_url",
    "llm_model",
    "ai_credential_key",
    "ai_planner_api_key",
    "ai_reviewer_kimi_api_key",
    "ai_reviewer_deepseek_api_key",
)


class ConfigError(Exception):
    pass


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ConfigError(f"invalid json: {path}: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"config must be object: {path}")
    return data


def load_config(base_dir: str | Path) -> dict[str, Any]:
    base = Path(base_dir).resolve()
    if base.is_file():
        cfg_path = base
        base = base.parent
    else:
        cfg_path = base / "config.json"
    secrets_path = base / "secrets.json"

    cfg = dict(DEFAULTS)
    cfg.update(_read_json(cfg_path))

    secrets = _read_json(secrets_path)
    for key in SECRET_KEYS:
        env_val = os.environ.get(f"AYANA_{key.upper()}")
        if env_val:
            cfg[key] = env_val
        elif key in secrets:
            cfg[key] = secrets[key]

    # 向后兼容：旧 config.json 的 token 视为 onewbot_token
    if "onewbot_token" not in cfg and cfg.get("token"):
        cfg["onewbot_token"] = cfg["token"]

    missing = [k for k in ("onewbot_token", "webhook_token") if not cfg.get(k)]
    if missing:
        raise ConfigError(
            f"missing secrets: {', '.join(missing)} "
            f"(set AYANA_* env or {secrets_path.name})"
        )

    cfg["base_dir"] = str(base)
    return cfg


def write_secrets_template(path: str | Path) -> None:
    """写出空秘密模板，不含真实秘密。"""
    p = Path(path)
    if p.exists():
        raise ConfigError(f"refusing to overwrite {p}")
    p.write_text(
        json.dumps({k: "" for k in SECRET_KEYS}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(p, 0o600)
