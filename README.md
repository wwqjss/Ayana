# Ayana v0.2.0

运维闭环平台：Alertmanager 事件 → Incident → 调查 → 权限 → 受控处置 → 独立验证 → Web/QQ 展示 → 审计。

## 架构

- 单进程 + 本地 SQLite（WAL / foreign_keys / synchronous=FULL）
- OneBot v11 反向 WS 直连 NapCat（无 AstrBot、无中间 LLM 抢答）
- Web 控制台：本地账号 + 密码（PBKDF2）+ TOTP 2FA + 恢复码
- 业务权限在 Ayana（Web 可改、带审计与版本快照）
- **主机侧** `commands.json` / forced-command / sudoers 仍是独立最终安全上限

## 运行

```bash
# KANATA
cd /root/Ayana
uv sync
uv run python -m ayana.main config.json
```

秘密放在 `secrets.json`（权限 600，不入库）：

| 键 | 用途 |
|----|------|
| `onewbot_token` | NapCat WS token |
| `webhook_token` | Alertmanager Bearer |
| `web_auth_pepper` | 密码哈希 pepper |
| `session_signing_key` | 会话 |
| `totp_encrypt_key` | 预留 |

环境变量 `AYANA_*` 可覆盖同名键。

## 命令（QQ）

`/ping` `/health` `/help` `/status` `/asset <id>` `/incident [id]`
`/investigate <asset> [object]` `/actions` `/approve <action_id>` `/cancel <action_id>`

不保留裸数字多选协议；批准必须指定 Action ID。

## HTTP

| 路径 | 说明 |
|------|------|
| `GET /health` `/ready` | 存活 / 就绪 |
| `POST /hooks/alertmanager` | 告警入口（Bearer `webhook_token`） |
| `/api/*` | 业务 API（会话 + CSRF） |
| `/` `/static/*` | 控制台 |

无公共 `/send`。静态路由只服务 `ayana/static/`。

## 首个闭环对象

NERV `frps`（systemd）+ blackbox `tcp_connect` 探测。
验证用 `timestamp(probe_success)` 的**两个不同新鲜采样**，不用 instant 评估时间。

## 测试

```bash
python -m unittest discover -s tests -v
```
