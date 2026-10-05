# Ayana v0.1.0

Ayana — 直接以 OneBot v11 反向 WS 服务端接管 NapCat 的运维平台（最小实验版）。

## 职责

- 监听 `ws://0.0.0.0:6199/ws`，接受 NapCat 的 WS 客户端连接
- 收 QQ 消息事件，`/ping` 回 `Ayana v0.1.0 / pong`
- HTTP `GET :6200/health` 健康检查
- 独立配置 `config.json`，日志写 stdout + 文件

## 运行

```bash
# KANATA 上
cd /root/Ayana
uv sync
uv run python -m ayana.main config.json
```

## 依赖

- Python ≥ 3.11
- aiohttp ≥ 3.9

## 配置

见 `config.json`：

| 键 | 说明 |
|----|------|
| `ws_port` | OneBot 反向 WS 端口（接管 AstrBot 的 6199） |
| `token` | NapCat `onebot11_*.json` 里的 token |
| `http_port` | health 端口 |
| `self_id` | QQ 号 |

## 命令

| 命令 | 响应 |
|------|------|
| `/ping` | `Ayana v0.1.0` / `pong` |
| `/health` | 服务状态 |
| `/help` | 帮助 |

## 切换说明

NapCat 侧无需改动：`onebot11_REDACTED-ADMIN-QQ.json` 里已是 `ws://127.0.0.1:6199/ws` 反向连接。
停掉 AstrBot（释放 6199）后启动本服务，NapCat 会在 30s 内自动重连。
