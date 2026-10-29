# Ayana

**运维闭环平台**：在同一个 MiMoCode 会话中调查、执行和验证故障处置，保留可核对的执行事实与恢复证据。

```text
Alertmanager → Event → Incident → MiMoCode 会话 → host.exec / 验证 → Web / IM / 审计
```

| 能力 | 说明 |
|------|------|
| 告警接入 | Alertmanager webhook，归并 Event / Incident |
| 调查与处置 | 同一 MiMoCode 会话通过 MCP 查询证据、执行命令和维护监控配置 |
| 账号组 | 一个全局默认组；会话可单独选择，实际权限由目标机 SSH 账号决定 |
| 结果与审计 | 写操作台账、未知结果保护、恢复证据和完整审计 |
| 入口 | Web 控制台；可选 QQ / 企业微信机器人 |
| 安全 | 本地账号 + TOTP、会话加固、命令白名单、SSRF 边界 |

适合：少量关键主机，需要自动处置并保留执行过程、验证依据的运维场景。

当前版本：**v0.8.0**（见 `ayana/__init__.py` / `pyproject.toml`）。

---

## 快速开始

完整步骤见 **[安装手册](docs/INSTALL.md)**。

**一键（脚本自己拉包，跟随最新 Release）：**

```bash
curl -fsSL https://raw.githubusercontent.com/wwqjss/Ayana/main/deploy/bootstrap.sh -o bootstrap.sh
bash bootstrap.sh --system              # 缺啥装啥；已装完整则跳过
```

从源码最短路径：

```bash
git clone https://github.com/wwqjss/Ayana.git
cd Ayana

# 1. 依赖：Python 3.11+，建议 venv
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 2. 配置
cp config.example.json config.json
# 编辑 config.json；秘密可用 scripts/gen-secrets.py 生成 secrets.json（600）
# 或使用 AYANA_* 环境变量
python -m ayana.main config.json
```

也可使用 `deploy/install.sh`（`--user` / `--system`）完成目录、依赖、秘密与可选 systemd 安装。

首次启动会在**数据库同目录**生成 `bootstrap-admin.password`（0600）。用该口令登录 Web（默认 `http://127.0.0.1:6200`），**立即改密**并删除该文件。

```bash
# 取默认口令（system 安装；用户安装把路径换成数据目录）
sudo cat /var/lib/ayana/bootstrap-admin.password

# 也可从日志确认路径
journalctl -u ayana -n 50 | grep BOOTSTRAP

# 登录改密后删除
sudo rm -f /var/lib/ayana/bootstrap-admin.password
```

---

## 架构一览

```text
Prometheus / Alertmanager
        │
        ▼
   接入层（webhook · Prom API · SSH）
        │
        ▼
 Asset → Event → Incident → MiMoCode 会话
        │
        ▼
 MCP 查询 / host.exec / config.* → 执行事实 / 恢复证据
        │
        ▼
   Web 控制台 · 通知 · 审计
```

- **平台**：asyncio + aiohttp；SQLite（WAL）；独立 MiMoCode 原生运行时。
- **账号选择**：未覆盖的会话和后台检查使用全局默认组；会话覆盖只影响后续操作。缺少指定组时明确报错，不换用另一组。
- **主机侧上限**：目标机 SSH 账号和 sudoers 决定命令权限；账号组名称不代表权限档位。
- **恢复判定**：命令成功不等于故障恢复，结案需要匹配故障和代次的新鲜证据。

---

## 配置与秘密

| 文件 | 是否入库 | 内容 |
|------|----------|------|
| `config.json` | 否 | 端口、DB 路径、Prometheus/AM 地址等 |
| `secrets.json` | 否（600） | token / pepper / 加密密钥等 |
| `config.example.json` | 是 | 模板，无真实秘密 |

秘密键可用环境变量覆盖：`AYANA_ONEWBOT_TOKEN`、`AYANA_WEBHOOK_TOKEN`、`AYANA_WEB_AUTH_PEPPER`、`AYANA_TOTP_ENCRYPT_KEY`、`AYANA_SSH_CREDENTIAL_KEY` 等（见 `ayana/config.py`）。

**安全基线（v0.7.3+）**：

- 登录：PBKDF2、失败锁定、TOTP 2FA、恢复码、会话绑定
- 首登强制改密；bootstrap 口令不写日志
- 自定义检查命令白名单；禁止任意文件读与输出内容 oracle
- Webhook / WebSocket 目标 SSRF 黑名单；Origin 精确校验
- 写操作留痕；未知结果保留并阻止盲目重复执行；旧逐动作审批已退役

---

## 开发与测试

```bash
python -m unittest discover tests -q
```

无网络依赖的单测可在无 aiohttp 环境运行核心逻辑；含 Web 集成的用例需要 `pip install aiohttp`。

---

## 文档

- [安装手册](docs/INSTALL.md) — 部署、systemd、备份、升级
- [MCP 操作接口](docs/mcp-operations.md) — MiMoCode 操作、账号组和监控配置

## 许可证

本项目采用 **MIT License**，详见 [LICENSE](LICENSE)。

Copyright (c) 2026 wwqjss
