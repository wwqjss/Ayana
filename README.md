# Ayana

**运维闭环平台**：把告警变成**可调查、可审批、可执行、可验证**的处置流程，而不是只丢一条群消息。

```text
Alertmanager → Event → Incident → 调查 → 权限 → 受控处置 → 独立验证 → Web / IM → 审计
```

| 能力 | 说明 |
|------|------|
| 告警接入 | Alertmanager webhook，归并 Event / Incident |
| 只读调查 | 受限 SSH / Prometheus 证据采集，有预算与截止时间 |
| 受控执行 | 能力目录固定 argv；提案 → 批准 → 执行 → 验证 |
| 权限与审计 | Policy 三态（禁止 / 人工确认 / 自动）+ 完整审计 |
| 入口 | Web 控制台；可选 QQ / 企业微信机器人 |
| 安全 | 本地账号 + TOTP、会话加固、命令白名单、SSRF 边界 |

适合：少量关键主机，需要「半夜自动处置也要留痕、可拒、可验」的运维场景。

当前版本：**v0.7.3**（见 `ayana/__init__.py` / `pyproject.toml`）。

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
 Asset → Event → Incident → Investigation
        │
        ▼
 Capability / Policy → Action → Verification
        │
        ▼
   Web 控制台 · 通知 · 审计
```

- **运行时**：单进程 asyncio + aiohttp；SQLite（WAL）
- **执行零自由度**：LLM 只分析；动手只能命中能力目录 / runbook 固定动作
- **主机侧上限**：业务权限在 Ayana；目标机 sudoers / forced-command 仍是最终边界

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
- 写操作职责分离（非 admin 不可自批）

---

## 开发与测试

```bash
python -m unittest discover tests -q
```

无网络依赖的单测可在无 aiohttp 环境运行核心逻辑；含 Web 集成的用例需要 `pip install aiohttp`。

---

## 文档

- [安装手册](docs/INSTALL.md) — 部署、systemd、备份、升级
- [智能填表说明](docs/assist-configuration.md) — 可选 LLM 填表

## 许可证

本项目采用 **MIT License**，详见 [LICENSE](LICENSE)。

Copyright (c) 2026 wwqjss
