# Ayana v0.2.0

运维闭环平台：把告警变成**可调查、可审批、可执行、可验证**的处置流程，而不是只丢一条群消息。

一条链路：

```text
Alertmanager → Event → Incident → 调查 → 权限 → 受控处置 → 独立验证 → Web / QQ → 审计
```

- **单进程** Python 3.11+ / aiohttp / SQLite
- **OneBot v11 反向 WS** 直连 NapCat（不经 AstrBot，无中间 LLM 抢答）
- **Web 控制台** 与 QQ 共用同一业务服务层
- **执行零自由度**：LLM 只分析；真正动手只能命中 runbook 预登记动作，并经主机侧安全闸

---

## Ayana 是什么

| 角色 | 说明 |
|------|------|
| 告警入口 | 接收 Alertmanager webhook，归并为 Event / Incident |
| 调查员 | 只读探查（经 NT 受限 SSH + Prometheus），沉淀证据 |
| 分析员 | 可选 LLM 分类/摘要（建议，不执行） |
| 执行员 | 提案 → 批准 → 执行 → 验证；runbook 查表 |
| 值班通道 | QQ 命令 + 通知；Web 全流程与审计 |
| 安全边界 | 业务权限在 Ayana；主机 `commands.json` / sudoers 是最终上限 |

适用场景：少量关键资产（本仓库种子含 NERV / KANATA / Sora / Yomi），需要「半夜自动处置也要留痕、可拒、可验」。

---

## 架构

```text
Prometheus / Alertmanager / Blackbox
              │
              ▼
     接入层（webhook · Prom API · NT SSH）
              │
              ▼
 Asset → Event → Incident → Investigation
              │
              ▼
    Capability / Policy → Action → Verification
              │
              ▼
     Web 控制台  ·  QQ 通知  ·  审计
```

技术选型：

| 层 | 选择 |
|----|------|
| 运行时 | 单进程 asyncio + aiohttp |
| 存储 | SQLite（WAL · foreign_keys · synchronous=FULL，短事务） |
| IM | OneBot v11 反向 WS（`ws://…:6199/ws`） |
| 监控 | Prometheus range vector 真采样（`timestamp()` + value），不用 instant 评估时刻冒充样本 |
| 主机通道 | 受限 SSH（`restricted_dispatcher` only） |
| 认证 | 本地账号 · PBKDF2 · TOTP 2FA · 恢复码 |

模块（包 `ayana/`）：

| 模块 | 文件 | 职责 |
|------|------|------|
| 入口/装配 | `main.py` | 启动、种子资产、后台任务 |
| 配置/秘密 | `config.py` | `config.json` + `secrets.json`（秘密不入库） |
| 数据库 | `db.py` | SQLite、审计、短事务 |
| 认证 | `auth.py` | 密码 / TOTP / 恢复码 |
| 权限 | `policy.py` | 主体 → 资产 → 能力 → 对象，默认拒绝 |
| 能力目录 | `capabilities.py` | 固定能力表，目标只来自登记对象 |
| **知识库** | `knowledge.py` | 对象语义/依赖/调查提示；精确匹配，不授予执行权 |
| NT 通道 | `ntsafe.py` | 受限 SSH + 身份/别名校验 |
| Prometheus | `prom.py` | range vector 采样与验证 |
| 告警接入 | `alertmanager.py` | webhook + AM 对账 |
| 事件 | `incidents.py` | 归并、生命周期、人工待办 |
| 调查 | `investigation.py` | 只读探查 + 注入对象知识 |
| 操作 | `actions.py` | 提案→批准→执行→验证 |
| Agent | `agent.py` | 知识→调查→LLM→runbook→执行/找人 |
| LLM | `llm.py` | 可选分析（可注入知识上下文） |
| Runbook | `runbook.py` | 固定规则表 |
| 通知 | `notify.py` + `fmt.py` | outbox，人类可读，无 emoji |
| OneBot / QQ | `onewbot.py` · `qqbot.py` | 连接、命令 |
| Web | `web.py` + `static/` | 控制台 |

---

## 核心闭环

```text
1. 接入     Alertmanager webhook → fingerprint 归并 → Event / Incident
2. 调查     只读证据（服务状态 / 端口 / 磁盘 / 探测…），走 Policy
3. 分析     可选 LLM：分类、摘要、建议（写进记录，不赋执行权）
4. 决策     runbook 查表（asset × object × alertname），或人工提案
5. 授权     Policy：主体/能力/资产/对象；Web 可改，默认拒绝
6. 执行     提案 → 批准（指定 Action ID）→ 受限 SSH 写通道
7. 验证     两个新鲜采样、完整标签序列比对；失败/未知 → need_human
8. 通知     QQ/Web；全程审计
```

**执行状态机**（`actions`）：

```text
proposed → approved → dispatched → success | failure | unknown
                ↘ cancelled / expired
success → verification: passed | failed | unknown
unknown / 验证失败 → incident.need_human
```

**Agent（`agent.py`）**：`知识 → investigate → LLM 分析 → match_runbook → Policy → 执行或找人`。  
`auto_remediation` 默认 **关**；开启后也只跑 runbook 命中项，且有日次数/冷却。

**验证**：`timestamp(probe_success)` 的 **两个不同新鲜样本**（完整标签含 instance 的单序列），不用 instant 评估时间伪造。

---

## 运维知识库（`knowledge/` + `knowledge.py`）

**一个知识点 / 系统链路 / 典型故障 = 一个 Markdown 文件**。  
Markdown 正文是知识事实源；SQLite（`object_knowledge`）仅历史遗留/可重建索引，不作为正文。

### 目录

```text
knowledge/
├── hysteria2-chain.md          # Hysteria2 代理链路（system）
├── frps-service.md             # NERV frps（system）
└── ayana-port-bind-failed.md   # 6200 拒连（issue）
```

### Markdown 格式

```markdown
---
id: hysteria2-chain
title: Hysteria2 代理链路
status: active          # active | deprecated | historical
type: system            # system | issue | procedure
objects:
  - sora:hysteria-server
  - sora:google
tags:
  - hysteria2
---

# 标题
正文自由 Markdown（用途 / 关系 / 异常含义 / 调查 / 处置…）
```

- **status**：`active` 可用于当前调查；`deprecated` 不应作当前操作依据；`historical` 只作历史
- **objects**：资产:对象，可跨资产；知识主题不按资产切分
- **只写长期语义**，不写「xx 当前正常」等实时状态

### Agent 接入

```text
Incident → docs_for_object / docs_for_objects
         → investigation_context（active MD 正文）
         → Investigation / LLM（仅建议）
         → runbook ∩ Policy ∩ 主机闸 → Action → Verification
```

google + youtube 同时命中 `hysteria2-chain.md` → 共同依赖优先调查。  
知识**不能**授予执行权。

### Web

导航 **知识**：主题列表（type/status/搜索）→ 查看 Markdown。  
总览只展示实时监控表，不展示知识正文。

### 新增一条知识

1. 在 `knowledge/` 新建 `*.md`，写 front matter + 正文
2. 重启 Ayana（或调用 `KnowledgeBase.reload()`）
3. Web「知识」页可见；命中 `objects` 的调查自动带上

不要把 secrets/密码写入知识文件。

---

## 安全模型

双层闸，Ayana **不能**扩大主机权限。

| 层 | 控制什么 | 位置 |
|----|----------|------|
| **Ayana 业务权限** | 谁能看/提案/批准哪类资产能力 | Web 可改，带审计与版本快照 |
| **主机安全闸** | 进程实际能执行哪些命令 | `commands.json` / forced-command / sudoers（独立） |

硬约束：

- 写操作只走：`sudo -n -- /usr/local/sbin/astrbot-nt-command exec …`
- NT 账号 `nt-probe`（只读）/ `nt-exec`（仅 start/stop/restart）；策略白名单 + 审计日志
- 能力目录固定；对象名只来自登记对象，禁止自由拼命令
- **LLM 想法 ≠ 执行权**；执行权 = runbook 查表 ∩ Policy ∩ 主机白名单
- 秘密在 `secrets.json`（600），不入 git；环境变量 `AYANA_*` 可覆盖
- 无公共 `/send`；静态路由只服务 `ayana/static/`
- Web：会话 + CSRF；密码 PBKDF2 + pepper；TOTP；恢复码

---

## 当前能力

### 能力目录（`capabilities.py`）

| 类型 | 名称 | 说明 |
|------|------|------|
| 读 | `asset.summary` | 资产摘要（调查入口） |
| 读 | `service.status` / `service.logs` | 服务状态 / 日志 |
| 读 | `port.listen` / `disk.usage` / `memory.available` / `load.current` | 端口、磁盘、内存、负载 |
| 读 | `probe.status` | 外部探测（经 Prometheus） |
| 写 | `service.restart` / `start` / `stop` | systemd（start/stop 偏人工） |
| 写 | `container.restart` | docker restart（登记容器） |

写命令由对象绑定生成（如 `systemctl restart frps`），不可注入。

### 种子资产（`main.py` · 首启写入）

| 资产 | 读/写别名 | 对象示例 |
|------|-----------|----------|
| **nerv** | `nerv` / `nerv-exec` | frps · nginx · php-fpm · tcp 32659 · 黑盒探测 |
| **kanata** | `kanata` / `kanata-exec` | harbor-core · nginx · alist |
| **sora** | `sora` / `sora-exec` | hysteria-server · udp 443 |
| **yomi** | `yomi` / `yomi-exec` | （待登记） |

### Runbook（默认三条，零自由度）

| 规则 | 条件 | 动作 | 限制 |
|------|------|------|------|
| frps 不可达 → 重启 | nerv · frps · TargetDown · 探测失败 | `service.restart` | ≤3 次/日 · 冷却 30min |
| nginx 不可达 → 重启 | nerv · nginx · TargetDown · 探测失败 | `service.restart` | 同上 |
| hysteria 不可达 → 重启 | sora · hysteria-server · TargetDown | `service.restart` | 同上 |

### 监控接入

- Prometheus / Alertmanager / Blackbox（配置项 `prometheus_url` · `alertmanager_url`）
- `POST /hooks/alertmanager`（Bearer `webhook_token`）
- 验证依赖 `probe_success` 等指标的 range 查询

---

## QQ

OneBot v11 反向 WS（`ws_host`/`ws_port`/`ws_path`，NapCat 侧连入）。

| 命令 | 作用 |
|------|------|
| `/ping` `/health` `/help` | 存活 / 自身状态 / 帮助 |
| `/status` | 总览 |
| `/asset <id>` | 资产状态 |
| `/incident [id]` | 事件列表或详情 |
| `/investigate <asset> [object]` | 发起只读调查 |
| `/actions` | 待批准操作 |
| `/approve <action_id>` | 批准（**必须带 Action ID**） |
| `/cancel <action_id>` | 取消 |

无裸数字多选；通知人类可读、无 emoji；`admin_qq` 可作管理侧提示。

---

## Web

本地账号登录（密码 + TOTP + 恢复码），路径 `:6200`。

| 区域 | 内容 |
|------|------|
| 总览 | 紧凑统计 + 资产可折叠条（对象表、探测） |
| 事件 | 列表 / 详情（人话摘要、关联操作、时间线）、手动关闭 |
| 操作 | 列表（完成时间）、批准/取消/执行/验证，与事件互链 |
| 权限 | admin 改策略 |
| 审计 | 关键词 + 时间范围 |
| 其他 | `#assets/<id>` 深链接 · 通知 outbox · runbook · Agent 开关 |

**HTTP**

| 路径 | 说明 |
|------|------|
| `GET /health` `/ready` | 存活 / 就绪 |
| `POST /hooks/alertmanager` | 告警入口 |
| `GET/POST /api/*` | 业务 API（会话 + CSRF） |
| `GET /` `/static/*` | 控制台 |

---

## 部署

```bash
# 运行（开发）
cd /path/to/Ayana
uv sync
uv run python -m ayana.main config.json
# 或：ayana config.json
```

生产（当前约定）：

```bash
cd /root/Ayana
nohup setsid ./start.sh   # uv run python -m ayana.main config.json
```

**配置** `config.json`（见 `config.example.json`）：端口、`self_id`、`db_path`、Prometheus/Alertmanager、`admin_qq`、`auto_remediation_enabled`、验证窗口等。

**秘密** `secrets.json`（600，不入库）：

| 键 | 用途 |
|----|------|
| `onewbot_token` | NapCat WS token |
| `webhook_token` | Alertmanager Bearer |
| `web_auth_pepper` | 密码哈希 pepper |
| `session_signing_key` | 会话签名 |
| `totp_encrypt_key` | TOTP 密钥加密（预留） |
| `llm_api_key` | 可选 LLM |

**开发**

```bash
python -m unittest discover -s tests -v
```

依赖见 `pyproject.toml` / `requirements.txt`（aiohttp 等）。

**主机侧（与本仓库解耦）**：受限入口 `/usr/local/sbin/astrbot-nt-command`、策略 `commands.json`、sudoers、NT 账号与别名绑定须由管理员单独部署与审阅。

---

## Roadmap

当前 v0.2.0 已闭环告警→处置→验证。后续方向：

- [ ] 部署身份迁 systemd 非 root（现为 `setsid` root）
- [ ] NT 写通道 `sora-exec` / `kanata-exec` / `yomi-exec` 创建与核实
- [ ] 自动处置 runbook 与主机闸的独立变更窗口（默认仍关）
- [ ] 外网恢复通知延迟（Alertmanager `group_interval`）可调
- [ ] Yomi 对象与探测补齐；监控清单持续对齐
- [ ] 验证策略可配置（采样窗口、稳定性判据）
- [ ] 权限/审计导出；备份与恢复脚本

---

## 版本与许可

- 版本：`ayana.__version__`（当前 **0.2.0**）
- 仓库：私有部署使用；主机安全配置不在本仓库

**已验收参考**：NERV `frps` 闭环（重启 + 双新鲜采样验证）；白屏问题（前端 `ZH_CAP`）已修复并上线。
