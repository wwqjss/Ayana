# Ayana「外部事务」功能 — 阶段 A/B 调查与实施方案

> 状态：**暂停在阶段 B，等待确认后再改代码。**
> 调查范围：本地源码 `C:\Users\karory\Git\Ayana`（schema_version=14）。
> 飞牛备份细节来自上一会话对 KANATA 的只读调查，本文不重复改动任何飞牛侧配置。

---

## 阶段 A：现状检查

### A1. 架构中可直接复用的机制

| 能力 | 现有实现 | 复用方式 |
|---|---|---|
| Schema 迁移 | `db.py`：`SCHEMA_VERSION=14` + `_MIGRATIONS` 幂等迁移 | 新增 `_migrate_v15_ext_tasks`，不改旧迁移 |
| 事件链路 | `alert_episodes` → `IncidentService.upsert_from_episode` → `incidents` + `events` | 外部事务失败/超时写入 episode，走同一收敛 |
| 告警收敛 | `IncidentService.reconcile` / `upsert_from_episode`（含复发 generation） | 失败 streak 开 episode，成功后 resolve episode → reconcile |
| 通知 | `notification_outbox`（`dedup_key` UNIQUE）+ `Notifier.enqueue` + 多渠道 + `compensate_missing` | 生命周期事件 `incident_opened/reopened/resolved` 自动建通知义务 |
| 鉴权（管理面） | `web_sessions` + CSRF + `_require_auth` / `_require_admin` | 外部事务管理界面走现有会话鉴权 |
| 鉴权（上报面） | `/hooks/alertmanager`：`Authorization: Bearer` + `hmac.compare_digest`；`setup_token_hash`（哈希存储）；`hash_recovery_code(code, pepper)` | 上报 Token 用「生成明文一次 + 只存哈希」模式，Bearer 头校验 |
| 审计 | `db.audit()` / `audit_log` | Token 生成、吊销、轮换、配置变更全部落审计 |
| 后台调度 | `main.py`：`_bg_checks` / `_bg_outbox` / `_bg_reconcile` / `_bg_correlate` | 新增 `_bg_ext_watch` 做超时/失联扫描 |
| 异常数据隔离 | `alertmanager.py`：无效 startsAt → `quarantine`，不自动执行 | 采集端 DB 异常/字段无法识别 → 上报 `unknown`/`monitor_error`，**绝不默认成功** |
| UI | `static/index.html` + `app.js`，顶部 Tab 导航 | 新增「外部事务」Tab（或并入「事件」子页） |

### A2. 关键数据表（现有）

- `alert_episodes`：`UNIQUE(source_id, fingerprint, starts_at_norm)`，`status= firing|resolved`，`incident_id` 关联
- `incidents`：`status=open|resolved|closed`，`generation` 复发递增，`resolution_basis`
- `events`：`type/title/payload_json`，生命周期类型被 `notify.py` 的 `LIFECYCLE_TYPES` 消费
- `notification_outbox`：`dedup_key` UNIQUE，天然幂等
- `checks` / `check_results`：最接近「外部事务」的现有模型（interval、fail_streak、fail_threshold），但它**主动 SSH 探测**，与「外部主动上报」方向相反，不可直接套用

### A3. 记忆与代码的偏差

项目记忆写 `schema_version=10`，**当前源码为 14**（`db.py`）。以代码为准。后续部署前应确认 kanata `/var/lib/ayana/ayana.db` 的实际版本。

### A4. 飞牛备份侧已有调查结论（上一会话，只读）

- 状态库：`/usr/trim/var/backup_service/basic_backup.db3`（SQLite 只读可打开）
- 服务日志：`/usr/trim/logs/backup_service.log`
- `operations.status=3` 且 `error_code=0` → 成功；`status=4` 且 `error_code≠0` → 失败
- `error_code=84934737` 对应日志中的 `RefreshTokenExpired`（云盘令牌族）
- `user_tasks.next_time` 存在陈旧值（FNBK 的 next_time 仍显示 2026-04-20，但实际每周一 00:00 仍跑），**不能单独作调度依据**
- 判断「未按时执行」应用任务自身调度配置（`day_nos` / `period`）+ 最近 `start_time`，**不得把「周一」硬编码为所有任务默认**
- 已有 `mysqlbk` 任务指向阿里云盘；`error_message` 在 DB 中常为空，真实原因在日志

### A5. 边界确认（与需求一致，不引入）

- 不新增第二套告警引擎 / 通知系统
- 不重写 Prometheus / Alertmanager
- 不自动修复飞牛、不自动重登阿里云盘
- 不改 MySQL 主从
- 不重构现有 Event/Incident 体系
- 不做通用任务调度平台

---

## 阶段 B：最小增量方案

### B1. 设计原则

1. **通用事务模型**：只认「事务（Transaction）+ 执行（Run）+ 上报」，不绑飞牛语义。
2. **复用事件链路**：失败/超时/失联 → 写 `alert_episodes`（`source_id='ext_tx'`）→ `upsert_from_episode` → Incident → 现有通知。
3. **Token 最小权限**：一个 Token 只能上报一个事务（`event_key`），无管理/执行权限。
4. **幂等 + 防旧覆新**：同 `run_id` 重复上报不重复建记录/发告警；低优先级状态不得覆盖高优先级终态。
5. **异常不冒充成功**：采集/解析失败上报 `unknown` 或专用 `monitor_error`，并按「监控异常」告警。

### B2. 数据结构（迁移 v15）

```sql
-- 外部事务定义
CREATE TABLE ext_transactions (
  id TEXT PRIMARY KEY,
  event_key TEXT NOT NULL UNIQUE,          -- 如 mysqlbk.cloud_backup
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  source_label TEXT NOT NULL DEFAULT '',   -- 来源展示名
  asset_id TEXT NOT NULL DEFAULT '',       -- 可选挂到资产
  object_id TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  expect_interval_sec INTEGER NOT NULL DEFAULT 0,  -- 0=不检查失联
  timeout_sec INTEGER NOT NULL DEFAULT 0,          -- running 超时阈值
  alert_on_failure INTEGER NOT NULL DEFAULT 1,
  alert_on_recovery INTEGER NOT NULL DEFAULT 1,
  alert_on_timeout INTEGER NOT NULL DEFAULT 1,
  alert_on_missing INTEGER NOT NULL DEFAULT 1,
  last_status TEXT NOT NULL DEFAULT 'unknown',
  last_run_id TEXT NOT NULL DEFAULT '',
  last_report_at REAL NOT NULL DEFAULT 0,
  last_success_at REAL NOT NULL DEFAULT 0,
  last_failure_at REAL NOT NULL DEFAULT 0,
  open_incident_id TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);

-- 上报 Token（只存哈希；明文仅创建/轮换时返回一次）
CREATE TABLE ext_tokens (
  id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_hint TEXT NOT NULL DEFAULT '',     -- 末 4 位，便于识别
  created_at REAL NOT NULL,
  revoked_at REAL,
  last_used_at REAL,
  rotated_from TEXT NOT NULL DEFAULT ''
);

-- 执行记录
CREATE TABLE ext_runs (
  id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL,                   -- running|success|failure|timeout|unknown
  severity TEXT NOT NULL DEFAULT 'warning',
  message TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  client_ts REAL,                         -- 上报 timestamp（epoch）
  reported_at REAL NOT NULL,              -- 服务端接收时间
  status_rank INTEGER NOT NULL DEFAULT 0, -- 防旧覆新
  content_hash TEXT NOT NULL DEFAULT '',  -- 幂等去重
  episode_id TEXT NOT NULL DEFAULT '',
  incident_id TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(transaction_id, run_id)
);
CREATE INDEX idx_ext_runs_tx ON ext_runs(transaction_id, reported_at);
CREATE INDEX idx_ext_tokens_hash ON ext_tokens(token_hash);
```

**状态优先级（防旧消息覆盖新状态）**

| status | rank | 说明 |
|---|---|---|
| running | 0 | 可被任何后续状态覆盖 |
| unknown | 1 | 监控异常/无法识别 |
| timeout | 2 | 执行超时 |
| failure | 3 | 终态失败 |
| success | 3 | 终态成功 |

写入规则：
1. `new_rank < old_rank` → **拒绝更新**（旧结果不得覆盖新状态）。
2. `new_rank == old_rank` → 仅当 `client_ts` 更大（或相等且 `content_hash` 不同）才更新。
3. `new_rank > old_rank` → 允许更新。
4. 同 `run_id` 同 `content_hash` → 幂等，直接返回 `deduped=true`，不写 Event、不发通知。
5. 事务级 `last_status` 始终跟随**最新 `reported_at` 的 run**，不因历史 run 回写。

### B3. 状态与告警流转（复用 Episode → Incident）

```
上报 failure/timeout
        │
        ▼
  是否已有 firing episode?
   ├─ 否 → 建 alert_episode(source_id='ext_tx')
   │        fingerprint=hash(event_key)
   │        starts_at_norm=本次 streak 起点
   │        → upsert_from_episode → Incident + notify（alert_on_failure）
   └─ 是 → 只更新 last_seen/receive_count/annotations
            保留执行记录，不重复通知（防轰炸）

上报 success
        │
        ▼
  episode.status → resolved
  → IncidentService.on_alert_resolved / reconcile
  → incident_resolved + 恢复通知（alert_on_recovery）

后台 _bg_ext_watch（每 60s）
  ├─ running 超过 timeout_sec → 合成 timeout run + 告警（alert_on_timeout）
  └─ 超过 expect_interval_sec 无任何上报
     （宽限 = expect_interval + max(timeout, 300)）
     → 失联/未执行告警（alert_on_missing）
```

约束对齐需求：
- 首次失败 → 事件 + 通知
- 持续失败 → 只记 run，不重复通知
- 失败后成功 → 关闭/恢复 Incident + 恢复通知
- 超时 → 超时事件
- 未按时上报 → 失联告警
- 监控恢复 → 自动更新状态
- **一次成功只解决当前 streak**，历史 run 保留，不批量「抹平」其他未决问题

### B4. 上报 API

```
POST /api/ext/report
Authorization: Bearer ext_<token>
Content-Type: application/json

{
  "event_key": "mysqlbk.cloud_backup",
  "status": "failure",
  "severity": "warning",
  "message": "阿里云盘备份失败",
  "detail": "RefreshTokenExpired",
  "run_id": "backup-20261019-0000",
  "timestamp": "2026-10-19T00:00:00+08:00"
}
```

**校验（全部通过才入库）**

| 字段 | 规则 |
|---|---|
| Token | 必填；哈希命中且未吊销；绑定的 transaction.enabled=1 |
| event_key | 必须与 Token 绑定事务一致，否则 403 |
| status | 枚举 `running\|success\|failure\|timeout\|unknown` |
| severity | 枚举 `info\|warning\|critical`，默认 `warning` |
| message | 可选，≤500 字符，纯文本存档 |
| detail | 可选，≤2000 字符，纯文本存档 |
| run_id | 必填，`[A-Za-z0-9._:-]{1,128}` |
| timestamp | 可选 ISO-8601；非法则记 `unknown` 来源并继续用服务端时间 |

**响应**

```json
{"ok": true, "run_id": "backup-20261019-0000", "status": "failure", "deduped": false}
```

**安全硬约束**
- 不允许匿名上报
- Token 只上报、无管理/命令权限
- 日志、审计、事件 payload **不写明文 Token**（只记 `token_hint` / `token_id`）
- `message`/`detail` 只作数据展示，不进任何执行/模板求值路径
- 长度超限、类型错误、来源不匹配 → 4xx，不入库

### B5. 管理 API（会话 + CSRF，走 `_require_auth`/`_require_admin`）

```
GET    /api/ext/transactions
POST   /api/ext/transactions                 # 创建
POST   /api/ext/transactions/{id}/update     # 名称/描述/周期/阈值/告警开关
POST   /api/ext/transactions/{id}/enabled
DELETE /api/ext/transactions/{id}            # 仅允许无 open incident 或强制
POST   /api/ext/transactions/{id}/tokens     # 生成/轮换，明文只返回一次
POST   /api/ext/tokens/{tid}/revoke
GET    /api/ext/transactions/{id}/runs
GET    /api/ext/runs/{run_id}                # 按事务+run 查看
```

Token 生成：`ext_` + `secrets.token_urlsafe(24)`，存储 `sha256(token + pepper)`（复用 `hash_recovery_code` 思路），`token_hint` 存末 4 位。

### B6. UI（保持现有风格）

顶部 Tab 新增「外部事务」：

**概览列表**
- 名称 / 来源 / 最新状态 / 最后上报 / 最后成功 / 告警状态
- 行点击进详情

**详情**
- 执行历史（run_id、状态、开始/结束、耗时、message/detail）
- 关联 Incident（可跳转现有事件页）
- Token 管理（生成/吊销/轮换；明文一次性展示）

**接入配置**
- 创建/编辑表单（名称、event_key、描述、周期、超时、告警开关）
- 「API 接入说明」折叠区：可复制 curl / Python 示例（含占位 Token）

不新建独立通知管理页——告警开关只是事务上的布尔项，通知渠道仍用「通知」Tab。

### B7. 需要修改的文件（最小集）

| 文件 | 改动 |
|---|---|
| `ayana/db.py` | 迁移 `_migrate_v15_ext_tasks` + `SCHEMA_VERSION=15` |
| `ayana/exttx.py` | **新增**：事务/Token/Run 服务、校验、幂等、episode 收敛 |
| `ayana/web.py` | `/api/ext/*` 路由与 handler（上报 + 管理） |
| `ayana/main.py` | 装配 `ExtTxService` + `_bg_ext_watch` 循环 |
| `ayana/static/index.html` | 「外部事务」Tab 骨架 |
| `ayana/static/app.js` | 列表/详情/表单/Token/接入示例 |
| `tests/test_exttx.py` | **新增**：校验/幂等/状态流转/Token/超时/失联 |

**不改**：`alertmanager.py`、`incidents.py`、`notify.py`、`notify_channels.py`、`auth.py`（仅 import 复用哈希函数）、现有监控/SSH/审批逻辑。

### B8. 飞牛接入（阶段 D，独立脚本）

部署在 KANATA 的只读采集脚本（建议 `scripts/fnbk-collector.py`，systemd timer 或 cron）：

1. SQLite **只读** 打开 `basic_backup.db3`
2. 读 `user_tasks`（调度配置）+ `operations`（执行记录）
3. 状态识别：
   - `status=3, error_code=0` → `success`
   - `status=4, error_code≠0` → `failure`（从 `backup_service.log` 附近时间窗提取原因，如 `RefreshTokenExpired`）
   - 无 `finished_time` / 进程仍在 → `running`
   - 超过任务自身预期时长 → `timeout`
   - 到调度点却无新 operations → 不上报 success，由 Ayana 失联/未执行逻辑处理；或主动上报 `unknown`+说明
4. `run_id` = `fnbk:{task_id}:{operation_id}`（稳定、可重放）
5. 检查点（本地 JSON）记录已处理 `operation_id`，避免重复上报
6. DB 不可读 / 字段异常 / 状态无法识别 → 上报 `unknown` + `detail=monitor_error:...`，**不得默认成功**
7. **只读**，不改飞牛 DB/任务/凭据

`event_key` 示例：`fnbk.task_fnbk`、`fnbk.task_mysqlbk`。

### B9. 验收用例（阶段 E）

| # | 场景 | 期望 |
|---|---|---|
| 1 | 正常上报 success | 记 run，状态 success，无告警 |
| 2 | 首次 failure | 建 episode + incident + 通知 |
| 3 | 持续 failure ×N | 有 run 记录，通知不重复 |
| 4 | failure 后 success | 恢复通知，incident 恢复/关闭 |
| 5 | 同 run_id 重复提交 | `deduped=true`，无新事件/通知 |
| 6 | 旧 run 结果晚到 | 不覆盖新 run 状态 |
| 7 | 超时无后续上报 | `_bg_ext_watch` 产生 timeout/missing 告警 |
| 8 | Token 错误/已吊销/越权 event_key | 401/403，无入库 |
| 9 | 采集端 DB 异常 | 上报 unknown，不判 success，产生监控异常告警 |
| 10 | Ayana 重启 | 事务状态、run 去重、episode/incident 仍在 |
| 11 | 现有 Event/Incident/通知 | 回归测试全部通过 |

### B10. 回滚方式

- 代码：git revert 增量提交（不含迁移回滚）
- 数据：`ext_*` 三表独立，禁用功能（`enabled=0` 或摘掉路由）即可停用，不影响旧表
- 迁移：v15 只 `CREATE TABLE IF NOT EXISTS`，不改旧表结构，可安全向前
- 部署：沿用 scp → `chmod 644` + `chown ayana:ayana` → `systemctl restart ayana`

---

## 待确认事项（实施前请拍板）

1. **UI 位置**：独立 Tab「外部事务」，还是放进「事件」子页？（方案默认独立 Tab）
2. **Token 形态**：每事务多 Token（可并存轮换），还是单 Token 轮换即失效？（方案默认多 Token + 吊销）
3. **失联宽限**：`expect_interval + max(timeout, 300s)` 是否合适？
4. **删除事务**：存在历史 run / open incident 时，是「仅禁用」还是允许硬删？（方案默认：有 open incident 禁止删，仅可禁用）
5. **首个接入**：确认阶段 D 只做 FNBK 采集脚本，`mysqlbk` 是否一并接入（同一脚本多任务即可，建议一并）？

确认以上后进入阶段 C 实现。


---

## 阶段 C 实现备注（2026-10-19）

在原 B 方案基础上，按 OneUptime 对照结论与最终确认做了如下**增量**（不改 Episode/Incident/Outbox 主链路）：

| 项 | 变更 | 兼容 |
|---|---|---|
| 恢复防抖 | 新增 `resolve_delay_sec`（默认 0=立即）+ `pending_resolve_at`；成功先记 Run，到期再关 Incident；等待期间失败取消恢复 | 默认 0 与原行为一致 |
| 调度 | `schedule` 支持标准五段 cron：`{"kind":"cron","expr":"0 0 * * 1","tz":"UTC"}`；保留 daily/weekly/interval | 旧配置仍可用 |
| 漏跑判据 | 只认服务端 `received_at`（API 当场 `now()`），不用客户端 timestamp | — |
| 上报语义 | 保持同步入库 + 诚实 HTTP 状态码；**不**采用 OneUptime 先 200 再异步 | 脚本可判断失败 |
| 历史 | 每次上报独立入 `ext_runs`，不做 coalesce | — |
| 安全 | Token 仅 Bearer；哈希存储；审计/事件/run 不含明文 | — |
| UI | 「事件 → 外部事务」子页：列表/详情/表单/Token/API 示例 | 中文，复用现有样式 |

`ext_watch_marks` 仍用于超时/漏跑幂等；`watch_tick` 新增 `recovered` 计数处理防抖到期。
