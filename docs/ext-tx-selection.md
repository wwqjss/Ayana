# 外部任务上报：选型评估（阶段 C 中止后的研究结论）

> 状态：仅研究与评估，**不改代码、不装服务、不部署**。
> 对比对象：Healthchecks.io、Sentry Crons、Uptime Kuma，以及 Ayana 已有阶段 C 实现。
> 优先目标：最小实现、低维护成本。

---

## 1. 三者在「外部任务上报」上的实际做法

### 1.1 Healthchecks.io（开源可自托管，协议最干净）

核心模型是 **dead man's switch**：任务主动 HTTP ping，按时到就静默，迟到就告警。

| 维度 | 做法 |
|---|---|
| 上报协议 | `GET/POST/HEAD /<uuid>` = 成功；`/start` = 开始；`/fail` = 失败；`/log` = 只记日志；`/<exitcode>` = 0 成功非 0 失败 |
| 执行标识 | 查询参数 `rid=<uuid>`，把 start 与结束配对，计算耗时 |
| 身份 | URL 里的 UUID 或 `project-ping-key/slug`（可 auto-provision） |
| 状态机 | `New → Up → Late → Down`，另有 `Paused` |
| 心跳/漏跑 | Simple：`Period + Grace`；Cron：`cron 表达式 + 时区 + Grace`；OnCalendar：systemd 日历 |
| 超时 | 若发过 `/start`，`Grace` 内没等到成功 → 判失败 |
| 告警去重 | **状态转换才发**：进 Down 发一次，停留 Down 不重复发；恢复再发一次 |
| 载荷 | POST body 最多 100KB，可存日志 |
| 自托管 | Django + PostgreSQL/MySQL + `sendalerts` 进程 + Docker 镜像 |

要点：协议极简（一条 curl 就能上报），调度语义（cron + grace）成熟，去重靠状态转换而不是消息条数。

### 1.2 Sentry Crons（指标最全，但绑定 Sentry 平台）

| 维度 | 做法 |
|---|---|
| 上报协议 | `GET/POST .../cron/<slug>/<key>/?status=in_progress\|ok\|error` |
| 执行标识 | `check_in_id`（重叠任务必须自备稳定 ID，语义上就是我们的 `run_id`） |
| 状态机 | in_progress / ok / error；missed（未按计划 check-in）/ failed（超时） |
| 调度 | `monitor_config` 可 upsert：`crontab` 或 `interval`，另有 `timezone` |
| 宽限 | `checkin_margin`（迟到多久算 missed） |
| 超时 | `max_runtime`（start 后多久算 failed） |
| **告警去重** | `failure_issue_threshold`：连续 N 次失败才开 issue；`recovery_threshold`：连续 M 次 OK 才恢复 |
| 告警落地 | 生成 error event，走 Sentry Alert Rules |
| 自托管 | 官方 SaaS 为主；自托管 Sentry 是 Kafka/ClickHouse 级重栈 |

要点：`failure_issue_threshold` / `recovery_threshold` / `check_in_id` 三个概念非常值得抄进设计；但平台本身过重。

### 1.3 Uptime Kuma（自托管友好，但模型不匹配）

| 维度 | 做法 |
|---|---|
| 上报协议 | Push 型：`GET/POST /api/push/<token>?status=up\|down&msg=...` |
| 执行标识 | 无 run_id |
| 状态机 | up / down / pending |
| 心跳 | 只有「每 N 秒应收到一次 push」，**无 cron 计划、无「周一 00:00 漏跑」语义** |
| 超时 | 无 start/end 配对，无法测单次执行时长 |
| 告警去重 | 状态转换触发通知 |
| 自托管 | Node + SQLite，Docker 一行起 |

要点：适合「进程还活着吗」，不适合「备份任务本周一有没有按时跑完」。Push 只是附带能力。

---

## 2. 四个评估问题

### 2.1 有没有可直接复用的轻量组件或协议？

| 候选 | 结论 |
|---|---|
| **Healthchecks Pinging API 协议** | **值得借用（协议层）**：`/start` `/fail` `/<exitcode>` + `rid`，脚本一行 curl。不必装它，只抄 URL 形态与语义。 |
| **Sentry check_in_id / 阈值** | **值得借用（语义）**：稳定 run_id；连续失败 N 次才告警、连续成功 M 次才恢复——比「每次失败都叫」更贴近「防轰炸」。 |
| **Uptime Kuma push** | 不够用：无计划调度、无 run 级状态。 |
| **Healthchecks 自托管整装** | 不建议作为组件嵌入：独立 DB、独立 sendalerts、独立通知渠道配置。 |
| **Sentry SDK/服务** | 不建议：为 2–3 个备份任务挂上整套 APM。 |
| **Ayana 现有 Episode/Incident/Outbox** | **已经是可复用组件**：fingerprint 稳定 → 持续失败共用 episode；`dedup_key` UNIQUE → 通知幂等；生命周期事件驱动恢复通知。 |

**结论：没有值得“整装引入”的第三方组件；有两套协议语义值得吸收。**

### 2.2 自建最小上报入口的代码量与维护成本

阶段 C 已落地（未部署）的大致规模：

| 模块 | 约略规模 | 职责 |
|---|---|---|
| `exttx.py` | ~600 行 | 校验、Token、状态机、Episode 收敛、心跳/计划漏跑 |
| `db.py` 迁移 v15 | ~90 行 | 4 张新表 |
| `web.py` 路由 | ~180 行 | `/api/ext/*` 上报 + 管理 |
| `main.py` | ~20 行 | 装配 + `_bg_ext_watch` |
| `tests/test_exttx.py` | ~550 行 | 37 项，已全绿 |
| UI | 骨架已挂到「事件」子页 | 列表/详情/表单未写完 |

**维护成本判断：低。**

- 落在同一 SQLite、同一迁移机制、同一 Episode/Incident/Outbox/审计，没有新进程、新库、新通知栈。
- 真正需要长期维护的是：状态机边界用例 + 漏跑时钟计算。这两块测试已覆盖主路径。
- 相比之下，多养一套 Healthchecks/Sentry/Uptime Kuma = 多一个进程、一套账号、一套通知渠道、一套升级与备份策略。

粗算：把现有实现砍到「Healthchecks 同等能力」约 **250–350 行核心 + 测试**；保留 run_id 状态机与 collector/business 区分则约 **500–600 行**——与现状同量级，不值得为省几百行去接一个新服务。

### 2.3 引入第三方会不会反而增加复杂度？

| 方案 | 部署 | 集成到 Ayana | 通知 | 总评 |
|---|---|---|---|---|
| Sentry Crons | SaaS 或极重自托管 | 出网 / 数据在外 | Sentry Alert → 再转发 Ayana 或重复通知 | **复杂度最高** |
| Uptime Kuma 自托管 | Docker/Node，中等 | Webhook → Ayana，或双写 | **两套通知**，易双报/漏报 | 中高，且模型不对 |
| Healthchecks 自托管 | Django+DB+sendalerts，中等 | Webhook → Ayana，或 Ayana 只做展示 | **两套通知** | 中等 |
| Healthchecks.io SaaS | 零部署 | Webhook 回调 | 同上 | 中等 + 数据出内网 |
| **Ayana 自建最小入口** | **零新增** | 一体 | **一套 Outbox** | **最低** |

家宽/NAS 环境（KANATA）尤其不适合再叠 Sentry/双通知栈：故障时要能一眼看出是备份失败、采集异常，还是监控栈自己挂了。

### 2.4 阶段 C 哪些可以简化或删除？

对照 Healthchecks/Sentry 的「最小充分集」：

**保留（需求硬约束或已有测试收益）**

1. `run_id` + **合法状态转换**（`success` 终态不可被迟到 `failure` 覆盖）——比 Healthchecks 的 rid 更严，正是你点名要的。
2. **采集异常 ≠ 业务失败**（`report_kind=collector`）——FNBK 库不可读必须报监控异常，不得判成功也不得判备份失败。
3. Token 多把并存 / 独立吊销 / 无中断轮换。
4. Episode → Incident → Outbox 复用（去重、恢复通知已在现有生命周期里）。
5. 有未关闭 Incident 禁删、只许禁用。

**建议简化**

| 现状 | 建议 | 理由 |
|---|---|---|
| `schedule_json` 自定义 daily/weekly/interval | 改为标准 **cron 表达式 + 时区**（可选 simple interval），与 Healthchecks 对齐 | 少维护一套日历语义；FNBK 周一 00:00 就是 `0 0 * * 1` |
| 五个 `alert_on_*` 开关 | 收敛为 `alert_on` + 可选 `alert_on_missing` | 多数场景全开/全关；减少 UI 与测试矩阵 |
| `severity` 由上报方随意指定 | 由 problem 类型推导（failure/collector→warning，连续阈值后→critical） | 避免采集端乱写 severity |
| 自定义 `watch_mode=heartbeat/schedule` 双模式 | **保留**，但 schedule 换成 cron | 两种模式是真实需求（守护进程 vs 计划任务） |
| UI 的 API 示例区、复杂 Token 轮换向导 | 延后到验收后 | 不影响闭环 |

**建议删除/不做**

1. **不引入** Healthchecks 自托管/Sentry/Uptime Kuma 作为组件（理由见 2.3）。
2. **不做** 完整 Healthchecks Management API 兼容层（项目/团队/徽章/Prometheus 端点都无需求）。
3. **不做** 双通道上报（既收 JSON 又收 HC 风格 path ping）——除非阶段 D 脚本确实更爱 curl；若做，也只做 `/fail`、`/<exitcode>` 两个糖。
4. **删掉** 若有「旧结果用客户端时间戳排序覆盖」的残留逻辑——已由合法状态转换取代，时间戳只做展示与幂等指纹。

**阶段 D 脚本侧对齐 Healthchecks 习惯即可**（一条 curl 上报，`run_id` 用 `fnbk:{task}:{op}`），无需改协议。

---

## 3. 明确选型建议

```
┌─────────────────────────────────────────────────────────┐
│  选型：Ayana 自建最小上报入口（继续阶段 C 精简版）         │
│                                                         │
│  协议语义：借 Healthchecks（start/fail/exitcode + rid）  │
│  告警阈值：借 Sentry（连续 N 次失败才开 / M 次成功才关）   │
│  事件与通知：100% 复用 Ayana Episode / Incident / Outbox │
│  第三方：不引入（Sentry 过重，Kuma 模型不符，HC 双栈）    │
└─────────────────────────────────────────────────────────┘
```

**一句话：继续自建，把阶段 C 做“瘦”，不要为省几百行代码去养第二套监控。**

### 推荐落地顺序（待你确认后执行）

1. **简化阶段 C**（半天级）：cron 调度、收敛告警开关、去掉冗余 severity 策略；测试跟着收。
2. **补阈值语义**（小）：`failure_threshold` / `recovery_threshold`（默认 1 / 1，保持现行为）。
3. **阶段 D**：FNBK + mysqlbk 同一只读采集脚本，上报即 curl/HTTP 一行。
4. **验收**按原清单跑。

### 明确不选的方案（及原因）

| 方案 | 不选原因 |
|---|---|
| Sentry Crons | 为 2–3 个备份任务引入 APM 级平台；数据出内网；告警不进 Ayana Incident |
| Uptime Kuma | 无 cron 漏跑、无 run_id；通知与 Ayana 重复 |
| Healthchecks 自托管 | 能力对口，但多一套进程/库/通知/升级；与 Ayana 双写状态无收益 |
| Healthchecks.io SaaS | 同上 + 备份状态出内网 |
| 只写脚本直推企业微信 | 无状态机、无 Incident 关联、无幂等、无审计，扩展到 MySQL/证书时会崩 |

---

## 4. 与 Ayana 现有架构的契合度（自查）

| 需求 | Ayana 现有机制 | 是否够用 |
|---|---|---|
| 失败首报、持续不轰炸 | episode fingerprint 稳定 + Outbox `dedup_key` | 够 |
| 失败后恢复通知 | `incident_resolved` ∈ `LIFECYCLE_TYPES` | 够 |
| 超时/失联 | `_bg_ext_watch` + `ext_watch_marks` 幂等 | 够（实现中） |
| Token 鉴权 | 哈希存储、吊销、轮换，模式同 recovery code | 够 |
| 审计 | `db.audit()` | 够 |
| 采集异常 | `report_kind=collector` 独立 problem 族 | 够（自建优势） |
| 不新建告警引擎 | 全部走 Episode→Incident→Outbox | 满足 |

---

## 5. 来源

- Healthchecks.io Docs — Introduction / Pinging API / Configuring Checks / Compared to Sentry  
  https://healthchecks.io/docs/  
  https://healthchecks.io/docs/http_api/  
  https://healthchecks.io/docs/configuring_checks/  
  https://healthchecks.io/docs/healthchecks_sentry_comparison/
- healthchecks/healthchecks（BSD-3，Python/Django）  
  https://github.com/healthchecks/healthchecks
- Sentry Crons — HTTP Check-Ins  
  https://docs.sentry.io/product/monitors-and-alerts/monitors/crons/getting-started/http/
- Uptime Kuma（MIT，Node）  
  https://uptime.kuma.pet/  
  https://github.com/louislam/uptime-kuma

> 注：Uptime Kuma 的 Push 细节部分来自仓库公开行为与 wiki 目录，页面未稳定渲染出独立 Push 文档；其「无 cron / 无 run_id」结论与产品定位一致，若你要求逐行核对可再挖源码。
