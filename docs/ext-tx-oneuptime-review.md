# OneUptime 源码对照：Incoming Request Monitor → Ayana 外部事务

> 状态：只读研究，**不改 Ayana 代码**。
> 源码来源：`https://github.com/OneUptime/oneuptime`（master，浅取关键文件）。
> 对照基准：`docs/ext-transaction-design.md` + 阶段 C 已实现的 `exttx.py`。

---

## 1. OneUptime 是怎么做的

### 1.1 产品定位（文档）

Incoming Request Monitor 一个类型干两件事：

1. **Heartbeat / dead man's switch** — cron/脚本按计划 ping，停报即告警
2. **收别的系统的告警** — Alertmanager/Grafana POST JSON，转成 Incident，恢复时自动关

同一种 Monitor，差别在 **Criteria 配置**。

### 1.2 上报入口（`Telemetry/API/IncomingRequestIngest/IncomingRequest.ts`）

```
GET|POST /incoming-request/:secretkey
（文档也写 /heartbeat/YOUR_SECRET_KEY）
```

关键行为：

| 点 | 做法 |
|---|---|
| 鉴权 | **只有 URL 路径里的 secret key**，无 Header/Token |
| 响应 | **立刻回 `200 {}`，再异步入队**；错误 key / 已删 / 已禁用 **也是 200** |
| 到达时间 | 在入口就写入 Redis（`IncomingRequestReceivedAtStore.advanceIfTracked`） |
| 处理 | 入 Telemetry 队列，worker 里再校验 monitor、评估 criteria |
| 压缩 | 明确禁止 `Content-Encoding: gzip`（路径取不到字段） |
| Body | `application/json` 或 form；最大 50MB |

代码注释原文点破了取舍：

> "That reply is written before any validation happens, so a `200` is **not** confirmation that the request was accepted."

### 1.3 异步处理（`ProcessIncomingRequestIngest.ts`）

- **按 monitor 合并（coalesce）**：队列积压时只评估该 monitor 的**最新**请求，旧的直接丢
- secret → monitor 查找；**paused/disabled 直接跳过**（外部会一直打过来，避免白做锁/DB）
- **脱敏**：`redactMonitorSecret()` 把 headers/body 里出现的 secret 抹掉再入库（`Monitor.incomingMonitorRequest` 对 Viewer 可读）
- **用「到达时间」而不是「worker 处理时间」评估**；时钟超前则 clamp 到 now
- 最后统一走 `MonitorResourceUtil.monitorResource()`

### 1.4 漏报检测（`Workers/Jobs/IncomingRequestMonitor/CheckHeartbeat.ts`）

| 点 | 做法 |
|---|---|
| 节奏 | 每 **30 秒** 全量 sweep |
| 范围 | 仅配置了 `CheckOn.IncomingRequest` criteria 的 monitor |
| 判据 | Redis 里的**最新到达时间**（不是队列持久化时间） |
| 原因（注释） | 队列积压时持久化时间会滞后 → 曾导致「sender 还在收 200，monitor 全线 Offline」 |
| 记账 | `incomingRequestMonitorHeartbeatCheckedAt` 用**无 hook 的单语句 UPDATE**，避免每 30s 打审计/工作流 |
| 评估 | `onlyCheckForIncomingRequestReceivedAt: true`，只做「多久没来」 |

### 1.5 Criteria / 状态

- `CheckOn.IncomingRequest`（收到请求）
- `CheckOn.NotRecievedInMinutes`（**N 分钟未收到** — 源码里拼写就是 NotRecieved）
- 可配 JSON 字段 / JavaScript Expression 判成功失败
- Criteria 命中 → 改 Monitor 状态 → 声明 Incident，**Auto Resolve Incident** 开关

### 1.6 Incident / Episode 自动恢复（`IncidentEpisode/AutoResolve.ts`）

- 每分钟跑：找 `resolvedAt IS NULL` 的 episode
- 若 episode 内**全部** incident 都到 resolved 状态（按 state.order 比较）
- 可选 **`enableResolveDelay` + `resolveDelayMinutes`**：全部 resolved 后再等 N 分钟才真正 resolve episode（防抖）
- 另有 `ResolveInactiveEpisodes` 清理空 episode

### 1.7 到达时间存储（`IncomingRequestReceivedAtStore.ts`）

- Redis，key = `sha256(lower(secretKey))`（**不落明文 secret 到 key 名**）
- `setNumberIfGreater`：只前进不后退
- TTL 1 天；入口 `advanceIfTrusted` **不能新建 key**（防伪造 key 打爆 Redis）
- Redis 挂了 **best-effort 回退**到调用方已有时间，绝不拖垮请求

---

## 2. 和 Ayana 现有设计/实现的对照

| 能力 | OneUptime | Ayana 阶段 C 现状 | 评价 |
|---|---|---|---|
| 上报协议 | 路径 secret，GET/POST | `POST /api/ext/report` + Bearer Token + JSON | Ayana 更明确；Token 可吊销/轮换 |
| 同步还是异步 | **先 200 再入队**，200≠成功 | 同步校验 + 同步入库，诚实状态码 | **Ayana 更适合脚本**（见 §3） |
| 到达时间 | Redis 边沿记录 | `received_at` 在 API 当场写入 | 一致；若将来入队需保住「边沿时间」 |
| 漏跑 | 30s cron + NotRecievedInMinutes | `_bg_ext_watch` 60s + heartbeat/schedule | 等价 |
| 计划任务漏跑 | 靠 criteria 组合，非一等公民 | `schedule`（计划时刻 + grace） | **Ayana 更贴 FNBK** |
| 超时 | start 语义弱，靠 criteria | `timeout_sec` + running 超时合成 | Ayana 更明确 |
| run 级状态 | **无 run_id 状态机** | run_id + 合法状态转换 | **Ayana 更强**（旧消息不覆盖终态） |
| 采集异常 vs 业务失败 | 无此区分 | `report_kind=collector` | **Ayana 独有**（FNBK DB 不可读需求） |
| 防重复通知 | 状态转换 + Episode 分组 | episode fingerprint + Outbox dedup_key | 等价 |
| 恢复防抖 | **resolveDelayMinutes** | 无 | **值得抄** |
| 合并积压请求 | coalesce 只评最新 | 无（每条 run 都记） | Ayana 要保留历史 run，不抄 coalesce |
| Secret 脱敏 | 存储前 redact + Redis key 哈希 | Token 不入库/不进日志 | 一致；message/detail 也应继续不回显 Token |
| 鉴权 | 仅 URL secret | Token + 事件绑定 + 吊销 | Ayana 更严 |
| 事件/通知 | 自有 Incident/Episode/通知 | 复用现有 Episode/Incident/Outbox | Ayana 满足「不造第二套」 |

---

## 3. 值得吸收 vs 明确不要抄

### 3.1 值得吸收（建议进方案）

| # | 点 | 建议落点 |
|---|---|---|
| A | **恢复防抖 `resolve_delay_sec`** | 事务级配置；全部相关 episode 解决后，再等 N 秒才关 Incident/发恢复通知。备份抖动一次不至于「告警→立刻恢复→再告警」 |
| B | **漏跑判定用「到达时刻」** | 已有 `received_at`；若阶段 D 采集端有队列，上报仍应带原始时间，Ayana 用它算「是否按时」 |
| C | **secret 存储/日志脱敏纪律** | 已做 Token 不落日志；再确认 `message/detail/audit` 不会回显 Token；Redis 类缓存 key 也用哈希（若以后加） |
| D | **disabled 短路** | 事务 `enabled=0` 时上报直接拒绝（已做）；采集端也别对禁用任务死磕上报 |
| E | **「N 分钟未报」作为显式一等状态** | 对应 `watch_mode=heartbeat` 的 `expect_interval + grace`；命名可对齐 `not_received_in` |
| F | **只评估该事务是否有「漏跑」类配置** | `_bg_ext_watch` 对 `watch_mode=off` 的跳过（已做）；保持 |

### 3.2 明确不要抄

| # | 点 | 原因 |
|---|---|---|
| 1 | **先回 200 再异步校验** | 脚本无法知道 Token 错、事务禁用、字段非法。Ayana 场景是少数可控采集脚本，**必须诚实返回 200/400/401/403**；需要异步时也只对「已通过校验且已落库」回 202 |
| 2 | **路径里放 secret** | 易进代理日志/Referer；OneUptime 自己都要 redact。Ayana 继续 Bearer Header |
| 3 | **coalesce 只留最新请求** | 会丢历史 run；FNBK 需要「每一次执行」的记录 |
| 4 | **JavaScript Expression 判 body** | 过重，且引入表达式执行面；采集端应上报结构化 status |
| 5 | **整套 Monitor/Probe/Incident 平台** | 与 Ayana Episode/Incident 重复 |

### 3.3 和「选型评估」结论的关系

此前 `docs/ext-tx-selection.md` 建议自建精简版、借 Healthchecks/Sentry 语义。OneUptime 源码**加强**了这一结论：

- 它比 Healthchecks 更重（队列、Redis、Criteria 引擎、Episode）
- 它的 **200-before-validate** 对运维脚本是反模式
- 它真正值得拿的是 **resolve delay** 和 **边沿到达时间** 两个细节，不是平台本身

---

## 4. 对阶段 C 的修订建议（待确认后再动代码）

1. **加** `resolve_delay_sec`（默认 0=立即）；成功上报后延迟收敛 + 延迟恢复通知  
2. **加** 漏跑告警文案统一为「N 分钟未收到上报」，与 `grace_sec` 语义写进 UI  
3. **保持** 同步 API、诚实状态码；**不要**改成 OneUptime 式 200  
4. **保持** run_id 状态机与 `report_kind=collector`  
5. **保持** Token 在 Header；审计/日志/事件 payload 继续脱敏  
6. （沿用上次选型）调度字段改为标准 cron + 时区，替代自定义 daily/weekly  

阶段 D 采集脚本对齐习惯：成功/失败都显式 POST 一次 JSON；失败带 detail；**不要**依赖「没报就是成功」。

---

## 5. 源码索引（本机只读副本/下载）

| 文件 | 作用 |
|---|---|
| `Telemetry/API/IncomingRequestIngest/IncomingRequest.ts` | HTTP 入口：先 200 再入队 + 边沿记到达时间 |
| `Telemetry/Jobs/IncomingRequestIngest/ProcessIncomingRequestIngest.ts` | 异步评估、coalesce、脱敏、disabled 短路 |
| `Workers/Jobs/IncomingRequestMonitor/CheckHeartbeat.ts` | 30s 漏报检测，判「到达时间」 |
| `Workers/Jobs/IncidentEpisode/AutoResolve.ts` | Episode 自动恢复 + resolve delay |
| `Common/Server/Utils/Monitor/IncomingRequestReceivedAtStore.ts` | Redis 到达时间（哈希 key、只前进、best-effort） |
| `Common/Types/Monitor/CriteriaFilter.ts` | `CheckOn.IncomingRequest` / `NotRecievedInMinutes` |

官方文档：  
https://oneuptime.com/docs/en/monitor/incoming-request-monitor  
https://oneuptime.com/docs/en/probe/incoming-request-ingress  

---

## 6. 一句话

OneUptime 的 **Episode 自动恢复 + 防抖延迟 + 边沿到达时间** 值得进 Ayana；它的 **200-before-validate / 路径 secret / 只留最新请求** 不要抄。外部事务继续「自建最小入口 + 复用现有 Episode/Incident/Outbox」。
