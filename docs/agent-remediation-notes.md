# Agent 自动处置审计与状态约定

审计范围：`agent.py`、`runbook.py`、`main.py`，以及与 `actions.py` 最终派发门、Incident 生命周期和通知义务的接口。保留原有未提交工作，在现有边界内收拢判断，不替换整套状态机。

## 职责

| 模块 | 负责的事实/决定 | 不应承担的职责 |
| --- | --- | --- |
| AlertIngest / IncidentService | 告警来源、当前故障代次、恢复/关闭、并行人工义务 | 根据暂时限速伪造权限不足 |
| InvestigationService | 有限只读调查；真实观察与运输失败分开 | 通过 LLM 文字扩大写权限 |
| RunbookRule | 固定能力与对象匹配、结构化前置阻塞；共享自动预算计算 | 直接执行或批准操作 |
| Policy | forbidden / approval_required / automatic 的唯一权限决定 | 把冷却时间解释成权限问题 |
| AgentLoop | 当前代是否需要调查、等待、请求授权或自动提案 | 越过 ActionService 写入执行状态 |
| ActionService | 提案/决定审计；身份等待后短事务复查；唯一派发、预算领取、不可重放 | 将暂时派发拒绝解释成必须人工批准 |
| Notifier | 以事件建立各渠道/收件人 outbox 义务、幂等重试与补偿 | 通知异常反向改变已完成的执行结果 |
| `_bg_agent` | 选取当前可处理事件、清理到期提案 | 让尚未到重试时间的旧事件占满处理名额 |

## Agent 状态转移

| 条件 | 事件/操作结果 | Incident 下一状态 | 后续责任 |
| --- | --- | --- | --- |
| 当前代已有有效 Action | `skipped_prior_*` | 交由现有操作/验证/人工流程 | 不再重复调查提案；调度阶段直接排除 |
| 当前代已有人工拒绝审计 | `skipped_rejected` | 保留人工决定 | 本代不再提案；新代按新边界处理 |
| 冷却、24 小时预算、缺新鲜失败探测、暂时通道/来源不可用、全局暂停、普通对象占用 | `agent_waiting` / `waiting_precondition`；不创建 Action | `open / watching / need_human=0` | `retry_at` 到期重查；重启从事件恢复等待 |
| 控制面对象、无验证契约、匹配不一致、对象存在结果未知的写入 | `agent_escalated` | `need_human=1` | 补配置/核清，不自动重放 |
| Policy forbidden | `agent_escalated`，零提案零派发 | `need_human=1` | 不通过审批按钮放宽显式禁止 |
| 真实缺自动权，或自动处置开关关闭 | manual/proposed + 唯一 `proposal_waiting` | `awaiting_approval / need_human=1` | 执行一次/不执行/永久允许执行协议 |
| automatic + 自动开关开启 + 全部前置满足 | auto/proposed → approved → ActionService.execute | 交由执行/验证流程 | 最终派发门仍重查当前事实 |
| 身份等待后遇到冷却/预算/全局暂停/普通锁/临时来源竞态 | 通过 CAS 安全取消未派发操作，只清该操作的阻塞义务，再 `agent_waiting` | `watching / need_human=0`（其他人工义务保留） | 到期重新调查；零实际写入 |
| 派发结果 unknown | 保留原 Action 与锁 | 人工核清 | 禁止自动重放 |
| 本代验证失败 | 验证历史 + 人工义务 | 本代需人工 | 防止对同一故障无限重启；恢复后新代可重试 |
| 来源明确确认恢复 | 由 IncidentService 闭环「目标已恢复」 | `resolved / done` | 旧验证迟到不得重新污染当前状态 |

`agent_waiting` 的 `generation`、`rule`、`blockers`、`reasons`、`reason`、`retry_at`、`body` 持久化在事件中。同代同一种阻塞复用事件并更新下次检查时间，通知只建立一次义务。新故障代次不继承旧等待。

## 修复的确定冲突

1. **automatic 被降级为人工提案。** 原逻辑把除少数硬停止外的一切前置失败都交给 `_propose_for_human`。现按结构化 blocker 分流，限速只等待，不再伪装权限审批。
2. **预算存在两个事实源。** Agent 原读 `audit_log.agent_auto_exec`（执行返回后写），Action 最终门读 actions（派发时写），时间和计数均可能不一致。现共用 `auto_budget_state`，以已派发的 auto Actions 为准，按派发时间计算滚动 24 小时与冷却，unknown 同样占预算。最终门继续在短事务内调用，保留原子领取。
3. **对象锁名字不一致。** Incident 保存短名称，Actions 保存对象规范 ID；Agent 原按短名称查询而漏锁，最终门又拒绝并转人工。现前置查询统一对象 ID；待验证/进行中操作等待，unknown 明确人工核清。
4. **窗口里的旧失败盖过最新恢复。** 原条件只需过去 180 秒存在任意失败。现只使用有时间戳且新鲜的最新样本，最新已成功时不重启。
5. **服务状态前置永远不可满足。** `require_service_state` 原上下文固定 None；现读取当前调查里同对象的 observed 证据，并将该条件纳入 runbook revision，配置变更不能绕过已有提案契约。
6. **调度饥饿。** 原查询只取最旧三个，等待或已有有效操作的事件可反复占位。现先排除未来重试事件及当前代已有有效 Action，再取本轮名额。
7. **旧代提案复用。** `_propose_for_human` 原查已有 proposed 时未限定代次。现使用当前 generation 的事件时间边界。
8. **通知异常改变执行结果。** 处置成功后发送异常原可落入执行 catch 并标人工。现先存事件义务，发送异常只交给补偿；授权/等待/自动完成/升级均使用 `enqueue_for_event`。
9. **短暂来源不可用与隔离混淆。** Agent、提案入口与最终门现统一区分 `source_unavailable`（等待）和 `source_quarantined`（人工硬停）。自动执行遇到可重试原因不新增永久人工义务，未领取动作安全取消后再调度。
10. **同时间戳代次边界。** 当前代动作和人工拒绝复用 Action 层 `action_incident_block`，优先按 generation/action_proposed 事件 ID 顺序辨别，旧导入数据才按时间兜底，避免 Windows 时钟精度导致旧代拒绝挡住新故障。

## 保留的安全复查与不变量

- Agent 的前置检查用于及时解释与调度；ActionService 在身份核验等待后重验 Policy、来源、绑定、runbook revision、对象、全局暂停、预算和占用，属于必要的时序安全门，不能删除。
- 只有 satisfied 的自动路径创建 auto Action。控制面对象（含 Ayana）不能匹配自动 runbook；unknown/dispatched 写入不能重放。
- 未派发的 rejected/cancelled/expired 操作不消耗派发预算。普通取消/过期不永久阻止新提案；人工拒绝由本代审计明确阻止重复打扰。
- 自动开关关闭时继续调查，允许形成需要显式决定的 manual 提案；不触发自动派发。
- 三态 Policy 不因临时前置变化而改写；永久允许仍受 allow、管理员资格、控制面、契约和最终派发门约束。
- `proposal_waiting` 每个 Action 一条事件；`agent_auto_exec`、`agent_escalated` 均带 `generation/body`，通知补偿不依赖重新拼接内部 ID。
- 已批准而未派发的动作在恢复/关闭时应被取消；已派发/unknown 保留执行事实与对象锁，不因通知或 Incident 展示状态而重放。

## 遗留数据与审计提示

- 已由旧逻辑错误生成的 `manual/proposed + awaiting_approval` 不做全局自动迁移。`auto_enabled=False` 也能合法形成 automatic policy 的人工提案；部署时只处理已核实由冷却误降级的具体操作。
- 来源 quarantine 保持人工隔离；临时不可用由 Agent 与最终派发门使用同一可重试错误集合处理。
- Notifier 补偿同时检查当前代操作是否已取代等待，以及升级原因是否仍在当前人工义务中，避免已执行后发送「冷却中」或发送已被替换的旧人工原因。

## 验证

`tests/test_agent_deferred.py` 覆盖冷却到期恢复、滚动日预算、规范对象 ID、缺探测、全局暂停与执行前竞态、同代拒绝、新代重入与相同时间戳、调度饥饿、控制面、最新恢复探测、服务状态条件、未知写入、验证占用、自动开关、临时来源恢复、未派发操作清理、持久通知及通知异常隔离。`test_agent_notification_lifecycle.py` 验证执行后等待通知、义务替换后旧升级通知均取消发送。Phase B 的暂停断言同时验证零派发和解除后可重新调度。
