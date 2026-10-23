# 授权与操作链路说明

## 职责与状态

| 组件 | 事实源与职责 | 状态与下一步 |
| --- | --- | --- |
| Policy | 现有权限、能力目录、Agent ceiling；统一三态 | 禁止 / 等待确认 / 自动执行 |
| Agent / Runbook | 确定规则、前置条件、预算预检；决定执行、等待或找人 | 冷却/额度等待不得伪装成缺少授权 |
| ApprovalService | 解析人类三选项，选择唯一当前提案，永久授权与批准同事务 | 执行一次 / 不执行 / 永久允许执行 |
| ActionService | 提案、批准、拒绝、唯一派发领取及验证义务 | proposed → approved → dispatched → success/failure/unknown；拒绝 → cancelled |
| IncidentService | 事件生命周期及按动作记录的人工义务 | 审批完成清对应 awaiting_approval；派发成功领取清对应 execution_blocked |

`ApprovalService` 不另写执行器。Web、QQ、企微保留已认证的人类主体，最后仍调用 `ActionService.execute`。普通批准和拒绝仍要求该人的既有目标能力权限。永久授权还要求渠道确认的管理员，不能由 Agent 代答。

## 三种人类决定

- **执行一次**：批准当前操作并执行，不修改长期权限。
- **不执行**：复用 `ActionService.reject`，记录 action_rejected 事件、审计和该代次人工拒绝义务。旧斜杠入口与新入口使用相同状态处理。
- **永久允许执行**：仅适用于 `auto_rule / agent` 提案。为对应 capability + asset + object 建立精确权限，不修改广域权限或人类权限。现有效 allow 必须已为真，目录和 ceiling 必须允许自动，控制面禁止授权。仅该精确权限设 `auto_allowed=1, require_approval=0`，才符合 Policy 的 automatic 语义；`allow=0` 和无授权不能借此放宽。

永久授权与 approve 在无网络等待的同一短事务中提交。任何一项失败，两项一起回滚。审计 `permission_auto_allowed_granted` 保存实际人类身份、渠道、动作、精确目标和 before/after，配置历史同样可追溯。随后执行当前操作时保持人工审批身份与 manual 模式，以后新提案按更新后的 Policy 判定。

回复只按完整句匹配，引用、否定、混合三种决定的文字不触发授权。无明确操作绑定时，必须只有一条有效当前 proposed；多条提案要求人在事件详情选择。过期、已关闭或属于旧代次的提案不参与选择。

## 派发前复核与竞态

`action_incident_block(store, action)` 同时供审批、候选选择和最终派发短事务使用。它复核事件仍 open、资产/对象绑定一致，以及动作属于当前代次。代次事件与 action_proposed 事件的先后采用事件序号，避免时钟时间戳相同时漏判；缺少历史提案事件时才回退时间判断。

身份核验存在网络等待。即使批准时事件有效，核验结束后也必须重查，防止目标已经恢复、事件已经关闭、代次递增或对象绑定改变后派发旧操作。恢复或关闭时只取消尚未领取的 proposed/approved，保留 dispatched/unknown，避免将未确认的执行误作未执行。

最终派发门保留身份、当前 Policy、权限撤销、期限、登记对象、命令绑定、对象锁、runbook/模板版本、自动验证契约、全局暂停和预算检查。所有 `mode=auto` 操作都在此强制检查控制面标记，包括绕过 runbook 匹配直接建立的自动操作；检查对象 ID、名称、unit 和 container。人工模式保留明确人类批准语义。

## 预算与执行前失败

Agent 预检和事务内派发门共用 `runbook.auto_budget_state`。统一读取 actions 中已派发的 dispatched/success/failure/unknown，使用派发时间（缺少时回退创建时间）计算滚动 24 小时额度和冷却，规范化对象名称与 ID。拒绝、取消及过期且从未派发的提案不占预算；unknown 继续占预算且不得重放。

若执行前身份门等暂时失败，操作仍 approved，不重复审批。仅当其事件仍为当前 open 代次时，记录 `execution_blocked:<action_id>` 人工义务和审计，供 Web 的“继续执行”入口处理。真正派发领取成功时仅清除此动作的 execution_blocked，保留其他人工义务。dispatched、unknown 或其他终态禁止再次派发。

自动处置的冷却、额度、全局暂停、对象占用和普通来源不可用由 Agent 等待重试，不设置上述人工执行义务。来源暂时不可用返回 `source_unavailable`，来源隔离返回 `source_quarantined` 并硬停。Agent 在重试前通过 `safe_cancel_pending_auto` 原子取消自己尚未派发的 proposed/approved，并仅清对应执行阻塞义务；已派发或结果不明的操作绝不转为可重试。

## 验证

`tests/test_approval_protocol.py` 使用真实 SQLite、Policy、ActionService 与假运输，不访问生产。31 项覆盖三选项、人类身份与审计、精确永久权限、审批要求转换、allow 禁止、ceiling、控制面、原子回滚、歧义、过期、旧代次、目标恢复、重复请求、恢复/换代/对象变化发生在身份核验等待期间，以及执行前失败后只审批一次、只派发一次的人工继续路径。另覆盖来源不可用与隔离分流、自动软阻塞不转人工，以及安全取消不会触及已派发、unknown 和人工操作。

另与现有 Policy、权限模型、runbook 边界和执行安全测试合并验证，确认新协议沿用原有最终安全门。
