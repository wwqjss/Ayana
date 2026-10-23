# 三省制投票箱与执行边界

`CouncilService` 负责确定性授权，不负责模型网络访问。中书省只能提交调查证据与修复方案；Kimi 和 DeepSeek 只能提交结构化意见。现有 `ActionService.execute()` 仍是唯一写入派发通道。

## 数据与生命周期

数据库迁移 16 新增 `council_goals`、`council_plans`、`council_reviews`、`council_ballots`、`council_grants`、`council_steps`；现有 Action 增加 `council_grant_id`、`council_step`。旧数据不转成授权。

方案按同一 Incident generation、登记资产、登记对象归并到固定 `restore_registered_object` 目标。模型提供的目标名称不影响目标标识或封驳次数。方案最多八步，每步只有目录 capability 和固定参数；当前目录不接受参数覆盖。服务名和命令必须由登记对象和能力目录解析，模型不能提供自由命令。

每份方案固定 evidence、rationale、scope、rollback、verification、精确 argv、有效期、generation 和版本，并对规范 JSON 计算 SHA-256。数据库触发器禁止修改方案正文与绑定字段。修改方案必须建立新版本；旧待执行授权立即撤销。方案最长有效 1800 秒，默认 600 秒。

方案同时固定真正执行的独立验证 profile 全文；执行前如果验证契约变化必须重新会审，模型的验证描述不能替代后端契约。

公开验证契约将目录模板的目标占位符展开为精确 `asset` / `service`，并在测试中与 Action 实际写入的 Verification criteria 比对。方案还包含后端生成的 `policy_at_draft` 与 `backend_preconditions`，让委员能区分当前权限证据、执行前必查条件和待执行操作；这些说明不会赋予额外权限，真正派发仍重查实时状态。

主要状态为 `drafted → reviewing → approved/vetoed/failed/stale → executing → verifying → completed/verification_failed`。`completed` 表示独立验证通过，业务结案仍由原 Incident 收敛机制决定，不能单独覆盖仍在 firing 的告警。

## 独立会审

编排器必须使用实际配置的 ProviderClient 身份调用 `begin_review()`，不能使用模型输出的 provider/role。第一席只接受 `reviewer_kimi` + `kimi/moonshot`；第二席只接受 `reviewer_deepseek` + `deepseek`。返回的请求凭据固化 role、provider、model、plan digest 和 deadline。凭据只能记录一次终态结果；重复回调不能更改投票。

`record_review()` 严格接受以下字段，不接受模型自报角色或授权：

```json
{
  "approve": false,
  "reason": "端口当前归属尚未核对，重启目标证据不足",
  "missing_evidence": ["登记端口的监听与进程证据"],
  "suggested_revision": "先补充端口与服务状态，再提交新方案"
}
```

`approve` 必须为真正布尔值，理由必须非空。`tally()` 只在两份指定独立席位意见对应同一版本、摘要、均有效且均同意时创建授权。API 错误、超时、异常格式、缺票均不放行。有效否决每个方案版本只累计一轮，两个否决不会算两轮；调用错误不算实质封驳。连续三轮封驳固定目标后，建立人工裁决屏障。

管理员可以在既有身份认证、CSRF 与二次验证保护的管理端点调用 `release_manual_barrier()`。该操作只允许重新拟旨会审，不更改旧投票、不批准旧方案、不消除未核清写操作。

中书省主动请求人工时，`request_manual_adjudication()` 同样持久化规范目标的人工屏障，即使当时没有修复方案也不会在下一轮自行恢复自动写入。

## 一次性授权与 Action

授权绑定 Incident、generation、登记资产与对象、方案摘要、逐步命令和有效期。`execute_grant()` 原子领取一次授权后，逐步通过 Action 的 `reviewed` 模式提交；每一步 Action 和步骤领取状态在同一短事务中写入。后续步骤必须等此前步骤确定成功，任意失败或未知都停止后续写入。

`reviewed` 模式不能通过普通 `approve()` 批准，必须有对应步骤专属授权。执行身份仍为受 Agent ceiling 约束的 `auto_rule:agent`，执行时 Policy 必须明确允许自动执行。两票同意不能覆盖默认拒绝、人工审批要求、全局暂停、控制面保护、来源健康检查、独立验证契约或主机身份校验。

身份核验的网络等待后，Action 在派发事务中重新检查当前 Incident 状态、generation、对象登记、精确命令与参数、授权期限、当前 Policy 和步骤状态。审议期间恢复、模型改方案、对象改名或 Policy 撤权均不能派发过时修复。

同一事务还检查管理员持久化的 Agent 自动执行开关与自治模型开关。审议已通过后关闭任一开关，或者在主机身份核验等待期间关闭，都会阻止新 `reviewed` 写派发；原 Runbook 通道沿用原有开关规则。

Runbook 与审议执行共同统计同一对象、同一能力的已派发次数，失败和 unknown 同样计数。匹配现有 Runbook 时沿用其冷却和每日次数；无对应规则时保守使用每能力三次/24 小时、1800 秒冷却。不同能力拥有各自限制，因此重启耗尽仍可继续只读调查，也可在独立 Policy 许可及双票审议后执行其他已登记能力。修改命令字符串不是新能力。

多步方案的各步仍建立独立 Verification 记录。全部写入结束后统一调度原有验证器，避免第一步的恢复验证抢在后续步骤前判断业务恢复。期间对象锁阻止其他写操作，只允许同一授权中按顺序、精确绑定的后续步骤继续。SSH 返回成功不代表验证通过。

后续方案全部独立验证通过后，只核销同 generation、同登记目标、早于此方案的 `verify_failed` / `verify_inconclusive` 技术义务。`verify_unknown`、人工拒绝、人工裁决屏障以及其他目标或其他代次的义务保持不变。核销之后仍由原 Incident 收敛机制检查告警和恢复证据，不能直接假定业务结案。

同一条件下，旧 Agent 自动产生的精确 `no_runbook_match`（可带 ` | llm:` 说明）也会核销并审计；它表示旧执行器能力不足。包含其他语义的相似理由、Policy 拒绝和人工决定不在此清理范围。

## 重启与故障恢复

启动时 `recover_inflight()` 将未完成审议标记失败、撤销未领取授权；进行中的多步执行转人工，不恢复执行游标。已派发但结果不明的 Action 标记 unknown，保留不可自动重放语义；尚未派发的旧步骤取消。已经进入独立验证的计划由既有 Action 验证恢复机制继续检查，不能再次派发命令。

管理员解除三次封驳屏障不等于核清 unknown；unknown 仍受原 Action 人工裁决和对象锁保护。

## 本地验收

`tests/test_council_security.py` 使用模拟 SSH、模拟委员结果和持久 SQLite，覆盖两票同意、单/双否决、三轮人工、委员失败/超时/异常结构、身份冒用、重复回调、方案变更、generation 更新、恢复/对象变更发生在身份等待期间、过期、重复执行、unknown 不重放、重启、冷却后的独立调查与其他能力、精确多步及首步失败中断、Policy 人工要求、参数篡改和独立验证。测试不调用付费模型、不访问生产环境。

新增能力仍须显式加入能力目录、验证 profile、Policy 和主机固定命令白名单。审议通过不能自行扩大任一层权限。

新目录工具通过真实 `SSHTransport` 的命令组装、读写账号选择及严格主机指纹校验测试，测试仅模拟最终进程和主机公钥探测，没有连接生产。主机 sudo/forced-command 白名单由部署方独立配置，源码不会自动添加 `reload` 或 `reset-failed`。登记目标拒绝选项形态、通配符、路径分隔和控制字符，防止 `systemctl reset-failed --all` 或模式匹配扩大影响范围，正常 `foo@instance.service` 单元保持可用。

`service.config` 只读取固定的文件位置、运行配置及启动/重载能力属性，不读取 Environment、ExecStart 或 ExecReload 原始值，减少命令参数秘密进入模型的机会；现有日志仍需要有界脱敏，不能保证识别任意位置参数中的秘密。
