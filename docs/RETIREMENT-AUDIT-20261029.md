# 功能与旧实现盘点（2026-10-29）

10:05 后续修复：工单写操作已绑定真实工单与代次；旧 Loop 查询和页面明确区分现役事实与退役历史，且查询不再改写旧表。默认约束与原生 Agent 执行契约已同步。详见 [验收截图修复记录](ACCEPTANCE-FIX-20261029.md)。下表所保留的旧 Loop 预算代码和原始历史数据仍未恢复为现役执行调度。

本表按当前工作区核查。MiMo 已删除的旧架构没有恢复；本轮只处理会报错、会误导操作或违反账号组选择的明确遗留。生产部署结果以本次交付记录为准，本文不把静态检查当作生产验收。

核查范围：`ayana/` 的 61 个 Python 文件、11 个静态资源文件；入口注册、后台任务装配、模块引用、数据库迁移、配置与测试/文档引用。以下列出功能族，避免把同一功能的几十个接口重复当作几十项功能。

## 当前功能：保留什么、还需要你判断什么

| 功能 | 当前用途与入口 | 初步判断 | 证据 |
|---|---|---|---|
| MiMoCode 原生会话 | 一个会话完成调查、修复、验证；Web 可输入、观察、接管、停止和恢复 | 核心，保留 | `main.py` 的 `_bg_mimo_serve` / `_bg_native_receipts`；`agent_tui.py`；`native_turns.py` |
| 任务状态与中断恢复 | 将原生消息、回执、调查任务对应起来；中断不冒充完成 | 核心，保留 | `native_turns.py:111`；`duty_session.py:418` |
| SSH 账号组 | 一个全局默认，单会话可覆盖；读/写用途选同一组 | 核心，取代旧权限档位 | `agent_authority.py:22`；`duty_session.py:101`；`transport.py` 的 `_endpoint_for_channel` |
| SSH 连接、密码/密钥、主机指纹 | 保存账号与密钥引用，确认目标主机身份；缺组不能选别组代替 | 核心，保留 | `transport.py`；`credentials.py`；`web.py` 的 `/api/ssh/*` |
| `host.exec` | 模型通过所选 SSH 账号执行诊断和变更，权限来自目标账号 | 核心，保留 | `mcp_tools.py` 的 `host_exec`；`transport.py` 的 `exec_shell` |
| 写操作台账与未知结果核销 | 防止同一意图重复执行；超时/断链不能直接当失败重试；保留人工核销事实 | 核心保护，保留 | `session_bridge.py:502`、`:654`、`:687`；`exec_facts.py`；`/api/agent/write-ops/{wid}/adjudicate` |
| 告警/事件/工单 | Alertmanager 接入、归并、故障代次、人工关闭与恢复证据 | 核心，保留 | `alertmanager.py`；`incidents.py`；`main.py` 的 `_bg_reconcile` |
| 恢复证据门槛 | 验证对象、故障代次、证据新鲜度；命令成功不等于故障恢复 | 核心保护，保留 | `incidents.py:306`、`:383`、`:439`；`verify_profiles.py:146`；`checks.py` |
| 业务检查 | 服务、端口等定时检查；失败形成故障，成功提供恢复证据 | 正在使用，保留 | `checks.py`；`main.py` 的 `_bg_checks`；`/api/checks/*` |
| Prometheus 指标与资源监控 | 查询指标、主机资源与业务状态 | 正在使用，保留 | `prom.py`；`host_monitor.py`；`/api/monitor/*` |
| Prometheus 配置/Node Exporter 管理 | 规则、目标、Exporter 安装/控制/接入 | 仍可运行；是否长期保留由你决定 | `promconfig.py`；`/api/promconfig/*`；`web.py` 的 `_ne_transport` |
| 知识库 | 查询、更新、历史版本；只有 active 知识注入当前调查 | 正在使用，保留 | `knowledge.py`；MCP `knowledge.*`；`/api/knowledge` |
| QQ/企微消息、通知和 outbox | 生命周期通知、重试与投递去重；管理员监控查询 | 正在使用，保留 | `qqbot.py`；`wecom_bot.py`；`notify.py`；`channels.py` |
| Web 人工 SSH 终端 | 管理员直接终端；与模型原生会话不同入口 | 仍可运行；是否需要由你决定 | `terminal.py:240`；`/api/terminal/check`、`/ws/terminal` |
| 节点守望 | 节点心跳、失联检测与通知 | 可选功能；是否启用由现有配置决定 | `nodewatch.py`；`/api/node-watch/*` |
| 外部事务/任务上报 | 外部系统带令牌上报事务与运行结果，超时形成通知/事件 | 可选功能；是否需要由你决定 | `exttx.py`；`/api/ext/*`；`main.py` 的 `_bg_ext_watch` |
| 人工只读调查与监控自然语言查询 | `/investigate` 等收集固定诊断证据；可选辅助 LLM 解释 | 尚有真实使用路径；保留待你判断 | `investigation.py:251`、`:770`；`agent_query.py:152`；`main.py` 中 `self.investigation.llm` |
| 登录、管理员、TOTP、会话与审计 | 管理用户身份和配置权限，记录实际操作者 | 核心，保留；这不是退役的 Agent 读写档位 | `auth.py`；`access.py` 的 `_role`；`audit_log` |

## 明确遗留：已清理与本轮收口项

| 项目 | 查到的实际问题 | 本轮处理/状态 | 证据 |
|---|---|---|---|
| 普通消息仍导入已删除审批模块 | `/help`、自然语言、旧 `-c` 解析均会抛 `ModuleNotFoundError: ayana.approval` | **已修复**：移除失效导入和审批识别，普通路由正常 | 修复前 `msgentry.py:176`；新增 `tests/test_retired_message_entry.py` |
| 消息帮助宣传旧命令 | QQ 帮助仍列 `-c`、待批准动作、批准/拒绝/取消；企微设置也推荐 `-c` | **已清理**：不再宣传；旧斜杠输入保留退役提示 | `qqbot.py` 的 `HELP`、`_dispatch_authorized`；`wecom_bot.py` 的 settings 分支 |
| 不可达的消息审批分支 | 消息解析已不再产生审批结果，渠道仍保留专用审批分派 | **已清理**：删除 QQ/企微审批分支与旧数据字段 | `msgentry.py` 的 `ParsedEntry`；`qqbot.py`、`wecom_bot.py` |
| 智能填表 API 导入已删除实现 | `/api/assist/configure` 仍动态导入已删除的 `assist.py` | **已改为退役响应**，不恢复实现；普通检查表单仍保留 | `web.py` 的 `api_assist_configure`；`formspec.py` 仍被检查表单使用 |
| 指定账号组连接测试实际测默认组 | 连接测试把组名降成读/写用途，可能测错账号 | **已按组修正**；回传实际组 | `transport.py` 的 `test_connection`；后端专项测试 |
| 人工 SSH 终端跨组回退 | 找不到指定组时会选第一个可用端点 | **已移除回退**；未指定才使用全局默认 | `terminal.py` 的 `create` |
| Node Exporter 通道仍认字面 read/write | 统一账号组后可能错误判为没有 SSH，甚至走本机通道 | **已统一解析**，沿用全局默认且禁止错误回退 | `web.py` 的 `_ne_transport`；`transport.py` 的 `resolve_exec_channel` |
| 老 pending-writes 审批执行 API | 即使新 MCP 不再生成审批，历史 pending 仍能经公开接口触发执行 | **已改为 410 退役响应**；历史只读查询保留，禁止审批派发 | `web.py` 的 `api_agent_pending_approve` / `api_agent_pending_reject`；`session_bridge.py` 的旧 pending 方法 |
| 无效的 `action.execute` 模型工具 | 公开工具目录仍宣称可执行结构化动作，实际只会调用退役桩失败 | **已移出公开工具目录**；旧直接调用返回 `tool_retired` | `mcp_tools.py` 的 `TOOL_SPECS` / `action_execute` |
| 会话旧权限切换 API | 页面改为账号组后，旧 permissions 接口仍可写无效的 readonly/manual 覆盖 | **已退役为 410**，保留管理员和 CSRF 校验；使用账号组接口 | `/api/agent/sessions/{sid}/permissions` 与 `/account-group` |
| 模型工具/提示词仍写调查组和执行组 | 代码已统一组，描述仍可能误导模型选工具 | **已同步文案**：channel 只作读写用途标注，使用同一有效组 | `mcp_tools.py` 的 `host.exec` 描述；`auto_investigate.py` 的 `CONCLUSION_PROMPT` |
| 已退役功能的前端入口 | Council 历史界面、旧费用接口、动作/待写审批按钮、智能填表代码及专用模型设置仍存在 | **已清理**；保留手工表单、MiMo 模型设置和未知结果核销 | `static/app.js`、`static/settings.js`、`static/workbench.js`；185 项前端测试通过 |
| 当前项目说明仍写旧架构 | README 宣称 Policy 三态、固定 Action 执行和旧版本；智能填表文档未标退役 | **已更新 README**，智能填表文档注明历史，指向 MCP 当前接口 | `README.md`；`docs/assist-configuration.md`；`docs/mcp-operations.md` |

消息专项验证：`tests.test_retired_message_entry`、`tests.test_msgentry`、`tests.test_wecom_aibot`、`tests.test_wecom_retry_boundary` 共 **50 项通过**。测试不发送外部消息、不运行主机命令。对 61 个 Python 源文件解析相对导入，当前未发现仍指向已删除本地模块的导入；本轮修改的空白检查通过。

## 有争议或需归档后再处理：本轮保留

| 项目 | 当前状态与影响 | 建议 | 证据 |
|---|---|---|---|
| Action 历史表、验证记录与事件 | 新 ActionService 已删除，但工单详情、恢复证据和阻塞判定仍读取 `actions` / `verifications` | **保留数据和读取**。以后先定义历史展示与恢复证据替代，再迁移；不能直接删表 | `db.py:261`、`:292`；`incidents.py` 的 `_claim_recovery_with_evidence`、`reconcile`、`get_incident` |
| Council 历史表与旧迁移 | 无 Council 运行装配，部分建表迁移仍存在；历史费用/审议表可能有记录 | 可归档后清退；不自动删生产历史，也不修改旧版本迁移来掩盖问题 | `db.py:811`；`main.py` 中 `self.agent = self.providers = self.council = self.autonomy = None`；`scripts/export_retired_tables.py` 目前未完整覆盖 Council 表 |
| 旧权限列与旧设置键 | `access_mode` / `approval_mode` / override 字段和旧 stage-group 设置仍存库；权威判断已固定为账号组 | 页面和公开写入口退役后，可下一次 schema 迁移删除。旧数据先保留 | `db.py:1144`；`duty_session.py` 的 `create` / `set_settings`；`agent_tui.py:548`；`agent_authority.py:22` |
| OpsLoop 状态/失败预算/前置预算 | 二次动作执行已返回退役；`close_recovered` 仍用于带代次收尾，状态 API 仍可展示旧预算 | 保留恢复收尾；旧预算与 `note_round` 等是否删除需明确新的模型轮数口径 | `ops_loop.py:32`、`:111`、`:197`、`:243`；`incidents.py` 对 `close_recovered` 的调用 |
| Runbook 规则配置与 API | 可加载和列出规则，但没有现役 Action 调度器消费执行规则 | 倾向删除规则引擎/配置/空入口；需先确认是否还把它当人工操作参考 | `runbook.py:20`、`:155`；`config.py` 的 `runbook_rules`；`main.py` 的 `apply_runbook_rules`；`/api/runbook` |
| 能力目录里的写 token 生成器 | 旧固定动作 argv/auto_allowed 仍存在；能力目录的读取部分仍被人工调查与账号角色检查使用 | 只考虑瘦身写动作生成器，不能整删目录 | `capabilities.py:14`、`:438`；`investigation.py` 和 `access.py` 的能力查询 |
| `NotificationObligations` | 包含旧待审批/等待/升级逻辑；生产模块未引用该类，测试仍单独调用 | 倾向删除孤立旧实现，迁移仍有价值的通知去重断言；现役 `Notifier` 必须保留 | `notification_obligations.py:20`；`tests/test_notification_obligations.py`；`notify.py` |
| 旧恢复验证 profile 查询 | `profile_for_action` 是旧动作路径，`recovery_evidence_contract` 仍给恢复证据使用 | 可删旧动作匹配函数；保留恢复契约和证据新鲜度 | `verify_profiles.py:146`、`:160` |
| AccessControl 返回 approval_required | 人工账号角色仍使用能力检查，但返回值包含旧审批语义；部分配置管理已独立认证管理员 | 先梳理每个读取调用，统一改为角色准入。当前不粗暴全删，避免误开放或误拦截 | `access.py:78`；`web.py` 的 Prometheus/Exporter 管理权限检查 |
| 历史 Action 只读详情 | 执行/批准按钮已移除，历史记录仍能用于工单阅读 | 保留只读历史，后续可统一迁移至执行事实展示 | `static/app.js` 的 `openActionDetail`；工单历史读取 |
| 人工调查辅助 LLM | 智能填表专用 UI 已删，同一 LLM 仍用于人工只读调查 | 查询分析仍有调用，整体删除前需确认是否继续使用该入口 | `investigation.py:770`；`agent_query.py`；`llm.py` |
| 大批历史说明文档与测试 | 旧权限/审批/Council 报告描述已废弃架构；部分测试导入已删除 fixture | 当前 README 已更新；历史报告后续归档。测试失败分为旧 fixture、旧断言、真实回归，不为全绿恢复旧架构 | `docs/AGENT-PERMISSIONS-v0.8.0.md`；`docs/approval-action-notes.md`；`tests/test_lifecycle_consistency.py:15` |
| 退役接口的 410 拒绝桩 | permissions/Action/Council 等旧 URL 仍注册，但大部分仅返回明确退役 | 可以保留一段兼容期防止旧客户端误操作；不属于还在运行的旧执行架构 | `web.py` 的 `api_legacy_permissions_retired`、`api_action_*`、`api_council_*` |
| 旧 read_alias / write_alias 等资产字段 | 用于历史标识/展示、旧测试和兼容字段；不应再代表账号组权限 | 可在字段迁移时统一改名或删除；需先核对导入/导出与资产 API | `db.py:88`；`qqbot.py` 的 `_asset_text`；`static/app.js` 的资产详情 |

### 不应因为“断舍离”删除的保护

`unknown` 不是失败确认；删除会话不解除未知写操作台账。账号组缺少目标就报配置错误，不借用别组账号。恢复结论必须绑定目标、故障代次与新鲜证据。管理员身份、CSRF、主机指纹、凭据加密、执行事实和审计继续保留。

这些机制在当前单 MiMoCode 会话架构中仍有作用，和旧 Council/审批/Action 二次决策无关。
