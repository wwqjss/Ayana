# 三省制自治 Agent：上线联调测试方案

对应实现与边界见 [autonomous-agent.md](autonomous-agent.md)。本方案覆盖从部署配置到真实 frps 停服/告警/恢复验收的完整联调路径。本地代码回归已通过，**不等于**本方案的生产验收。

## 1. 范围与目标

| 项 | 内容 |
| --- | --- |
| 范围 | 三省制自治 Agent（`ai_providers` / `council` / `autonomy`）及其与 Incident、Policy、Action、Verification、Notifier 的联调 |
| 不在范围 | 原 Runbook 通道既有能力的重新验收；厂商账单对账 UI；任意 shell/文件写改能力 |
| 目标 | 在预发/生产环境完成配置核验、双票会审链路、真实 frps 事件闭环，并留下可签字记录 |
| 原则 | 新模型默认关闭；先只读后写；写操作须双票 + Policy + 主机权限同时成立；任一开关关闭即拦截 |

## 2. 环境前提

- [ ] Ayana 已按 [INSTALL.md](INSTALL.md) 部署，`/health` 正常，数据库迁移已完成（含 migration 16）
- [ ] 受管主机（含 frps 所在主机）SSH 身份已登记且指纹已确认
- [ ] Prometheus / Alertmanager 可达，frps 相关 `TargetDown` 或 probe 告警链路可用
- [ ] 通知通道（QQ/企微）至少一条可用，用于人工裁决与恢复通知
- [ ] 有管理员账号，可改全局设置、权限、Agent ceiling，并完成 TOTP/人工裁决操作
- [ ] 已获授权可在目标主机执行 `systemctl stop/start/restart/reload/reset-failed frps`（或等价登记服务名）

## 3. 联调前置配置检查表

按顺序执行；每项填「结果 / 操作人 / 时间」。

### 3.1 Provider 与预算

| # | 检查项 | 期望 | 结果 |
| --- | --- | --- | --- |
| P1 | Web 全局设置 → 三省制自治 Agent | 配置可打开，三家角色字段齐全 | |
| P2 | planner = MiMo，reviewer_kimi = Kimi，reviewer_deepseek = DeepSeek | 角色与 Provider 绑定，不可互换身份 | |
| P3 | 各角色 Base URL / 模型 / 超时 / 重试 | 与官方文档一致；模型为账户实际支持的型号 | |
| P4 | 各角色 Key 写入 | 只写入、不可回读；落库为 AES-GCM 密文；仓库无明文 | |
| P5 | 各角色「账户模型核验」 | `/models` 只读核验通过，或明确拒绝并显示原因 | |
| P6 | 单价（元/百万 Token，输入/输出） | 按当前官方价填写；未知则保持 null 且不发起收费调用 | |
| P7 | 总预算 `budget_cny` | 首期 100 元；若计入本地验收消耗，剩余额度 ≤ 99.55 元 | |
| P8 | 原 `llm_*` 分析设置 | 保留且不受影响 | |

### 3.2 开关与 Policy

| # | 检查项 | 期望 | 结果 |
| --- | --- | --- | --- |
| S1 | 「三省制自治 Agent」总开关 | **保持关闭** 直至 3.3 完成 | |
| S2 | 「自动处置」总开关 `auto_remediation_enabled` | 与 S1 独立；写派发需二者同时开启 | |
| S3 | 登记对象（资产/服务） | frps 及验证所需对象已登记，名称精确、无通配符 | |
| S4 | Agent ceiling | 仅包含本次联调所需能力；不含任意 shell | |
| S5 | `auto_rule:agent` 读 Policy | 调查只读能力允许（日志/配置属性/进程/端口等） | |
| S6 | `auto_rule:agent` 写 Policy | 仅对计划使用的能力显式 allow；`service.stop/start/restart/reload/reset_failed` 按需 | |
| S7 | 验证 profile | 每个写能力绑定 `probe.status` 等真实验证器，selector 为精确资产/服务 | |
| S8 | 控制面保护 | 不把控制面对象纳入自治写目标 | |

### 3.3 主机权限（源码不会自动授予）

受管主机的 sudo / forced-command 白名单需**部署方独立配置**。新增能力未配则写操作会在主机侧失败（应表现为失败/unknown，不得放行）。

| # | 主机侧命令 | 用途 | 是否需授权 | 结果 |
| --- | --- | --- | --- | --- |
| H1 | `systemctl status/show/is-active ...`（只读） | 调查与验证 | 是（通常已有） | |
| H2 | `systemctl restart <svc>` | 原快速路径 / 会审 | 按需 | |
| H3 | `systemctl start <svc>` / `stop <svc>` | 停服演练与恢复 | 按需 | |
| H4 | `systemctl reload <svc>` | **新增**，ExecReload 重载 | **需显式添加** | |
| H5 | `systemctl reset-failed <svc>` | **新增**，清除失败/启动限速 | **需显式添加** | |
| H6 | SSH 账号 | 受限账号；写通道与只读通道账号符合设计 | | |
| H7 | 主机指纹 | 与登记指纹一致，拒绝跳过校验 | | |

> 提醒：`reload` / `reset-failed` 不会随源码自动上主机。未授权时联调预期为**失败并留痕**，不是跳过。

## 4. 分阶段联调步骤

### 阶段 A：配置与只读调查（不写）

1. 确认 3.1–3.3 检查表完成，S1/S2 仍为关闭。
2. 打开「三省制自治 Agent」（S1），**保持**「自动处置」（S2）关闭。
3. 人为制造或等待一条与 frps 相关的告警/Incident（可用预发主机临时 stop frps 后立刻 start，或用测试告警注入）。
4. 观察事件详情：
   - [ ] 出现 Investigation / 时间线 / 证据（只读）
   - [ ] 若产生方案：可见不可变方案版本、精确目标、验证契约、Policy 快照
   - [ ] **不得**派发任何写操作
   - [ ] 费用页出现本事件用量；未知 usage 不显示为 0
5. 通过 Web 完成三家角色的账户核验与价格确认（若 P5/P6 未完成）。

**阶段 A 通过标准**：只读链路完整，零写入，预算/用量可见，开关拦截生效。

### 阶段 B：双票会审与单次授权（预发可回滚主机）

1. 打开「自动处置」（S2），确认 S1+S2 均开。
2. 在预发主机（非生产 frps）注册一个**可丢弃**测试服务，或使用已有测试单元。
3. 触发 Incident，等待或引导生成具体方案（如 `service.restart` / `service.reload`）。
4. 核对会审：
   - [ ] Kimi、DeepSeek **并行**读取同一不可变方案
   - [ ] 均返回严格 JSON；非法 JSON 失败关闭且记费用
   - [ ] 投票箱显示两席理由；两票同意才签发一次性授权
   - [ ] 否决则封驳，无授权、无 Action 派发
5. 若两票同意，观察 Action：
   - [ ] `reviewed` 模式，不可被普通 approve 绕过
   - [ ] 派发前再次校验 Policy / 开关 / SSH 身份 / 固定能力
   - [ ] 只消费一次授权；重复执行被拒
   - [ ] 命令成功只进入 `verifying`，不直接结案
6. 观察 Verification：使用方案内契约，与模型描述无关；失败则回到调查。
7. 人为篡改/过期授权（如有测试钩子）或等待过期，确认拒绝并留痕。

**阶段 B 通过标准**：双票、单次授权、独立验证、失败闭环均符合设计；预发主机状态可回滚。

### 阶段 C：真实 frps 停服/告警/恢复验收

在生产或预发 frps 主机，**明确授权窗口**内执行。建议双人：一人操作主机，一人只观察控制台。

1. 记录基线：frps 状态、Prometheus probe、现有 Incident、通知通道、剩余预算。
2. **停服注入**：`systemctl stop <frps>`（或授权的等价动作）。
3. **告警**：等待 Alertmanager → Incident 生成/聚合。
   - [ ] Incident 出现且 generation 递增
   - [ ] 调查证据含进程/端口/探针
4. **自治处置**（若进入会审）：
   - [ ] 方案目标精确指向该 frps 对象
   - [ ] 双票记录完整
   - [ ] 授权后 Action 执行（预期 `service.start` 或 `service.restart`，以方案为准）
   - [ ] 验证 profile 通过（probe 成功、服务 active）
   - [ ] 来源不再 firing 后才结案；恢复通知发出
5. **恢复确认**：主机 `systemctl is-active` 为 active；Prometheus 恢复；控制台无残留写锁/待验证。
6. **异常分支抽查**（按时间盒，可选但建议至少 1 项）：
   - [ ] 主机侧拒绝 `reload`/`reset-failed`（未授权时）→ 失败/unknown 留痕，不自动重放
   - [ ] 关闭 S1 或 S2 → 新写派发被拦
   - [ ] 三轮封驳 → 持久人工屏障 + 通知；「允许此目标重新拟案」只解该目标
   - [ ] 来源仍 firing 时不因 SSH 成功强行结案

**阶段 C 通过标准**：真实告警进入、双票写、独立验证、结案与通知符合文档；全程无越权命令。

### 阶段 D：恢复与收敛

1. 确认 frps 正常、无进行中的授权/Action。
2. 按策略决定是否关闭 S2（保留只读自治）或 S1。
3. 核对费用账本：角色/Provider/事件用量、预留与未知费用。
4. 备份数据库与配置（见 INSTALL.md 备份一节）。
5. 归档本方案填写后的记录表与日志摘录（不含 Key）。

## 5. 验收标准汇总

| 类别 | 标准 |
| --- | --- |
| 安全 | 无任意 shell；无未登记能力；开关/Policy/主机权限任一缺失即失败关闭 |
| 会审 | 两独立委员、不可变方案、严格 JSON、确定性投票、单次授权 |
| 执行 | Action 唯一写通道；成功仅入验证；unknown 不自动重放 |
| 验证 | 后端契约生效；来源仍 firing 不结案 |
| 人工 | 三轮封驳/Policy 拒绝转人工并通知；屏障可精确解除 |
| 费用 | usage×单价估算可见；未知不伪造；预留防重复扣费 |
| 通知 | 人工裁决与关键暂停可送达；来源恢复/换代取消未发通知 |

## 6. 记录表（执行时填写）

| 阶段 | 时间 | 环境 | 操作人 | 结果 | 证据（事件 ID/日志/截图） | 问题单号 |
| --- | --- | --- | --- | --- | --- | --- |
| A 配置与只读 | | | | | | |
| B 双票与授权 | | | | | | |
| C frps 验收 | | | | | | |
| D 收敛 | | | | | | |

**总体结论**：☐ 通过　☐ 有条件通过（遗留：____）　☐ 不通过

签字：________　日期：________

## 7. 应急与回滚

| 情况 | 动作 |
| --- | --- |
| 模型费用异常 | 关自治开关；查 `autonomy/usage` 与账本；必要时调低/清零预算并保留未知预留 |
| 错误写操作 | 关 S2；人工用现有人工操作恢复服务；作废未用授权；记录 generation |
| 通知风暴 | 确认补偿/合并逻辑；必要时静默通道并人工处理 pending |
| 主机权限过宽 | 立即收紧 sudo/forced-command 至本清单；复核审计 |
| 回滚版本 | 停服务 → 换回上一版本代码/依赖 → 迁移兼容性确认 → 重启 → `/health` |

## 8. 本地基线（2026-07 联调前）

| 验证 | 结果 |
| --- | --- |
| 完整 Python 回归 | 1188 项，OK（skipped=2，Windows 符号链接/只读目录） |
| 自治/会审/Provider 专项 | 149 项通过 |
| 六组 UI 行为回归 | 96 项全部通过（council 15 / approval 8 / channel_admins 4 / security 21 / assist 29 / monitor 19） |

命令入口：

```text
python -m unittest discover -s tests -p 'test_*.py' -q
python -m unittest tests.test_autonomy_engine tests.test_autonomy_integration tests.test_autonomy_capabilities tests.test_autonomy_notify tests.test_council_security tests.test_council_api tests.test_ai_providers -q
node tests/test_council_ui.cjs
node tests/test_approval_ui.cjs
node tests/test_channel_admins_ui.cjs
node tests/test_security_ui.cjs
node tests/test_assist_ui.cjs
node tests/test_monitor_ui.cjs
```

## 9. 与文档的差异说明

- 本文是**联调执行**方案；实现细节、状态机、费用与恢复语义以 `autonomous-agent.md` 为准。
- `autonomous-agent.md` 中的「本地验收」记录的是开发机回归与模拟注入，不能替代阶段 B/C。
- 首期预算若采用保守剩余额度，以 **99.55 元** 为上限，再对厂商实际账单；该数字不是新的 100 元额度。
