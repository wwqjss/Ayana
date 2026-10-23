# 自治 Agent 模型接入与预算

自治 Agent 的三个角色共用现有 `LLMClient` 协议适配器，配置与旧版分析 `llm_*` 完全分开。新功能默认关闭，既有告警、监控与 Runbook 不依赖新 API。模型调用本身没有 SSH、Action、Policy 或投票权限。

## 初始角色与官方 API

2026-10-21 核对官方文档后，使用以下可修改的候选配置：

| 角色 | Provider | Base URL | 初始候选模型 |
| --- | --- | --- | --- |
| planner | MiMo | `https://api.xiaomimimo.com/v1` | `mimo-v2.6-pro` |
| reviewer_kimi | Kimi | `https://api.moonshot.cn/v1` | `kimi-k2.6` |
| reviewer_deepseek | DeepSeek | `https://api.deepseek.com` | `deepseek-v4-pro` |

[Kimi 官方快速开始](https://platform.kimi.com/docs/get-api-key) 给出国内 API 地址与当前模型示例；[DeepSeek 官方模型表](https://api-docs.deepseek.com/quick_start/pricing/) 给出当前模型 ID。不要把已退役的 `deepseek-chat` 或 `deepseek-reasoner` 当作默认模型。MiMo 规划模型由本次实施要求指定；接入后仍需核实账户权限。

候选 ID 不等于账户已经开通。管理员可通过 `verify_account(role)` 请求同一 Base URL 的只读 `/models`；只有当前密钥、地址与模型组合核验成功，才显示已验证。切换任意一项后恢复为未验证。模型服务不提供 `/models` 或返回列表缺少目标模型时，界面明确显示失败原因；不会代替委员批准方案。配置正确的成功结构化调用也可作为该组合已验证的证据。

生产只允许 HTTPS；拒绝 URL 凭据、query、环回、私网和云元数据地址。请求不跟随重定向，连接时重新检查 DNS 解析地址，防止向重定向目标或私网泄露 API Key。仅显式注入测试 client factory 时允许本地 HTTP 故障模拟。

## 凭据与热更新

在现有 `secrets.json` 或环境变量配置以下独立键：

| secrets 键 | 环境变量 |
| --- | --- |
| `ai_planner_api_key` | `AYANA_AI_PLANNER_API_KEY` |
| `ai_reviewer_kimi_api_key` | `AYANA_AI_REVIEWER_KIMI_API_KEY` |
| `ai_reviewer_deepseek_api_key` | `AYANA_AI_REVIEWER_DEEPSEEK_API_KEY` |
| `ai_credential_key` | `AYANA_AI_CREDENTIAL_KEY` |

`ai_credential_key` 是加密主密钥；未设置时可使用现有 `ssh_credential_key` 作为 AES-GCM 主密钥。这不意味着复用 SSH 凭据。API Key 绝不回退到 `llm_api_key`，也不会读取 MiMo Token Plan Key。请使用已经允许用于本自治工作负载的普通 API 凭据。

管理员 Web 设置调用 `ProviderRegistry.update_config(patch, actor=...)`。非秘密设置持久化到 `ai_provider_config`；API Key 使用现有凭据模块 AES-GCM 能力加密到 `ai_provider_keys`。重启保留运行时设置，并覆盖同名启动配置。API 和审计只返回是否已配置，不返回密钥。`clear_api_key: true` 持久化一个加密空值，从而清除密钥后不会悄悄重新加载环境变量旧值。

示例非秘密配置见根目录 `config.example.json` 的 `autonomous_agent`。每个角色独立设置 `base_url`、`model`、`timeout`、`retries`、`input_cny_per_million`、`output_cny_per_million`。角色对应 Provider 固定，以保留两位独立委员身份；可以在同一 Provider 内切换模型。

两位委员不得配置为相同的规范化 Base URL 与模型组合。自定义代理上不同真实模型 ID 可以保留；代理对应的 Provider 身份由受信管理员配置负责，模型输出不能自称委员身份或修改指定席位。

## 预算和费用语义

默认总预算为 **100 元人民币**，三个 Provider 共用。总预算是 Ayana 本地预算，不是厂商余额。价格以人民币每百万 Token 配置；初始价格未知，管理员应按真实账户、币种及当前官方价格确认后填写，不自动猜测汇率或折扣。

2026-10-21 官方人民币价核对记录（每百万 Token，实时 API）：

| 模型 | 缓存命中输入 | 未缓存输入 | 输出 | 官方来源 |
| --- | --- | --- | --- | --- |
| MiMo `mimo-v2.6-pro` | 0.025 元 | 3 元 | 6 元 | [中文模型价卡](https://mimo.mi.com/models/zh-CN/mimo-v2.6-pro) |
| Kimi `kimi-k2.6` | 1.1 元 | 6.5 元 | 27 元 | [开放平台首页价卡](https://platform.kimi.com/?from=footer_nav)、[官方价格介绍](https://www.kimi.com/resources/kimi-k2-6-pricing) |
| DeepSeek `deepseek-v4-pro` 空闲时段 | 0.15 元 | 4.5 元 | 13.5 元 | [官方中文价格表](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/) |
| DeepSeek `deepseek-v4-pro` 高峰时段 | 0.30 元 | 9 元 | 27 元 | 同上 |

DeepSeek 高峰时段为北京时间工作日 9:00–12:00、14:00–18:00（中国法定节假日除外）。本版本只配置统一输入/输出单价，未实现缓存与分时自动计价；可配置未缓存输入和峰值输出作为保守上界，界面仍明确标注“用量估算”，不能称为厂商实际扣款。上述价格是核对日期的事实记录，不自动写入默认配置，也不替代真实账户账单。

- API 返回的 `prompt_tokens` 与 `completion_tokens` 是实际用量证据。`cost_cny` 是这些用量乘以当次配置价格的本地计算费用；**不是厂商实际扣款**，`account_charge_cny` 与厂商账户余额没有证据时为 `null`。
- 价格未知时不发起收费调用，返回 `price_unknown`。这不会阻断告警接收、确定性只读调查、人工操作或已有 Runbook。
- 调用前，在 SQLite 短事务中按输入 UTF-8 字节上界及 `max_tokens` 输出上界预留预算；并行请求共用原子预算检查。此预留不是声称的实际 Token 数或扣费。
- 每次真实 HTTP 重试单独占一条调用记录和预算预留，默认不重试，最多配置两次。
- 正常返回 usage 后，使用真实 Token 数据结算本地计算费用并释放该次预留。超时、断线、usage 缺失或取消时，不知道厂商是否已收费，保留预留并标记费用未知，避免连续不明请求掏空预算。
- 服务启动、开始模型工作之前调用一次 `recover_inflight()`：未完成请求标记 `interrupted_usage_unknown`，保留预算预留，不自动重放请求或 Action。
- 默认每个 Incident 最多 60 次模型请求，每个 generation 最多 30 次（包括重试）。这些是模型费用熔断，不是只读监控次数上限或 Runbook 限制。
- 预算使用达到 80% 显示预警。`usage_summary(incident_id=...)` 提供角色、Provider、Incident 及总体 Token 与已知费用，另列未知调用和预留金额；不要将已知部分当作全部实际扣费。

当前没有厂商账单对账接口；不明请求的保留额不会自动清空。管理员可根据厂商账单确认后调整预算，部署方应保留账单证据。为避免伪造扣费记录，当前不提供自动按估算值填充 usage 或实际扣费的行为。

## 本地验证

`tests/test_ai_providers.py` 使用本地模拟 HTTP、临时 SQLite 和假密钥，覆盖独立凭据、结构化格式异常、双席并行预算、超时/重试费用不明、费用熔断、重启恢复、运行时密钥清除与模型账户核验。`tests/test_llm.py` 保持旧分析适配器回归。没有在这些测试中联系收费模型或生产 SSH。
