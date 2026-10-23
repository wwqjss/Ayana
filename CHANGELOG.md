# Changelog

## v0.8.0 — 三省制自治 Agent 与 MySQL 监控增强

### 新增

- **三省制自治 Agent**（默认关闭）：事件驱动「调查 → 拟案 → 双席独立审议 → 一次性授权 → 受控执行 → 独立验证」
  - **中书省 Planner**（MiMo）：对象级只读调查与具体修复方案；无 SSH 写、无 Action 写工具
  - **门下省双委员**（Kimi + DeepSeek）：并行读取同一不可变方案版本，输出严格 JSON 审议（approve / reason / missing_evidence / suggested_revision）
  - **投票箱**（Python 确定性）：仅两票均同意才签发单次逐步授权；否决、超时、非法 JSON、身份不符均失败关闭
  - **数据模型**：council_goals / plans / reviews / ballots / grants / steps（DB migration 16）
- **独立 AI Provider 注册表**（`ai_providers.py`）：三角色隔离客户端、AES-GCM 密钥、账户 `/models` 核验、usage×单价费用账本、预算与调用上限熔断
- **一次性细粒度授权**：方案签名绑定目标与固定 argv；派发前复核 Policy、双开关、Agent ceiling、SSH 身份；unknown 不自动重放
- **人工屏障**：同目标三轮封驳或 Planner 请求人工时持久 `manual_required`；管理员可精确解除单一目标
- **能力目录扩展**：
  - `service.reload` / `service.reset_failed`（write）
  - `mysql.replica.start`（write，令牌锁定为 `START REPLICA`）
  - `mysql.replica.status`（read，复制 IO/SQL 线程；实例健康 ≠ 复制健康）
- **MySQL 监控可见性**：业务状态自动展示「MySQL 实例 / 复制 IO / 复制 SQL」
- **告警规则** `ayana-mysql-alerts`：MySQLDown、复制 IO/SQL 停止、复制延迟、指标采集丢失（仅告警，不自动修复）
- **证据治理**：Agent 上下文使用摘要与故障相关摘录；原始证据保留 investigation 可追溯入口；按失败指纹去重并限量

### 修复

- 资源页主机红点抬升来源可在业务列表对照（复制线程停时不再「红但无相关监控」）
- 方案校验剥离 identity 回显 params，仍拒绝真正的写参数覆盖
- 调查链路放开只读能力（promconfig.read / checks.read / node_exporter.status / disk / memory 等），写权限边界不变

### 安全

- 写通道仍仅 ActionService；能力只映射登记对象固定命令，不接受任意 shell
- `mysql.replica.*` 令牌写死，不可改命令字符串绕过预算
- Provider Key 只写入、加密存储、UI 不回读；价格未知不发起收费调用
- Runbook 与会审共用冷却/次数账本；两票不覆盖人工审批、全局暂停与控制面保护

### 测试

- Python 回归 1188 项 OK（2 skip）；council / approval / security / channel_admins UI 全过
- 自治专项：双票、封驳、三轮人工、重启恢复、费用熔断、复制能力边界

### 配置

- `config.example.json` 增加 `autonomous_agent`（roles / budget / 调用上限）
- 详见 `docs/autonomous-agent.md`、`docs/ai-providers.md`、`docs/council-security.md`
- 旧 `llm_*` 分析设置保留；`auto_remediation_enabled` 与自治总开关独立

---

## v0.7.4 — 节点守望（配对 + 心跳 + 可选旁路）

### 新增

- **节点守望**：实例间 HTTP 心跳（HMAC + nonce 防重放 + seq），发送/接收两开关独立
- **邀请串配对**：接收端生成 `AYANA-WATCH1.<b64url(json)>`（url + node_id + key + 指纹 + 过期），发送端粘贴解析；密钥 SHA256 前 8 位指纹两边核对后才保存；默认 10 分钟有效
- **心跳周期可配置**：发送端可自定义间隔（最低 10 秒）；配对时写入或事后 `POST /api/node-watch/settings` 修改
- **首页总览状态卡**：展示角色、周期、对端在线情况与最近心跳；发送端显示目标地址与发送结果
- **失联调查**：心跳超时后并行探测已配置旁路（FRP/HTTP 健康口）；未配置 = 未配置，不算失败
- **语义**：旁路仍通 → 「心跳通道异常」；全部失败或无旁路 → 「疑似失联」（网络不可达 ≠ 物理宕机）
- **告警**：同一事件只告一次；有效心跳恢复后自动恢复通知；可绑定 `wecom_aibot` 长连接渠道推送
- **API**：`POST /api/node-watch/heartbeat`（HMAC 自鉴权）、`GET /api/node-watch/status`、`POST /api/node-watch/send-test`、`POST /api/node-watch/invite/{generate,parse,apply}`、`POST /api/node-watch/settings`
- **配置**：`config.json` 的 `node_watch.send` / `node_watch.recv`；心跳直连对端地址，不走 FRP

### 安全

- 管理端节点守望写操作补 CSRF 校验（与其它管理 API 一致）
- 邀请串 TTL 夹紧到 30–3600 秒；心跳 URL 仅允许 http(s) 且禁止 userinfo
- 日志只记指纹 `fp=`，不落明文密钥；状态接口不回显 `shared_secret`

### 测试

- 单测 19 项通过；KANATA→YOMI 心跳 200；停服后自动超时告警并送达企微长连接渠道

---

## v0.7.3 — 发布数据隔离与监控配置化（2026-10-14）

### 修复

- **发布数据污染**：移除代码内硬编码的个人环境业务检查（nerv frps/nginx、sora google/youtube/hysteria、kanata harbor-core）与自动 runbook 规则；全新安装不再出现假「采集故障」业务项
- **required checks / runbook 配置化**：通过 `config.json` 的 `required_checks`、`runbook_rules` 注入；默认为空，由部署方声明
- **knowledge / UI 占位符去个人化**：示例不再绑定 NERV/KANATA/nerv 等
- **验证 profile**：删除资产专属 `frps.recover`，保留通用 `svc.recover` / `svc.stop`（仅服务验证契约，不构成执行授权）

### 安全

- 通用验证 profile **不扩大**自动执行集合：自动仍须 runbook 匹配 × Policy `auto_allowed` × 审批/白名单/审计
- 迁移脚本失败即停：RunbookRule 解析数与源码调用数不一致时拒绝写入
- 迁移默认合并，不覆盖用户已有规则；`--replace` 才整段替换

### 迁移

- `scripts/migrate_monitor_config.py`：从旧 `health.py`/`runbook.py` 导出到 config（`--dry-run` / `--check` / 合并写入）
- 文档：`docs/migration-monitor-v073.md`（KANATA 等已有监视依赖的升级顺序与回滚）

### 测试

- 新增发布数据隔离、监控配置迁移、Runbook 权限边界回归
- 全量相关测试通过（见 CI / `python -m unittest discover tests`）

### 升级注意

**KANATA 等依赖硬编码监视的环境：先迁配置再换代码**，否则升级瞬间 required checks / runbook 会变空。

---

## v0.7.2

- 首登 Token 注册管理员、强制改密页、监控接入入口修复
- 其余见仓库提交历史
