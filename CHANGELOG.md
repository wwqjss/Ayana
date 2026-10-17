# Changelog

## v0.7.4 — 节点守望（心跳 + 可选旁路）

### 新增

- **节点守望**：实例间 HTTP 心跳（HMAC + nonce 防重放 + seq），发送/接收两开关独立
- **失联调查**：心跳超时后并行探测已配置旁路（FRP/HTTP 健康口）；未配置 = 未配置，不算失败
- **语义**：旁路仍通 → 「心跳通道异常」；全部失败或无旁路 → 「疑似失联」（网络不可达 ≠ 物理宕机）
- **告警**：同一事件只告一次；有效心跳恢复后自动恢复通知
- **API**：`POST /api/node-watch/heartbeat`、`GET /api/node-watch/status`、`POST /api/node-watch/send-test`
- **配置**：`config.json` 的 `node_watch.send` / `node_watch.recv`；心跳直连对端地址，不走 FRP

### 测试

- 单测 9 项通过；KANATA→YOMI 公网心跳 200；FRP 旁路判定「通道异常」正确

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
