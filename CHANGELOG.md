# Changelog

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
