# P6 最终架构整合 · 交付报告

> 基线：`speed-supreme` @ `283ecfb`（P4.5）。目标：MiMoCode 唯一 AI 大脑，Ayana 管理/执行/审计，告警即工单 ALL IN 自治。

## 1. 完成项

### 1.1 自治执行（退役 Ceiling / 三态）
- `actions.py` 新增 `mode=autonomous`：**不再**要求 template/runbook，**不再**走 Policy 三态 / Agent Ceiling。
- 系统自动批准（`approver_type=system`），保留：能力目录、对象绑定、host key、对象锁、幂等、unknown 禁重放、验证契约。
- `legacy_action_block`：仍永久拒绝 `auto`/`reviewed`/`council_*`；仅允许 `manual` 与 `autonomous`。
- 人工 Web/QQ 路径（`manual`）Policy / 审批 / ceiling **不变**。
- `ActionService.autonomous_execute`：提案→系统批准→执行 一键。

### 1.2 软约束
- 新模块 `ops_constraints.py`：默认提示词（无进展 3 轮停止、同方案失败 2 次停止、证据不足转人工）。
- 版本库落在 `config_versions`；支持保存 / 列表 / 激活唯一生效版本。
- Web：`/api/ops/constraints` GET/POST + `/activate`；UI「运维软约束（MiMoCode）」。
- `auto_investigate.CONCLUSION_PROMPT` 写入同一组软约束；禁止 `action.execute`。

### 1.3 硬保护（未放宽）
| 保护 | 状态 |
|------|------|
| SSH 凭据加密隔离 | 不变（CredentialStore） |
| host key 校验 | 不变 |
| 超时 | 不变（transport / verify_timeout） |
| 幂等 | 双台账：actions FSM + session_write_ops 租约 |
| unknown 禁止重放 | 不变；lease 过期→unknown |
| 只读隔离 | `AYANA_MCP_READONLY` + `readonly_commands` 不变 |
| 旧 Council/auto 授权 | 仍 `legacy_autonomy_retired` 拒执 |

### 1.4 自然语言配置
- MCP 新增 `config.prom_target_add/update/delete`，复用 `promconfig` 事务：备份→promtool→原子写→reload→失败回滚。
- 路径沙箱 `safe_rel_path` 保留；审计 `promconfig_*` / `*_failed`。

### 1.5 完整审计
- autonomous 写：`action_proposed` / `action_approved`（channel=autonomous）+ execute 审计。
- MCP 写：`mcp_host_exec_write` + `session_write_ops.action_key`。
- 新 API `/api/executions?incident_id=`：统一查询 actions + session_write_ops。

### 1.6 MiMoCode 管理
- `mimo_admin.py`：status / start / stop / restart / logs / stats / models；`provider_summary` **不输出密钥**。
- Web：`/api/mimo/*` + UI「MiMoCode 管理」+ `/api/mimo/chat`（经 SessionBridge 挂会话）。
- 配置键：`mimo_bin` / `mimo_workdir` / `mimo_serve_url` / `mimo_unit`。

### 1.7 工单闭环
- `ops_loop.py`：`note_round` 强制软约束（3 轮无进展 / 同方案 2 次失败 → 停止并 `escalate` 转人工+通知）。
- `run_action_and_verify` + `maybe_close`（经 IncidentService.reconcile）。
- 表 `ops_loop_state`（schema v21）。

### 1.8 MCP 工具面（19）
原 13 + `action.execute` / `ops.constraints` / `ops.loop_status` / `config.prom_target_{add,update,delete}`。

## 2. 测试

```
python -m unittest discover -s tests -p "test_*.py" -q
→ Ran 1311 tests · OK (skipped=2)
```

- 新增 `tests/test_final_architecture.py`（11）：legacy 拒执、autonomous 跳 Policy、manual 仍走 Policy、软约束版本、闭环停止、MCP 工具注册。
- 更新 `tests/test_speed_supreme_p0.py` 工具清单 13→19（产品变更，非删测）。

## 3. 提交

见 Git log（P6 分段提交）。

## 4. 遗留

1. Web 对话框仅 admin 调 `session_remote`；完整聊天 UI 可后续增强。
2. `action.execute` 能力目录仅覆盖登记对象；任意 shell 仍走 `host.exec`（SSH 账户边界）。
3. Alertmanager 规则级 MCP 尚未做（目标 CRUD 已通；rules 经 Web）。
4. 生产部署需 `ayana-setup.sh update` + 重启；`ops_loop_state` 首次迁移自动建表。
5. auto_investigate 默认仍 `enabled=false`，可按需打开只读调查；闭环写路径已具备。

## 5. 兼容与破坏性

- 无删表、无改 secrets/config；schema 仅新增 `ops_loop_state`。
- 历史 `mode=auto/reviewed` 动作仍拒执（安全）。
