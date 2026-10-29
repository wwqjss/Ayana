# Ayana MCP 操作接口（MiMoCode）

MiMoCode 在当前原生会话中通过 MCP 调查、执行、验证和维护监控配置。本文说明当前接口的用途与约束，具体字段以运行时发现的工具定义为准。Web 手工表单与 MCP 共享监控配置校验。

`host.exec` 的主机权限来自所选 SSH 账号及其 sudo 配置。配置工具还会校验参数、可信会话和目标配置权限；Prometheus 文件变更包含校验、备份与失败回滚。账号组名称只是标签。

## 账号组（SSH 凭据选择）

- 每台资产可配置多个 SSH 账号，归属到用户自定义的**账号组**（名称、描述由用户写）。
- Agent 设置里的 `ssh_default_group` 是全局默认账号组，未单独指定账号组的会话和后台检查均使用它。
- 会话顶部可单独切换账号组，保存为该会话的 `ssh_account_group`；空值表示“跟随默认”。单独切换不改变其他会话。
- 调查与执行都使用当前有效账号组；切换影响后续操作，已经发出的命令继续使用原账号。
- 可以只配一个组；组名和描述均由用户定义。
- 目标主机缺少指定账号组时返回配置错误，**不会自动回退**到另一组。
- MiMoCode 不得自行修改账号组绑定。

## 工具一览

| 工具 | 用途 |
| --- | --- |
| `host.exec` | 在资产上执行命令（调查 channel=read / 执行 channel=write） |
| `metrics.query` | 查询 Prometheus |
| `incident.list` / `incident.get` / `incident.note` / `incident.close` | 工单 |
| `knowledge.query` / `knowledge.get` / `knowledge.upsert` | 知识库 |
| `asset.list` | 资产列表 |
| `session.get` / `session.write_ops` / `session.claim` | 会话与写事实 |
| `ops.constraints` / `ops.loop_status` | 当前约束、工单事实与明确标记的历史状态 |
| `config.prom_target_add` / `_update` / `_delete` | Prometheus 采集目标 |
| `config.check_list` / `_add` / `_update` / `_delete` | SSH 业务检查 |

## host.exec

调用参数示例：

```json
{
  "asset_id": "demo-web",
  "command": "systemctl is-active nginx",
  "channel": "read",
  "timeout_sec": 12
}
```

`channel` 可选 `read` 或 `write`，默认 `write`。`read` 用于符合只读语法的调查命令；变更使用 `write`，两者使用同一有效账号组。工单处置可增加 `incident_id`，仅接受当前会话已关联、主机和代次匹配的未关闭工单。

返回：`ok`、`output`、`returncode`、`exec_state`（success|failure|unknown）、`action_key`，以及实际使用的 SSH 账号组和账号。
结果不明为 `unknown`，Ayana 如实记录并保留防重复保护。先通过只读检查核对目标，需澄清原始结果时使用写结果核销入口；不能把 unknown 当作已失败后盲目重放。

写操作省略 `incident_id` 时，仅将同一主机仍未关闭的关联工单作为候选。唯一候选自动绑定，多个候选必须明确指定；未关闭工单的关联代次过期时明确拒绝，需先 `session.claim` 刷新关联。

手动会话没有未关闭候选时，可省略 `incident_id` 执行独立任务，操作进入当前会话台账。已关闭工单的历史关联继续保留，不阻挡独立任务；显式指定已关闭工单返回 `incident_not_open`，可行时提示 `can_run_standalone=true`、`next_action=omit_incident_id`。自动会话不会因关联工单关闭而降级为独立写。

独立任务仍受账号组、主机指纹、目标占用、未知结果和防重复保护约束；SSH 真正派发前会再次检查工单范围，准备期间关闭、重开或新增关联会导致本次未执行拒绝。重复的已完成命令继续返回 `idempotent_block` / `already_done`，不能以独立任务名义重放。

工单写事实和审计包含真实工单、当前代次、会话、账号组及执行结果；同工单同代次的相同操作跨会话共享防重复键。历史 `unknown` 不会因换代、换会话或归档原会话而解除，必须先核对或人工核销。

独立操作也有会话台账和审计。`session.write_ops` 按工单查询；独立操作可在 Web 审计按会话查询，不应以某个工单列表为空来推断没有执行记录。

`ops.loop_status` 分别返回当前工单事实和只读历史快照。历史快照带 `retired=true`、`active=false`，不代表当前原生任务状态。当前执行任务与故障是否恢复分别核对。

## config.check_add

校验与 Web 表单同一契约（`formspec.validate_check_payload`）：

| kind | 必填 params | 说明 |
| --- | --- | --- |
| `service` | `unit` | systemd 单元，`systemctl is-active` |
| `port` | `proto`（tcp/udp/http/https）、`port`，http(s) 可带 `path`/`host` | 端口/HTTP 探测 |
| `command` | `cmd` | 仅允许白名单程序；expect 只支持 `exit_code` |

可选：`expect`（如 `{"active_state":"active"}`）、`interval_sec`（15–3600）、`fail_threshold`（1–20）、`severity`（info/warning/critical）。

示例——添加 Nginx 服务检查：

```json
{
  "asset_id": "demo-web",
  "kind": "service",
  "name": "Web nginx 服务检查",
  "params": {"unit": "nginx.service"},
  "interval_sec": 60,
  "fail_threshold": 2,
  "severity": "warning"
}
```

校验失败时返回 `issues`（字段级错误）与 `missing`（缺字段），据此修正后重试。

`config.check_update`：传 `id` 和要改的字段；`enabled:false` 停用检查。
`config.check_delete`：传 `id`。

## config.prom_target_add

```json
{
  "address": "http://192.0.2.10/healthz",
  "labels": {"instance": "demo-web"},
  "probe": {"exporter": "127.0.0.1:9115", "module": "http_2xx"}
}
```

这是 HTTP 探测示例，需准备 Blackbox Exporter。普通采集目标可使用 `192.0.2.10:9100` 并省略 `probe`。校验、备份、失败回滚由 Ayana 处理。

## 审计

所有写操作记录：会话、用途（调查/执行）、目标主机、实际 SSH 账号、命令/参数、结果（含 unknown）、时间。
原始执行事实不可被后续判断改写。
