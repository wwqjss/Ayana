# Prometheus 可视化配置管理（v0.6.1）

目标：通过 Ayana Web 管理现有 Prometheus，尽量不再手写 YAML/JSON。

## 范围（最小可用闭环）

1. 读取现有 `prometheus.yml`、抓取任务、目标、告警规则（兼容手写，原文保留）
2. Node Exporter：检查 / 安装 / 启动 / 停止 / 注册目标（默认 127.0.0.1:9100）
3. 监控目标：file_sd 增删改；展示 Prometheus 实时抓取状态
4. 告警规则：常用模板 + 阈值/for/级别；复杂规则只读
5. 安全应用：备份 → promtool → 原子写入 → 热重载；失败回滚

不在范围：完整 Prometheus UI 替代、远程写/联邦、Alertmanager 路由编辑。

## 架构

```
Web (index.html/app.js 页签 Prometheus)
        │
        ▼
web.py  /api/promconfig/*  ── Policy(promconfig.*) + admin + CSRF + audit
        │
        ▼
promconfig.py  PromConfigService
  ├── ConfigFS          local | ssh(transport)   路径沙箱
  ├── parse_simple_yaml 结构只读展示；写操作不整文件重写用户 YAML
  ├── file_sd/ayana-nodes.json   新增目标（Ayana 托管）
  ├── rules/ayana-node-alerts.yml 模板规则（Ayana 托管）
  ├── 外科插入          prometheus.yml 补 job / rule_files 条目
  └── 安全应用          backup → promtool check → atomic write → /-/reload → rollback
        │
        ▼
Prometheus 配置目录（本地或经 SSH 资产）
```

## API

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/api/promconfig/overview` | promconfig.read | 存储/文件/实时目标摘要 |
| GET | `/api/promconfig/config` | promconfig.read | 原文 + 任务结构化 |
| GET | `/api/promconfig/targets` | promconfig.read | 配置目标 + file_sd + 实时健康 |
| POST | `/api/promconfig/targets` | admin+promconfig.write | 添加 file_sd 目标 |
| POST | `/api/promconfig/targets/update` | admin+promconfig.write | 编辑 |
| POST | `/api/promconfig/targets/delete` | admin+promconfig.write | 删除 |
| GET | `/api/promconfig/rules` | promconfig.read | 规则文件 + 模板 |
| POST | `/api/promconfig/rules/template` | admin+promconfig.write | 启用/停用模板 |
| POST | `/api/promconfig/rules/update` | admin+promconfig.write | 编辑托管规则 |
| GET | `/api/promconfig/node-exporter` | node_exporter.status | 检查 |
| POST | `/api/promconfig/node-exporter` | admin+node_exporter.manage | install/start/stop/check |
| POST | `/api/promconfig/node-exporter/register` | admin+promconfig.write | 注册目标 |
| POST | `/api/promconfig/validate` | admin+promconfig.write | promtool + 热重载 |
| POST | `/api/promconfig/rollback` | admin+promconfig.write | 按路径恢复最近备份 |

## 配置

### Agent 添加 HTTP 健康监控

MCP 工具 `ayana_config_prom_target_add` 支持可选的 `probe` 对象。普通
`address=host:port` 仍使用原有 file_sd 流程；HTTP 探测示例：

```json
{
  "address": "http://172.16.0.14/",
  "labels": {"asset": "ROMI", "service": "nginx"},
  "probe": {
    "exporter": "blackbox:9115",
    "module": "http_2xx",
    "job_name": "romi-nginx-blackbox"
  }
}
```

`exporter` 必填，使用 Prometheus 能访问的 Blackbox Exporter 地址。
`module` 默认 `http_2xx`，`job_name` 省略时按探测参数生成稳定名称。
工具仅登记已有 Exporter 的探测配置，不安装 Exporter 或创建告警规则。
Agent 应继续核对 `probe_success` 和告警规则是否符合需求。

配置固定生成 `/probe`、`params.module`、静态目标和三条标准 relabel；
不接受自定义 relabel、任意 YAML 或文件路径。URL 仅允许 HTTP(S)，
拒绝内联凭据、片段和控制字符；内部标签、`job`、`instance` 保留。
配置在同一事务内完成备份、promtool 检查、热重载，失败恢复原配置。
读写模式和人工审批继续使用原工具的门禁。

已有等价探测（包括手写任务和额外标签）会返回 `changed=false` 和实际任务名，
保留配置原文，避免重复抓取。同名任务参数不兼容时返回 `probe_job_conflict`。
复杂且无法安全追加的 YAML 返回 `yaml_unsupported`，不会重写原文件。
`prom_target_update/delete` 仍只处理原有托管 file_sd 目标；此扩展仅提供安全新增和复用。

```json
"prometheus_config": {
  "local_dir": "prometheus",
  "ssh_asset_id": "",
  "remote_base": "/etc/prometheus",
  "promtool": "promtool",
  "reload_url": ""
}
```

- 本地：`<base_dir>/<local_dir>/prometheus.yml`
- SSH：`ssh_asset_id` 对应资产，读写 `remote_base`（禁止路径逃逸）

## 安全约束

- 路径：仅相对路径；拒绝 `..`、绝对路径、shell 元字符
- 监听：默认 `127.0.0.1:9100`；拒绝 `0.0.0.0`/公网（可显式 `allow_non_private`）
- 安装：不下载公网二进制；固定 unit 写 `/etc/systemd/system/node_exporter.service`；要求已有 `/usr/local/bin/node_exporter`
- 写回：非托管规则文件拒绝写；YAML 无法无损外科修改则拒绝
- 权限：admin + Policy 能力 + CSRF；写操作全部 `audit_log` + `config_versions` 备份

## 测试

`tests/test_promconfig.py`（23 项）：路径沙箱、YAML 解析、外科插入保注释、file_sd CRUD、模板规则、备份回滚、Node Exporter 固定命令、公网监听拒绝、能力注册。

## 未解决问题 / 后续

1. **promtool 可选**：本机/远端无 `promtool` 时校验跳过并标记 skipped；生产建议安装。
2. **YAML 子集解析**：复杂锚点/多文档/流式嵌套可能解析失败 → 降级只读原文，不提供结构化编辑。
3. **安装前提**：不负责下载 node_exporter 二进制；需主机预置且 `commands.json`/sudoers 允许 `sh -c`/`systemctl` 等固定动作。
4. **SSH 写**：使用 `sh -c` + base64 写文件，依赖主机允许该形态；若强制 forced-command 白名单，需在主机侧登记对应动作。
5. **未做**：Alertmanager 路由/静默编辑、多 prometheus 实例、规则 diff 界面、PromQL 编辑器。
6. **先测试环境**：功能已实现并本地单测通过；未在生产 Prometheus 上实际应用配置（按要求不擅自改生产）。
