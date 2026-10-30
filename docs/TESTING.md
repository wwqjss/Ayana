# 开发与测试

在仓库根目录运行测试。Python 依赖以 `pyproject.toml` 为准，前端行为测试使用 Node.js 自带测试运行器。

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## 改动相关与核心回归

下面的用例在临时数据库和模拟连接上验证工单绑定、账号组、写事实、原生任务观察与恢复证据，不向生产主机执行命令。

```bash
PYTHONPATH=.:tests python -m unittest \
  tests.test_incident_write_binding \
  tests.test_ssh_group_migration \
  tests.test_ssh_endpoint_preservation \
  tests.test_agent_authority \
  tests.test_agent_work_scope_roles \
  tests.test_native_turn_admission \
  tests.test_task_observation \
  tests.test_execution_observation \
  tests.test_loop_observation \
  tests.test_live_execution_contract \
  tests.test_incident_execution_view \
  tests.test_check_recovery \
  tests.test_recovery_evidence \
  tests.test_session_lifecycle
```

前端测试：

```bash
node --test \
  tests/test_native_workbench_ui.cjs \
  tests/test_incident_execution_ui.cjs \
  tests/test_connections_ui.cjs \
  tests/test_settings_ui.cjs \
  tests/test_monitor_ui.cjs \
  tests/test_mimo_ui.cjs \
  tests/test_terminal_clipboard.cjs \
  tests/test_security_ui.cjs
```

## v0.8.3 针对性验证

本次重点验证监控来源隔离、原生工具步骤展示与 MCP 执行参数。发布前应先通过这些用例及上面的核心回归，再做一次全量摸底；针对性通过不等于全量通过。

```bash
PYTHONPATH=.:tests python -m unittest \
  tests.test_monitor_business \
  tests.test_monitor \
  tests.test_host_health \
  tests.test_system_health_ratio \
  tests.test_checks \
  tests.test_mcp_check_contract \
  tests.test_live_execution_contract

node --test tests/test_monitor_ui.cjs tests/test_native_workbench_ui.cjs
```

验证应覆盖：Prometheus 缺失时有效原生检查仍决定主机状态，缺失指标不被造值；重复刷新只保留一个来源提示；业务异常、未知、过期和停用结果准确区分；当前步骤只显示真实工具事实；未执行的参数校验失败与执行后的未知结果分别处理。

## 安装与发行包

安装测试应在临时目录验证路径、配置、两个服务单元、依赖安装、重复执行、升级与回滚，不针对正在使用的安装目录进行试验。

公开文档与安装契约测试会验证正式文档链接、版本一致性、发行包内容和安装行为。构建命令及用户部署流程见 [安装手册](INSTALL.md)。

## 全量摸底

```bash
PYTHONPATH=.:tests python -m unittest discover -s tests -p 'test_*.py'
```

全量摸底与核心发布回归分开记录。部分历史测试仍引用已移除的测试夹具或旧权限语义，不能把加载失败当作通过，也不能为追求全绿恢复旧执行架构。此前一次摸底为 1037 项，包含 2 项旧语义失败、14 项旧夹具或接口初始化错误，以及 3 项平台跳过。

v0.8.3 本次摸底运行 1184 项，初次记录为 5 项失败、14 项错误和 4 项环境/平台跳过。其中本次错误文案兼容与文档版本切换涉及的 2 项已经修正并单独复测通过；剩余 3 项失败在未修改的 v0.8.2 源码上同样复现，分别要求旧配置键或已退役的逐动作审批语义。14 项错误来自旧权限表、已移除的夹具及旧接口导入。没有为这些历史用例恢复废弃实现。后续新增用例会改变总数。

发现失败时先区分当前功能回归、历史测试迁移和平台限制。核心链路必须通过，历史遗留需有明确分类。真实业务验收由部署者选择合适场景，不通过主动停止正常业务来制造测试故障。
