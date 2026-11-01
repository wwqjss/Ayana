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

## 轻量后台值班与模式隔离

轻量 Agent 的模型与工具测试使用模拟回复，不发起真实模型请求、不操作生产主机。应验证模型工具调用预算、未知写结果保护、账号组绑定，以及轻量模式无法从 Web 启动 MiMo、手动会话或交互终端。

```bash
python -m unittest discover -s tests -p test_lite_agent.py
python -m unittest discover -s tests -p test_lite_worker.py
python -m unittest discover -s tests -p test_lite_web.py
node tests/test_lite_model_ui.cjs
node tests/test_native_workbench_ui.cjs
```

模式安装测试还须覆盖：菜单选择及参数绕过、轻量安装无需 MiMo/tmux、升级保留原模式，以及切换前仍检查旧运行时和未决写操作。

v0.9.0 本次验证结果：核心集成实际执行的 400 项通过，另有 2 个历史夹具导入错误和 1 个平台跳过；轻量模型循环 29 项通过，轻量 Web 10 项通过，安装契约 47 项中 46 项通过、1 项环境跳过。后续补充的轻量 Worker 用例验证暂停、跨代次探测、未知写结果、取消与重启保护及通知补偿；文件锁软链接用例在 Windows 环境跳过，在 Linux 隔离环境验证。

全量只运行一次摸底：1252 项，3 个失败、14 个错误、4 个跳过。失败名称与此前 v0.8.3 记录一致：旧配置示例键检查及两项旧 Prometheus 审批语义；错误仍来自已删除的权限表、缺失历史夹具和废弃接口导入。前端相关 207 项检查通过，另有旧审批按钮测试失败，已在干净 v0.8.3 源码复现。未恢复已退役架构。

## 安装与发行包

安装测试应在临时目录验证路径、配置、两个服务单元、依赖安装、重复执行、升级与回滚，不针对正在使用的安装目录进行试验。

v0.9.1 的目录与菜单改动先运行以下专项：

```bash
python -m unittest discover -s tests -p test_installation_contract.py
python -m unittest discover -s tests -p test_bootstrap_contract.py
python -m unittest discover -s tests -p test_public_docs.py
```

应覆盖统一根目录的新安装、旧布局识别、显式自定义路径、只读检查不提问、不下载；交互菜单、无终端显式模式、EOF 退出及 sudo 不重复询问。目录迁移还须验证完整备份、配置和原生历史保留、路径映射不重复、服务覆盖保留，以及准备失败或启动失败能恢复旧布局。真实生产迁移只在任务空闲时执行，不主动制造业务故障。

本次引导脚本在 Linux 隔离环境运行 52 项通过，无跳过；包含 6 项真实终端交互检查：新装回车选择轻量、升级回车保留模式、非法输入、EOF、sudo 后不重复询问，以及标准输入为管道时从终端读取选择。另覆盖相对 `--root` 的 CLI 路径和显式 `--prefix` 的检查隔离。运行阶段断网，下载和包管理使用模拟边界，不调用模型或更改生产服务。

安装契约在 Linux 隔离环境实际运行 68 项全部通过，零跳过。真实离线安装验证默认四区目录、注册、独立轻量值班进程及 Web 重启；旧布局迁移真实重建虚拟环境，并核对数据库、密钥、历史、知识与日志摘要、旧 cron 与日志兼容链接，以及提交末期失败的完整回滚。容器无宿主挂载、断网、限制 512 MB 内存与 1 CPU，生产进程未改变。

自动核对改动的核心集成 219 项通过；针对性组合 161 项运行成功、其中 3 项平台跳过。最终补充的目标 JSON 验证 22 项通过，主机安全重试验证 10 项通过。前端八组相关检查共 209 项通过；长会话最新结论与增量事件语义有独立覆盖。所有模型与主机写任务测试使用隔离数据或模拟回复。

本轮全量摸底只运行一次：1342 项，初次结果为 2 个失败、13 个错误、22 个平台或环境跳过。其中“unknown 不可由普通 complete 直接改为 done”是本次引入的问题，修复后包含原测试的 44 项针对性复测全部通过；保留原有保护契约。其余历史项单列如下，不恢复已废弃架构：

| 分类 | 数量 | 原因 |
| --- | --- | --- |
| 旧配置示例断言失败 | 1 | `test_config_example_has_v073_keys` 仍要求已移除的 `required_checks` |
| 旧权限夹具初始化错误 | 10 | `test_perm_model` 与 `test_unified_web_permissions` 仍向已删除的 `permissions` 表写入 |
| 缺少历史测试夹具 | 2 | `test_agent_async_boundaries`、`test_lifecycle_consistency` 引用已移除的 phase 测试模块 |
| 废弃接口导入 | 1 | `test_settings_center_backend` 导入已移除的 `DECISION_PROMPT` |

前端全量摸底运行 11 个脚本：10 个通过，旧 `test_approval_ui.cjs` 在查找已删除的审批按钮时报 `TypeError`，与此前干净版本复现一致。未恢复旧审批界面。

公开文档与安装契约测试会验证正式文档链接、版本一致性、发行包内容和安装行为。构建命令及用户部署流程见 [安装手册](INSTALL.md)。

## 全量摸底

```bash
PYTHONPATH=.:tests python -m unittest discover -s tests -p 'test_*.py'
```

全量摸底与核心发布回归分开记录。部分历史测试仍引用已移除的测试夹具或旧权限语义，不能把加载失败当作通过，也不能为追求全绿恢复旧执行架构。此前一次摸底为 1037 项，包含 2 项旧语义失败、14 项旧夹具或接口初始化错误，以及 3 项平台跳过。

v0.8.3 本次摸底运行 1184 项，初次记录为 5 项失败、14 项错误和 4 项环境/平台跳过。其中本次错误文案兼容与文档版本切换涉及的 2 项已经修正并单独复测通过；剩余 3 项失败在未修改的 v0.8.2 源码上同样复现，分别要求旧配置键或已退役的逐动作审批语义。14 项错误来自旧权限表、已移除的夹具及旧接口导入。没有为这些历史用例恢复废弃实现。后续新增用例会改变总数。

发现失败时先区分当前功能回归、历史测试迁移和平台限制。核心链路必须通过，历史遗留需有明确分类。真实业务验收由部署者选择合适场景，不通过主动停止正常业务来制造测试故障。
