# Ayana

Ayana 是一个以事件为中心的运维工作台。接入告警后，MiMoCode 在同一个原生会话内调查、执行主机命令、核对恢复证据；你可以在 Web 中观察过程、接管会话，并追溯每次操作。

当前发布版本：**v0.8.3**。

```text
告警 / 业务检查 → 工单与故障代次 → MiMoCode 原生会话
                                  ↓
                         MCP 查询与 host.exec
                                  ↓
                   执行台账 / 恢复证据 / 通知与审计
```

| 功能 | 你可以做什么 |
| --- | --- |
| 事件与工单 | 接入 Alertmanager 或原生业务检查，追踪故障、复发代次与恢复依据 |
| 原生 Agent 工作台 | 观察、接管、暂停、恢复任务，查看当前真实工具步骤、目标、错误与待核对结果 |
| SSH 账号组 | 设置全局默认组，按会话覆盖；实际权限由目标服务器账号和 sudo 决定 |
| 主机与监控 | 管理连接、主机指纹、凭据、端口检查、服务检查和受限命令检查 |
| 资源状态 | 依据有效原生检查和已接入指标显示主机健康，区分异常、未观测和数据不足 |
| 通知与知识 | 配置通知渠道、检索运维知识、记录处置结论 |
| 节点守望 | 可选配对实例心跳，观察对端在线情况 |

命令执行成功和故障恢复分别记录。恢复结论需要匹配目标、故障类型和当前代次的证据；结果未知的写操作会保留台账，防止盲目重复执行。

未接入 Prometheus 时，启用且结果新鲜的原生检查仍可给出主机健康状态；CPU、内存等指标保持暂无数据。工作台的当前步骤来自真实工具事件，参数被拒绝会显示原因，模型没有输出的文字不会被补写。

## 安装

在使用 systemd 的 Linux 服务器上复制执行以下命令。root 账号直接安装，普通账号会请求 sudo；脚本会自动准备系统依赖和官方 MiMoCode CLI，安装 Ayana、启动两个服务，并检查 Web 是否正常响应：

```bash
curl -fsSL https://raw.githubusercontent.com/wwqjss/Ayana/main/deploy/bootstrap.sh -o ayana-bootstrap.sh &&
bash ayana-bootstrap.sh --system
```

完成后，终端会显示服务状态、访问方式和首次注册令牌的位置。在远程服务器安装时，按输出提示建立 SSH 转发，再用本机浏览器打开 `http://127.0.0.1:6200`；模型接口和 API Key 在页面中设置。

脚本支持 apt、dnf 或 yum，要求系统软件源能提供 Python 3.11+。已有配置与可用 CLI 会沿用。Ayana 下载使用最新正式 Release 并校验 SHA256。系统安装默认使用：

- 程序：`/opt/ayana`
- 配置：`/etc/ayana`
- 数据与运行时：`/var/lib/ayana`
- Web：`http://127.0.0.1:6200`
- 服务：`ayana`、`ayana-agent-runtime`

完整安装、固定版本、用户模式和升级步骤见 [安装手册](docs/INSTALL.md)。

## 第一次使用

1. 读取数据目录中的 `setup-admin.token`，在首次注册页面填写令牌，自行设置管理员用户名和密码。
2. 在用户菜单的设置中填写模型接口、模型 ID 和 API Key，执行“保存并验证”。
3. 在“连接”中登记主机、确认 SSH 指纹并配置账号组；在 Agent 设置中选定默认账号组。
4. 点击“新建会话 → 连接会话”，在原生输入框中提出任务。
5. 按需接入 Prometheus、Alertmanager 和通知渠道。没有 Prometheus 时也可以使用原生业务检查。

会话未单独选择账号组时继承全局默认。所选组缺少目标主机账号时会明确报错，不会借用其他组。

## 文档

- [文档导航](docs/README.md)
- [安装与升级](docs/INSTALL.md)
- [配置说明](docs/CONFIGURATION.md)
- [日常运维与故障排查](docs/OPERATIONS.md)
- [MCP 操作接口](docs/mcp-operations.md)
- [版本说明](CHANGELOG.md)

## 开发

依赖和静态资源打包规则由 `pyproject.toml` 统一声明。

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m unittest discover -s tests -q
```

测试范围与运行方式见 [测试说明](docs/TESTING.md)。

## 许可证

[MIT License](LICENSE)
