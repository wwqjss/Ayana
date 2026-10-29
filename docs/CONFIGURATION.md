# 配置说明

适用于 **Ayana v0.8.1**。系统安装路径以安装器默认值为例；自定义路径时请对应替换。

## 配置放在哪里

| 位置 | 内容 |
| --- | --- |
| `/etc/ayana/config.json` | 监听地址、数据路径、运行时路径及接入设置 |
| `/etc/ayana/secrets.json` | 认证、加密和渠道所需的秘密 |
| `/var/lib/ayana/ayana.db` | 主机、账号组、工单、会话、执行台账、审计及 Web 设置 |
| `/var/lib/ayana/agent-workspace` | MiMoCode 工作目录 |
| `/var/lib/ayana/agent-runtime` | 原生运行时状态 |
| `mimo_config_dir` 指定的目录 | 服务用户的 MiMoCode 模型与 API Key 配置，文件权限为 0600 |

安装器生成初始配置和秘密，已有秘密不会被覆盖。备份时应同时保留数据库和对应的秘密文件：丢失加密密钥会影响已保存凭据的解密。

启动态配置的优先级为：受支持的秘密环境变量 `AYANA_*` → `secrets.json` → `config.json` → 内置默认值。并非任意配置项都支持环境变量；支持列表见 `ayana/config.py` 的 `SECRET_KEYS`。

Web 保存的模型配置、监控地址和账号组选择存于数据库或受管运行时配置中。后续请在对应页面修改，避免把配置文件当作这些运行态设置的唯一来源。

## 首次登录与模型

首次启动在数据库同目录生成一次性注册令牌 `setup-admin.token`。打开 Web 注册页面，填写令牌，自行设置管理员用户名和密码。注册完成后令牌失效；可删除该文件，并在账号安全设置中启用 TOTP。

用户菜单 → 设置 → 模型中填写：

| 项目 | 填写方式 |
| --- | --- |
| Base URL | 模型提供方的兼容 API 地址 |
| 模型 ID | 提供方实际开放的模型名称 |
| API Key | 对应接口的密钥；界面不会回填明文 |

“测试”和“保存并验证”会发起真实模型请求。只有已保存配置验证通过，才会作为可用运行时配置。更换接口地址或密钥后需要重新验证。

模型 API Key 保存在服务用户的本地 MiMoCode 配置文件中；它与保存在数据库中的 SSH 凭据是不同的数据。备份应覆盖该配置目录，通常位于数据目录的 `.config/mimocode` 下。

MiMoCode CLI 必须能由运行 Ayana 的用户执行，并支持当前原生会话、回执、恢复和终端接口。模型设置中的安装状态有助于判断可执行文件路径；路径变更请在 `config.json` 中设置 `mimo_bin`，并在任务空闲时重启相关服务。首次尚未配置模型时，原生运行时可以保持运行并等待配置，先在 Web 中完成模型验证即可。

## SSH 账号组

在“连接”中登记主机、导入密码或密钥，并将账号加入账号组。首次连接应核对目标主机指纹；指纹变化需要重新确认服务器身份。

在 Agent 设置中选择一个**全局默认账号组**，会话和后台检查统一使用它。会话顶部可以设置当前会话的覆盖组，或选择“跟随默认”；切换只影响之后派发的命令。

组名只是标签，权限由目标 SSH 用户和 sudo 配置决定。调查和变更使用同一个有效账号组，工具的 `channel` 参数仅标注用途。指定组没有目标主机账号时应补齐配置，系统不会自动换组。

账号组定义、端点凭据和指纹都属于数据，应与数据库一起备份。

## 服务与网络

| 配置项 | 默认值 | 用途 |
| --- | --- | --- |
| `http_host` / `http_port` | `127.0.0.1` / `6200` | Web 控制台和 HTTP 接入 |
| `ws_host` / `ws_port` | `127.0.0.1` / `6199` | 可选 OneBot 反向 WebSocket |
| `mimo_serve_port` | `6290` | 本机 MiMoCode 服务 |
| `agent_tui_proxy_port` | `6291` | 原生终端代理 |
| `db_path` | 系统安装为绝对数据路径 | SQLite 数据库 |
| `knowledge_dir` | 安装器设置的数据目录 | 运维知识库 |
| `mimo_bin` | 安装时指定的绝对路径 | 兼容 MiMoCode CLI |
| `mimo_serve_external` | 系统安装为 `true` | 由独立原生服务持有模型进程 |
| `agent_tui_enabled` | 系统安装为 `true` | 启用原生终端代理 |
| `agent_runtime_home` / `mimo_workdir` | 数据目录及其 `agent-workspace` 子目录 | 原生服务的 HOME 和工作目录 |
| `mimo_config_dir` | 数据目录下的 `.config/mimocode` | 受管模型配置目录 |

系统安装将 Web 和原生运行时分成两个服务。原生服务与代理保持本机访问；远程使用 Web 时可配置 HTTPS 反向代理，代理需支持 WebSocket。

普通配置文件改动需要重启相应服务。涉及模型、数据库或运行时路径的改动，应等当前任务结束后按[运维手册](OPERATIONS.md)操作。

## 监控和通知按需接入

**原生业务检查**：在“资源 → 业务检查”创建端口、服务或受限命令检查，也可以在 MiMoCode 中使用配置工具。检查失败产生工单，成功结果可按匹配契约提供恢复证据。

**Prometheus / Alertmanager**：在设置的监控接入中填写实际地址。程序默认地址为 `http://127.0.0.1:9090` 和 `http://127.0.0.1:9093`；未部署这些组件时无需为了启动 Ayana 安装它们。使用指标恢复验证时，应保证数据标签能正确绑定登记主机和目标。

Alertmanager 接收路径由 `alertmanager_webhook_path` 控制，默认 `/hooks/alertmanager`。发送方必须使用 `webhook_token` 所对应的认证配置；接入时核对地址、token 和网络连通性。

例如，在 Alertmanager 中配置 Bearer 认证，并把对应 token 放入其服务器上的受保护文件：

```yaml
receivers:
  - name: ayana
    webhook_configs:
      - url: https://ayana.example.com/hooks/alertmanager
        http_config:
          authorization:
            type: Bearer
            credentials_file: /etc/alertmanager/ayana-webhook.token
```

该文件内容需与 Ayana 的 `webhook_token` 一致。修改 Alertmanager 配置后按其部署方式校验和重载。

**通知**：在通知设置中选择渠道类型并填写连接信息。QQ / 企业微信等集成需要各自的机器人或服务端配置。只有启用并配置的渠道参与投递；测试发送应由使用者显式操作。

**节点守望**：在“连接 → 节点守望”配对两个实例，核对双方指纹后设置发送或接收角色。它报告心跳和旁路观测结果，不把网络失联直接认定为物理宕机。

## 秘密与恢复

`secrets.json` 中的核心秘密包括 `webhook_token`、`onewbot_token`、`web_auth_pepper`、`totp_encrypt_key`、`ssh_credential_key`、`notify_channel_key`。其中前两个在启动时要求存在，即使尚未启用对应外部接入；安装器会生成它们。

不要通过重新运行秘密生成器来修复登录或解密问题。现有秘密应保持连续，轮换时需要单独制定凭据和数据迁移方案。忘记管理员密码时使用[密码重置流程](OPERATIONS.md#管理员无法登录)。
