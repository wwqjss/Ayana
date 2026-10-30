# 安装、升级与回滚

适用于 **Ayana v0.8.3**。这是项目的安装手册，命令以 Linux 系统安装的默认路径为例。

## 1. 安装条件

| 项目 | 要求 |
| --- | --- |
| 操作系统 | 支持 systemd 的 Linux；用户模式可不使用 systemd |
| 系统权限 | root 可直接安装；普通账号会请求 sudo |
| 软件源 | apt、dnf 或 yum 可用，能提供 Python 3.11+；缺少的系统依赖由引导脚本安装 |
| 系统工具 | Bash 和 curl 用于下载引导脚本；tmux、OpenSSH 等运行依赖由脚本准备 |
| MiMoCode | 首次缺少 CLI 时自动从小米官方安装；已有配置与可用 CLI 沿用 |
| 网络 | 能访问模型接口、受管主机 SSH，以及选择接入的监控或通知服务 |

使用当前系统软件源能提供 Python 3.11+ 的 Debian / Ubuntu 或 dnf / yum 发行版。较旧发行版的软件源若无法满足该版本，脚本会说明缺失条件并停止；先准备受支持的 Python，或使用较新的系统。

自动准备仅用于引导脚本的正常 `--system` 安装。`--check`、`--no-start` 和用户模式不会自动安装系统依赖或下载 CLI。直接从源码或解压包运行 `deploy/install.sh` 时，也应先自行准备 Python 3.11+、venv、pip、tmux、OpenSSH 客户端和兼容 MiMoCode CLI。

Prometheus、Alertmanager 和机器人渠道均按需接入，不是打开 Web 的前提。

## 2. 安装最新正式版本

```bash
curl -fsSL https://raw.githubusercontent.com/wwqjss/Ayana/main/deploy/bootstrap.sh -o ayana-bootstrap.sh &&
bash ayana-bootstrap.sh --system
```

引导脚本从 GitHub Release 下载安装包，要求存在匹配的 SHA256 校验文件，校验通过后调用安装器。它会准备缺少的系统依赖；首次没有可用 MiMoCode CLI 时，通过小米官方 `https://mimo.xiaomi.com/install` 安装 v0.1.16，并把可执行文件放在系统服务可读取的公共目录。已安装的 CLI 和现有 `mimo_bin` 配置会沿用，更新 Ayana 不会顺带升级 CLI。已有安装找不到其 CLI 时会停止并提示修复路径，不会自动换成另一个版本。

系统服务以专用用户 `ayana` 运行。若官方 CLI 已装在 root 的 `~/.mimocode/bin/mimo`，脚本会复制实际二进制到公共目录，不使用指向 `/root` 的软链接。需要使用自行准备的兼容 CLI 时，可增加 `--mimo-bin /usr/local/bin/mimo`；指定路径及其依赖必须对服务用户可用。

脚本会安装并启动 `ayana` 和 `ayana-agent-runtime`，等待 Web 健康检查通过后才报告成功，随后显示访问方式与首次注册令牌的位置。安装失败会明确退出并显示原因。

需要固定本次版本时：

```bash
env AYANA_VERSION=v0.8.3 bash ayana-bootstrap.sh --system
```

也可在 Release 页面下载版本安装包及同名 `.sha256`，校验并解压，然后从解压目录运行 `deploy/install.sh`。依赖由 `pyproject.toml` 声明，安装器创建独立虚拟环境并执行项目安装；安装包包含完整 Web 静态资源。

安装器保留已有数据和秘密。只有首次安装才生成初始配置和随机秘密。

后文手动管理服务和读取受保护文件的示例使用 sudo；已经是 root 时可省略 sudo。

## 3. 路径和服务

| 内容 | 系统安装默认路径 |
| --- | --- |
| 程序与虚拟环境 | `/opt/ayana`、`/opt/ayana/.venv` |
| 配置与秘密 | `/etc/ayana/config.json`、`/etc/ayana/secrets.json` |
| 数据库与运行数据 | `/var/lib/ayana` |
| 原生工作目录 | `/var/lib/ayana/agent-workspace` |
| 原生运行时状态 | `/var/lib/ayana/agent-runtime` |

安装器生成两个服务：

- `ayana.service`：Web、告警接入和业务后台。
- `ayana-agent-runtime.service`：MiMoCode 服务和原生会话的独立运行时。

```bash
sudo systemctl status ayana ayana-agent-runtime --no-pager
curl --fail http://127.0.0.1:6200/health
```

安装完成时已检查两个服务和 `/health`；以上命令可用于之后再次查看状态。`/health` 检查 Web 进程是否正常响应。模型可用性、SSH 连接和业务恢复需要在相应页面分别核对。尚未配置模型时，原生运行时等待配置是正常现象；先登录 Web 完成设置。

## 4. 首次注册与设置

读取一次性注册令牌：

```bash
sudo cat /var/lib/ayana/setup-admin.token
```

打开 `http://127.0.0.1:6200`，在注册页面填写令牌，并自行设置管理员用户名和密码。用户名支持 2–32 位字母、数字、点、下划线或连字符；密码至少 10 位。注册成功后令牌失效，可以删除令牌文件：

```bash
sudo rm -- /var/lib/ayana/setup-admin.token
```

远程服务器默认仍监听本机地址。按安装完成时的提示，在自己电脑上使用 SSH 转发：

```bash
ssh -L 6200:127.0.0.1:6200 your-user@ayana-server
```

保持 SSH 连接，在本机浏览器打开 `http://127.0.0.1:6200`。如果已配置 HTTPS 反向代理，可使用代理地址；需要自行调整初始监听地址时可用 `--http-host`。随后依次完成：

1. 用户菜单 → 设置 → 模型：填写 Base URL、模型 ID 和 API Key，执行“保存并验证”。这会发起真实模型请求。
2. 连接：登记主机、配置凭据、核对指纹并建立账号组。
3. Agent 设置：选择全局默认账号组。
4. Agent → 新建会话 → 连接会话：进入原生输入框，开始一个明确的任务。
5. 按需配置监控地址和通知渠道；账号安全设置中可启用 TOTP。

完整配置说明见 [CONFIGURATION.md](CONFIGURATION.md)。

## 5. 安装选项

在已解压的安装包或源码根目录中使用：

```bash
bash deploy/install.sh --help
sudo bash deploy/install.sh --system --check --mimo-bin /usr/local/bin/mimo
```

`--check` 检查环境和已安装状态，不安装依赖或变更服务。引导脚本的检查模式只调用已安装的本地检查器，不下载文件；尚未安装时会明确报告本地检查器不存在。检查已解压的安装包时直接调用 `deploy/install.sh`。

| 参数 | 用途 |
| --- | --- |
| `--system` | 系统安装，要求 root，正常引导安装时自动准备依赖并启动两个服务 |
| `--user` | 当前用户安装，默认模式，不安装系统服务 |
| `--prefix PATH` | 程序目录 |
| `--data PATH` | 数据目录 |
| `--conf-dir PATH` | 配置和秘密目录 |
| `--http-host HOST` / `--http-port PORT` | 初始 Web 监听设置 |
| `--mimo-bin PATH` | 可选，自行准备的 MiMoCode 可执行文件；指定后不自动安装替代 CLI |
| `--no-start` | 自备依赖，只准备安装文件，不建立系统账号或启动服务；正式启用时再次正常安装 |
| `--force` | 更新已安装程序和服务定义 |
| `--backup-dir PATH` | 备份父目录，系统默认 `/opt/ayana-backups` |
| `--skip-pip` | 跳过依赖安装，仅适用于已准备好匹配依赖的环境 |

可通过 `PYTHON_BIN` 选择 Python，例如 `PYTHON_BIN=python3.12 bash deploy/install.sh --check`。

用户模式需要自行准备 Python 3.11+、venv、pip、tmux、OpenSSH 客户端和兼容 MiMoCode CLI。默认安装位置为 `~/.local/share/ayana`、`~/.local/share/ayana-data` 和 `~/.config/ayana`。按安装器输出的命令分别启动 Web 与原生运行时；需要长期运行时请由自己的进程管理器托管。

用户模式更新前，先结束任务、释放会话接管，再正常停止自己启动的 Web 与原生运行时两个进程。安装器不会替用户模式调用 systemd；任一进程仍在线或状态无法确认时会拒绝更新。

## 6. 更新现有安装

先在 Agent 页面核对原生任务、队列和待核对写结果，并释放会话接管。等待当前工作结束，再进入维护窗口；不要为了验证升级主动停止受管主机业务。

1. 下载新版本安装包并核对校验值。
2. 确认两个服务都可安全停止，记录当前版本和备份位置。
3. 备份代码、配置、秘密、数据库及运行数据，见[备份与恢复](OPERATIONS.md#备份与恢复)。
   安装器保留现有配置；核对其中 `mimo_serve_external=true`、`agent_tui_enabled=true`，并为 `mimo_bin` 和原生运行目录填写实际路径。字段说明见[配置手册](CONFIGURATION.md)。
4. 从新包目录运行安装器，沿用原来的路径参数：

```bash
sudo bash deploy/install.sh --system --force --mimo-bin /usr/local/bin/mimo
```

5. 查看安装器报告和两个服务状态，确认 `/health`、登录、模型已保存配置、账号组和现有业务检查均可正常读取。
6. 在浏览器刷新页面，再由使用者选择业务验收任务。

已安装实例也可使用同一生命周期入口更新到明确版本：

```bash
sudo bash /opt/ayana/deploy/ayana-setup.sh update --system --ref v0.8.3 \
  --mimo-bin /usr/local/bin/mimo
```

该方式从项目仓库获取指定版本；默认引用为当前 `main`。生产更新建议指定发布 tag，或通过引导脚本使用正式 Release。

Web 重启和完整升级具有不同范围。只重启 Web 可保留独立运行时中的任务；更新运行时、核心代码或数据库时，应先等待任务结束，再按完整升级流程执行。

## 7. 回滚

优先使用安装器为该次操作记录的完整备份，恢复与旧程序匹配的配置、数据和服务定义。数据库升级后的回滚必须配套恢复对应备份，不能只替换程序文件。

安装器快照可通过统一入口回滚，使用明确选定的时间戳目录：

```bash
sudo bash /opt/ayana/deploy/ayana-setup.sh rollback --system \
  --backup /opt/ayana-backups/CHOSEN-TIMESTAMP
```

自定义安装路径时，沿用相同的 `--prefix`、`--data`、`--conf-dir` 和 `--backup-dir`。回滚也要求当前工作已结束、没有待核对的写结果。

如果新版本已经接入新告警或执行过操作，先保留当前状态和台账，再决定是否回退数据，防止覆盖新事实。具体备份内容和恢复命令见[运维手册](OPERATIONS.md#备份与恢复)。

## 8. 从源码开发

```bash
git clone https://github.com/wwqjss/Ayana.git
cd Ayana
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

需要固定发布源码时检出对应 tag。完整原生会话运行仍需要前述 Linux 工具、兼容 MiMoCode CLI 和可用模型配置。开发测试见[测试说明](TESTING.md)。
