# 运维手册

适用于 **Ayana v0.8.2**，系统路径以默认安装为例。

## 日常使用

“事件”追踪故障，“Agent”承载原生任务，“审计”保留执行事实。核对结果时应同时查看工单、故障代次、执行台账和恢复依据。

- 处理未关闭工单时，执行记录绑定当前真实工单与代次。
- 同一主机可能有关联的多个工单，需要明确目标，系统不会猜测归属。
- 手动会话只有已关闭的历史关联时，后续独立任务可以省略工单 ID，继续使用会话台账；历史关联保留。
- 要开始全新的独立任务，使用 Agent 左上角“新建会话 → 连接会话”。
- 自动值班不会因为工单关闭而转成无工单写入。

会话顶部切换账号组只影响后续派发。离开视图或断开浏览器不等于停止任务；“停止任务”“暂停值班”等操作具有实际效果，应先确认当前工作。

## 核对任务与恢复

| 显示内容 | 含义 | 建议动作 |
| --- | --- | --- |
| 任务执行中 / 输入已排队 | 原生回执或队列仍持有当前工作 | 观察原生画面和近期事件 |
| 任务已中断 | 该轮未正常完成 | 核对最后执行记录，再选择是否恢复 |
| 执行结果待核对 | 无法确认写操作是否生效 | 先核对目标状态和台账，不直接重放 |
| 执行完成 | 命令已有完成事实 | 继续检查业务是否恢复 |
| 已恢复 | 已记录当前代次的匹配恢复证据 | 查看证据时间、目标与契约 |
| 已解决，恢复证据待核对 | 工单已解决但缺少可确认的当前恢复证据 | 保持准确结论，不当作已验证恢复 |

只有命令退出成功、模型输出“完成”或告警消失，都不足以单独证明故障恢复。

对于结果未知的写操作，在目标主机、日志或业务指标中核实后，使用工作台的核销入口选择“已执行”“未执行”或“仍未知”，并填写依据。新建会话、重启服务和删除会话都不能替代核对，也不能消除原有未知结果保护。

故障排查以读状态、日志和已有证据为主，不需要制造真实业务故障来检查安装是否可用。

## 服务与日志

```bash
sudo systemctl status ayana ayana-agent-runtime --no-pager
sudo journalctl -u ayana -n 100 --no-pager
sudo journalctl -u ayana-agent-runtime -n 100 --no-pager
curl --fail http://127.0.0.1:6200/health
```

也可使用安装时提供的状态与健康检查入口：

```bash
sudo bash /opt/ayana/deploy/ayana-setup.sh status --system
sudo bash /opt/ayana/deploy/ayana-setup.sh health --system
```

Web 与原生运行时分别管理。只需刷新 Web 进程时可运行：

```bash
sudo systemctl restart ayana
```

重启 `ayana-agent-runtime` 会影响原生服务和终端进程，应先等待任务空闲。完整代码升级也应在任务结束后进行；不能仅凭 Web 不再显示连接，就认定后台已经空闲。

## 备份与恢复

备份至少包含：

| 内容 | 默认位置 |
| --- | --- |
| 程序、依赖和版本 | `/opt/ayana`，包括虚拟环境 |
| 配置和所有加密秘密 | `/etc/ayana` |
| SQLite、知识库和运行数据 | `/var/lib/ayana` |
| 两个服务定义及自定义覆盖 | systemd 单元与对应的 drop-in 目录 |

数据库和秘密应成套保存。只保留程序无法恢复凭据、工单或执行台账。

安装器会报告更新备份位置，默认位于 `/opt/ayana-backups`。安装器快照覆盖受管程序、虚拟环境、配置、模型配置文件、SQLite 和服务单元；知识库及其他运行数据需要另行完整备份。

可以在确认任务空闲后制作完整停机快照。以下命令只停止 Ayana 自身服务，不操作受管主机业务：

```bash
backup_dir="/var/backups/ayana/$(date +%Y%m%d-%H%M%S)"
sudo install -d -m 700 "$backup_dir"
sudo systemctl stop ayana ayana-agent-runtime
sudo tar -czpf "$backup_dir/snapshot.tar.gz" -C / \
  opt/ayana etc/ayana var/lib/ayana \
  etc/systemd/system/ayana.service \
  etc/systemd/system/ayana-agent-runtime.service
sudo systemctl start ayana-agent-runtime ayana
```

如使用了自定义路径或 systemd drop-in，请把相应路径加入快照。停机后整体保存数据目录可以一并保存 SQLite 的数据库和 WAL 文件；运行中备份数据库则应使用 SQLite 在线备份接口，不能只复制单个 `.db`。

托管升级优先使用安装器报告的配对备份回滚。核对版本、路径、时间和需要保留的新执行事实后执行：

```bash
sudo python3 /opt/ayana/deploy/installation.py rollback --system \
  --backup-dir /opt/ayana-backups \
  --backup /opt/ayana-backups/CHOSEN-BACKUP
curl --fail http://127.0.0.1:6200/health
```

安装器会检查任务状态，先保存回滚前的救援快照，再恢复受管代码、对应数据库、配置与原有服务定义。使用自定义目录时传入原安装的路径参数。用户模式应先正常停止两个进程，再使用 `--user` 和原路径回滚。

完整停机快照用于灾难恢复，应在隔离目录中核对后配套恢复。不要直接将旧压缩包覆盖到正在运行的程序目录，以免混入不同版本文件。恢复后核对服务、模型配置、账号组、工单和写台账，再恢复使用。

## 常见问题

### 安装时提示缺少依赖或 CLI

使用当前 README 中的 `bootstrap.sh --system` 命令，正常安装会自动准备系统依赖与缺少的官方 CLI。系统软件源必须能提供 Python 3.11+，下载官方 CLI 需要能够访问小米安装服务。失败时查看脚本最后报告的原因，修复网络或软件源后重新运行。

`--check`、`--no-start`、用户模式和直接运行解压包中的 `install.sh` 不会自动安装这些前置条件。`--mimo-bin` 应填写真实可执行文件路径；系统服务启用 `ProtectHome`，不能使用指回 `/root` 或用户主目录的软链接。已有 CLI 不会因更新 Ayana 而自动升级。

### 管理员无法登录

先核对用户名、TOTP、时间同步和登录锁定状态。忘记密码时，用实际注册的用户名执行本机重置：

```bash
sudo -u ayana /opt/ayana/.venv/bin/python -m ayana.main /etc/ayana/config.json \
  --reset-admin-password --reset-admin-user YOUR_USERNAME
```

按命令输出读取数据目录中的一次性密码文件。重置会撤销该账号已有登录会话，并要求下次登录修改密码；完成后删除一次性密码文件。不要删除数据库、重新生成秘密或清空用户表来尝试重开注册。

### Web 能打开，Agent 暂不可用

在模型设置中核对 CLI 路径、Base URL、模型 ID、API Key 和“已保存配置”的验证状态。检查原生运行时日志，确认 tmux、CLI 及其依赖对服务用户可用。

首次模型尚未配置时，运行时等待配置是正常现象。模型验证通过后再连接会话；不用反复重装程序或删除运行数据。

### 连接测试失败

核对当前有效账号组是否含目标主机、主机地址与端口是否正确、凭据是否存在、目标账号是否有相应命令权限。所选组缺失时系统不会自动换到其他组。

“主机指纹已变化”需要先确认服务器是否重装或更换；不应直接把新扫描到的指纹当作可信指纹。

### 页面显示执行中，但看不到进展

先连接相同的原生会话，查看任务状态、最新回执和执行记录。确认是否正在等待模型、网络、目标状态核对或人工输入。保留未知写结果；不要重复提交原命令来测试是否“卡住”。

### 告警已消失，但没有显示已恢复

检查告警与资产的绑定、当前故障代次、监控样本新鲜度和恢复契约。没有匹配证据时，系统会保持未证实的结论；先补齐观测，不通过手工改状态来制造恢复结果。

### 监控配置保存失败

检查 Prometheus 地址、配置目录、`promtool` 和重载方式。使用本地配置目录时，该目录必须同时允许 Web 与原生运行时服务写入；systemd 的 `ReadWritePaths` 也需包含它。需要重载服务定义时，先等待当前任务空闲。
