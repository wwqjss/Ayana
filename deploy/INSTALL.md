# Ayana 0.3.0 部署边界（P0-01）— 隔离验收用

**状态**：准备完成，**未切换生产 KANATA**。生产切换需单独批准窗口。

## 身份与目录

| 路径 | 属主 | 权限 | 说明 |
|------|------|------|------|
| `/opt/ayana/`（代码、.venv、knowledge/） | `root:ayana` | `750` / 文件 `640` | **ayana 不可写**；发布由管理员 |
| `/etc/ayana/config.json` | `root:ayana` | `640` | 生产现为 0666，**必须收紧** |
| `/etc/ayana/secrets.json` | `root:ayana` | `640` 或 `600` | 不入 git |
| `/var/lib/ayana/`（db、run、lock） | `ayana:ayana` | `750` | 应用可写 |
| `/var/log/ayana/` | `ayana:ayana` | `750` | 应用可写 |
| `/var/lib/ayana/.ssh/` | `ayana:ayana` | `700` | 独立 SSH 身份 / known_hosts |
| 主机闸 `/usr/local/sbin/astrbot-nt-command` | `root:root` | `755` | **ayana 不可改** |
| `/etc/astrbot-prom-alert/commands.json` | `root:root` | `640` | **ayana 不可改** |
| sudoers / authorized_keys forced-command | `root` | 默认 | **ayana 不可改** |

**不变式**：应用运行身份无法修改 dispatcher / commands.json / sudoers。

## 单实例

- 应用启动时对 `/var/lib/ayana/ayana.lock` 做 `flock(LOCK_EX|LOCK_NB)`
- 失败立即退出，不影响已运行实例
- systemd `Type=simple` + 自然单副本

## 端口与消费者顺序

```text
flock → schema → bind HTTP/WS → 成功后启动 outbox/reconcile/agent
```

绑定失败不拉起后台消费者（已在 `main.start()` 满足：site.start 在 create_task 之前）。

## 控制面隔离

- runbook `match_runbook` 拒绝对象名含 `ayana` 的自动规则
- 前置判据 `control_plane_object` → unsatisfied
- **禁止**把 Ayana 自身登记进可自动重启对象

## 迁移步骤（待批准，未执行）

1. 隔离机：创建 `ayana` 用户，装 unit，放代码到 `/opt/ayana`，db 到 `/var/lib/ayana`
2. 验收：非 root 启动、flock 拒双实例、`/health` ok、写通道仍走主机闸
3. 生产窗口：`systemctl stop` 旧 setsid 进程 → 拷贝 db（SQLite backup API）→ 改目录属主 → `systemctl enable --now ayana`
4. 回退：停 unit → 旧 `start.sh` root 路径仍可用（保留 `/root/Ayana` 至稳定）

## 回退

- 保留 `/root/Ayana` + `start.sh` 直至新 unit 连续稳定
- 不在同窗口改主机闸
