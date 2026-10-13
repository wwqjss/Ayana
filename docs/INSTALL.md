# Ayana 安装手册

适用于 **Ayana v0.7.2**。本文只描述安装与运维，不含任何真实凭据。

---

## 1. 环境要求

| 项 | 要求 |
|----|------|
| 操作系统 | Linux（推荐）；macOS 可开发用 |
| Python | 3.11+（推荐 3.12） |
| 磁盘 | ≥ 1 GB（含日志与 SQLite） |
| 网络 | 出站 SSH（受管主机）、可访问 Prometheus / Alertmanager（可选） |
| 权限 | 专用系统用户 `ayana`；**不要**用 root 长期跑应用 |

依赖见仓库 `requirements.txt`：`aiohttp`（Web）、`cryptography`（凭据/TOTP 加密，强烈建议）、`paramiko`（Web 终端）。目标机需要 `ssh` / `ssh-keyscan`。

---

## 2. 获取代码

```bash
git clone https://github.com/wwqjss/Ayana.git
cd Ayana
```

本地若另有 `ayana-v0.7.2-install.tar.gz` 发布包，可解压后同样进入目录安装；**以 GitHub 仓库为准**。

---

## 3. 一键安装（推荐）

### 3.1 从 GitHub 拉安装包（无需先 clone）

```bash
# 下载 Release 安装包
curl -fsSL https://github.com/wwqjss/Ayana/releases/download/v0.7.2/ayana-v0.7.2-install.tar.gz -o ayana.tgz
echo 'a6270381b364598f14eaf4ff470998588aff26f60d3fd7bf0fd8c2f3f8cf90e3  ayana.tgz' | sha256sum -c -
tar -xzf ayana.tgz && cd ayana-pkg

# 只检查（不改系统）
bash deploy/install.sh --check

# 安装：缺啥装啥，已装完整则跳过
sudo bash deploy/install.sh --system
# 或无 systemd：bash deploy/install.sh --user
```

也可用包内引导脚本（内部等价于上面下载+安装）：

```bash
# 需先有 bootstrap.sh（源码 deploy/bootstrap.sh，或自行下载 raw）
bash deploy/bootstrap.sh --system
```

校验：Release 资产 `ayana-v0.7.2-install.tar.gz`  
SHA256 `a6270381b364598f14eaf4ff470998588aff26f60d3fd7bf0fd8c2f3f8cf90e3`

### 3.2 已有源码/解压包

**先检查（不改动系统）**

```bash
bash deploy/install.sh --check              # 用户模式
sudo bash deploy/install.sh --system --check
```

**系统级（root + systemd）**

```bash
sudo bash deploy/install.sh --system
```

**当前用户（无 systemd）**

```bash
bash deploy/install.sh --user
```

脚本会：

1. **环境预检**：Python ≥ 3.11、包完整、磁盘、权限/systemd
2. **检查通过且已装完整 → 跳过安装**（不重复写盘、不覆盖配置）
3. **有缺失才装对应项**（代码 / venv / deps / secrets / config / unit）
4. **生成** `secrets.json`（0600，不覆盖已有文件）— 无需手填密钥
5. 写 `config.json`：`db_path` / `log_file` 指向**数据目录**（默认 `/var/lib/ayana` 或 `~/.local/share/ayana-data`）
6. `--system` 时创建 `ayana` 用户、安装并启动 `ayana.service`

需要强制重装代码或单元时加 `--force`（才会 `rsync --delete`）。

完成后按脚本输出：查日志中的 bootstrap 口令文件 → 浏览器改密 → 删口令文件。  
NapCat / 企微**可选**，不影响 Web 登录。

常用参数：`--prefix` `--data` `--conf-dir` `--http-host` `--http-port` `--skip-pip`。

也可单独生成秘密：

```bash
python3 scripts/gen-secrets.py -o /etc/ayana/secrets.json
```

---

## 4. 目录与用户（生产）

```bash
sudo useradd --system --home /var/lib/ayana --shell /usr/sbin/nologin ayana
sudo install -d -o root -g ayana -m 750 /opt/ayana
sudo install -d -o ayana -g ayana -m 750 /var/lib/ayana /var/log/ayana
sudo install -d -o root -g ayana -m 640 /etc/ayana
```

| 路径 | 属主 | 权限 | 说明 |
|------|------|------|------|
| `/opt/ayana/` | `root:ayana` | `750` | 代码与 venv，应用只读 |
| `/etc/ayana/config.json` | `root:ayana` | `640` | 配置 |
| `/etc/ayana/secrets.json` | `root:ayana` | `600` | 秘密 |
| `/var/lib/ayana/` | `ayana:ayana` | `750` | DB、锁、**bootstrap 口令文件** |
| `/var/log/ayana/` | `ayana:ayana` | `750` | 日志 |

---

## 5. 安装依赖

```bash
cd /opt/ayana
sudo python3 -m venv .venv
sudo .venv/bin/pip install -U pip
sudo .venv/bin/pip install -r requirements.txt
# 生产建议显式安装：
sudo .venv/bin/pip install aiohttp cryptography paramiko
```

将源码放到 `/opt/ayana`（保持 `ayana/` 包目录与 `knowledge/`）。

---

## 6. 配置

```bash
sudo cp /opt/ayana/config.example.json /etc/ayana/config.json
sudo chmod 640 /etc/ayana/config.json
```

编辑 `config.json`（示例字段）：

```json
{
  "ws_host": "127.0.0.1",
  "ws_port": 6199,
  "http_host": "127.0.0.1",
  "http_port": 6200,
  "db_path": "/var/lib/ayana/ayana.db",
  "log_file": "/var/log/ayana/ayana.log",
  "prometheus_url": "http://127.0.0.1:9090",
  "alertmanager_url": "http://127.0.0.1:9093",
  "auto_remediation_enabled": false
}
```

**不要**把 `http_host` 设成 `0.0.0.0`，除非前面有反向代理与 TLS。

### 秘密（secrets.json）

```bash
sudo install -o root -g ayana -m 600 /dev/null /etc/ayana/secrets.json
sudo -u root tee /etc/ayana/secrets.json >/dev/null <<'EOF'
{
  "onewbot_token": "<随机长令牌，可选 IM>",
  "webhook_token": "<Alertmanager webhook Bearer>",
  "web_auth_pepper": "<独立随机串，勿与 onewbot_token 相同>",
  "totp_encrypt_key": "<独立随机串>",
  "ssh_credential_key": "<独立随机串>",
  "notify_channel_key": "<独立随机串>"
}
EOF
```

生成示例：

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

也可用环境变量 `AYANA_*` 覆盖（见 `ayana/config.py` 的 `SECRET_KEYS`）。

**注意**：

- `web_auth_pepper` 用于口令哈希；**与 `onewbot_token` 隔离**。若历史库用旧 pepper，设置新 pepper 后旧口令仍可登录，并在登录成功后自动迁移到新 pepper。
- `totp_encrypt_key` 缺失时 TOTP 秘密可能明文入库——生产必须配置。
- **禁止**把真实 token 写进聊天、截图或仓库。

---

## 7. 首次启动与管理员

```bash
sudo -u ayana /opt/ayana/.venv/bin/python -m ayana.main /etc/ayana/config.json
```

1. 观察日志：出现 `BOOTSTRAP admin created` 与口令文件路径（通常在 DB 目录）。
2. 打开 `http://<主机>:6200`，用户 `admin`，粘贴临时口令。
3. 界面会要求**修改密码**（至少 10 位）。
4. 删除口令文件：`rm -f /var/lib/ayana/bootstrap-admin.password`。
5. 建议启用 **2FA**（控制台 → 2FA）。

口令文件权限 0600；**不会**写入应用日志。若文件丢失，用运维流程重置（停机改库或重装空库），不要在日志里找口令。

---

## 8. systemd

```bash
sudo cp /opt/ayana/deploy/ayana.service /etc/systemd/system/ayana.service
# 按实际路径调整 ExecStart / ReadWritePaths
sudo systemctl daemon-reload
sudo systemctl enable --now ayana
sudo systemctl status ayana
```

`deploy/ayana.service` 要点：

- `User=ayana`，非 root
- `ProtectSystem=strict`，仅 `/var/lib/ayana`、`/var/log/ayana` 可写
- 单实例由应用 `flock` + systemd 保证

反向代理（Nginx 示例）终止 TLS 后转 `127.0.0.1:6200`；应用侧 Cookie 已 `HttpOnly` + `SameSite=Lax`。

---

## 9. 验收清单

- [ ] `GET /health` 返回 `ok: true`
- [ ] 未登录 `GET /ready` 仅返回 `ok/version`（无内部明细）
- [ ] 能用 bootstrap 口令登录并强制改密
- [ ] 改密后旧会话失效
- [ ] 非 admin 无法自批写操作（若建了运维账号）
- [ ] 自定义检查拒绝 `cat /etc/passwd`、`curl file://...`
- [ ] Webhook 渠道拒绝环回 / 元数据地址
- [ ] `systemctl restart ayana` 后 `/health` 正常

测试：

```bash
cd /opt/ayana && .venv/bin/python -m unittest discover tests -q
```

---

## 10. 备份与升级

**备份**（SQLite 在线备份，勿直接拷 WAL 未 checkpoint 文件）：

```bash
sudo -u ayana sqlite3 /var/lib/ayana/ayana.db ".backup '/var/lib/ayana/backup-$(date +%F).db'"
sudo tar -C /var/lib/ayana -czf /var/backups/ayana-state.tgz backup-*.db bootstrap-admin.password 2>/dev/null || true
```

**升级**：

1. 备份 DB 与 `/etc/ayana`
2. 停服务 → 替换 `/opt/ayana` 代码与依赖（保留 venv 或重建）
3. 启动；schema 自动迁移（失败则回滚备份）
4. 跑验收清单

**回退**：恢复 DB 备份 + 旧代码 + 旧 secrets。

---

## 11. 与监控栈对接

### Alertmanager

```yaml
receivers:
  - name: ayana
    webhook_configs:
      - url: "http://127.0.0.1:6200/hooks/alertmanager"
        http_config:
          authorization:
            type: Bearer
            credentials: "<与 secrets.json 的 webhook_token 相同>"
```

### Prometheus

在控制台配置探测目标，或使用 Prometheus `probe_success`；应用只读查询 Prom API。

### IM（可选）

- QQ：NapCat 反向 WS 到 `ws://127.0.0.1:6199/ws`，Token 与 `onewbot_token` 一致
- 企业微信：在控制台配置机器人 Webhook / 智能机器人，凭据只进 `secrets`

---

## 12. 故障排查

| 现象 | 处理 |
|------|------|
| 启动即退 | 看日志；检查 `db_path` 目录可写、端口占用、`flock` |
| 登录 401 | 确认用户名；连续失败会锁定（默认 8 次 / 15 分钟） |
| 登录后提示改密 | 正常：bootstrap 或重置账号，按提示改密 |
| 403 `password_change_required` | 先调 `/api/password` 或走 UI 改密 |
| 改 pepper 后无法登录 | 确认旧 pepper 在 `legacy` 迁移路径；或用恢复码 / 重置 |
| SSH 主机密钥未信任 | 在「连接」页确认指纹后再测连接 |
| Webhook 401 | Bearer 与 `webhook_token` 不一致 |
| 依赖缺失 | 生产安装 `aiohttp`、`cryptography` |

---

## 13. 安全建议摘要

1. 仅监听本机 + 反代 TLS；不要裸奔公网 6200。  
2. 每个秘密独立随机；权限 600/640。  
3. 启用 2FA；管理员口令强度足够。  
4. 写能力最小化授权；非必要不开 `auto_remediation`。  
5. 受管主机侧仍限制 sudo / forced-command。  
6. 定期备份 DB 与 secrets（分开存放）。

更细的威胁模型与加固项见仓库变更说明；本手册不替代你的安全评审。
