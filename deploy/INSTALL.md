# Ayana 部署说明

完整安装请见 **[docs/INSTALL.md](../docs/INSTALL.md)**。

## 一键安装（脚本自己拉包）

```bash
curl -fsSL https://raw.githubusercontent.com/wwqjss/Ayana/main/deploy/bootstrap.sh -o bootstrap.sh
bash bootstrap.sh --system
```

默认拉 **latest** Release（`ayana-install.tar.gz`）并校验 `.sha256`。  
固定版本：`AYANA_VERSION=v0.7.4 AYANA_SHA256=<hash> bash bootstrap.sh --system`

## 本地源码一键安装

```bash
# 只检查环境与已装状态（不改任何东西）
bash deploy/install.sh --check
sudo bash deploy/install.sh --system --check

# 系统级（root + systemd）— 检查通过且已装完整则跳过
sudo bash deploy/install.sh --system

# 当前用户
bash deploy/install.sh --user

# 已装也强制重装代码/单元
sudo bash deploy/install.sh --system --force
```

行为：

- **先环境预检**（Python ≥ 3.11、包文件、磁盘、权限/systemd）
- **检查通过且已装完整 → 不安装**，直接退出（服务未起会尝试 start）
- **有缺失 → 只补缺失项**（venv / deps / secrets / config / unit）
- `secrets.json` / 已有 `config.json` 永不覆盖
- `--force` 才 `rsync --delete` 同步代码；平时重跑不会删你手工放的文件

## 取默认口令

```bash
# system 安装
sudo cat /var/lib/ayana/bootstrap-admin.password
journalctl -u ayana -n 50 | grep BOOTSTRAP

# user 安装（默认）
cat ~/.local/share/ayana-data/bootstrap-admin.password
```

退出码：`--check` 时 0=完整可跳过、2=有缺失、1=环境不通过。

`deploy/ayana.service` 为单元模板；`--system` 会按实际路径生成并启用。

## 原则

- 代码目录只读；数据（DB / secrets / 日志 / bootstrap 口令）在数据目录
- `secrets.json` 由 `scripts/gen-secrets.py` 自动生成，勿提交仓库
- NapCat / 企微可选，不影响 Web 登录
