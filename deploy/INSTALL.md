# Ayana 部署说明

完整安装请见 **[docs/INSTALL.md](../docs/INSTALL.md)**。

## 一键安装（从 GitHub 拉包）

```bash
curl -fsSL https://github.com/wwqjss/Ayana/releases/download/v0.7.2/ayana-v0.7.2-install.tar.gz -o ayana.tgz
tar -xzf ayana.tgz && cd ayana-pkg
bash deploy/install.sh --check
sudo bash deploy/install.sh --system
```

或 `bash deploy/bootstrap.sh --system`（自动下载 Release 包再装）。

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

退出码：`--check` 时 0=完整可跳过、2=有缺失、1=环境不通过。

`deploy/ayana.service` 为单元模板；`--system` 会按实际路径生成并启用。

## 原则

- 代码目录只读；数据（DB / secrets / 日志 / bootstrap 口令）在数据目录
- `secrets.json` 由 `scripts/gen-secrets.py` 自动生成，勿提交仓库
- NapCat / 企微可选，不影响 Web 登录
