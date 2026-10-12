# Ayana 部署说明

完整安装请见 **[docs/INSTALL.md](../docs/INSTALL.md)**。

## 一键安装

```bash
# 系统级（root + systemd）
sudo bash deploy/install.sh --system

# 当前用户
bash deploy/install.sh --user
```

`deploy/ayana.service` 为单元模板；`--system` 会按实际路径生成并启用。

## 原则

- 代码目录只读；数据（DB / secrets / 日志 / bootstrap 口令）在数据目录
- `secrets.json` 由 `scripts/gen-secrets.py` 自动生成，勿提交仓库
- NapCat / 企微可选，不影响 Web 登录
