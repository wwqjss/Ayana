# v0.7.3 监控配置迁移（required checks / runbook）

## 背景

v0.7.2 及更早把特定环境的业务检查与自动 runbook **硬编码**在：

- `ayana/health.py` → `REQUIRED_CHECKS`
- `ayana/runbook.py` → `RUNBOOK`
- `ayana/verify_profiles.py` → 资产专属验证 profile

全新安装会在资源页「业务状态」里冒出与个人环境一致的检查（例如 nerv 的 frps/nginx），
即使未配置 Prometheus 也会显示为「采集失败」。

从本版本起：

| 项 | 发行版默认 | 部署方配置 |
|----|------------|------------|
| required checks | 空 | `config.json` → `required_checks` |
| runbook 自动规则 | 空 | `config.json` → `runbook_rules` |
| 服务重启验证 | 通用 `svc.recover` | 无需配置 |
| 服务停止验证 | 通用 `svc.stop` | 无需配置 |

**能力保留**：业务检查仍会从 Prometheus 实测样本自动发现；原生 checks、创建/执行、审批链路不变。

---

## 升级顺序（KANATA 等已有监控依赖的环境）

**先迁配置，再换代码。** 否则升级瞬间 required checks / runbook 会变空。

### 1. 备份

```bash
sudo cp /etc/ayana/config.json /etc/ayana/config.json.bak-v072
sudo -u ayana sqlite3 /var/lib/ayana/ayana.db ".backup '/var/lib/ayana/pre-v073.db'"
```

### 2. 用旧代码导出监视配置到 config.json

在仍保留旧 `health.py` / `runbook.py` 的目录旁执行（只写 config，不动库）：

```bash
python3 scripts/migrate_monitor_config.py \
  --legacy-health /opt/ayana/ayana/health.py \
  --legacy-runbook /opt/ayana/ayana/runbook.py \
  --config /etc/ayana/config.json
```

若旧代码已不在，按下面格式手写进 `config.json`。

### 3. 替换代码 / 重启

按正常升级替换 `/opt/ayana` 后 `systemctl restart ayana`。

### 4. 校验

- `GET /api/monitor/business/<asset>` 中应仍有原 required 项
- `/api/runbook` 数量与迁移前一致
- 原生业务检查、SSH 资产、账号权限不受影响

---

## config.json 字段格式

```json
{
  "required_checks": {
    "your-asset-id": [
      {
        "object": "your-service",
        "metric": "probe_success",
        "selector": {"asset": "your-asset-id", "service": "your-service"},
        "freshness_sec": 120
      }
    ]
  },
  "runbook_rules": [
    {
      "id": "rb_yourservice_restart",
      "name": "yourservice 不可达 → 重启",
      "asset_id": "your-asset-id",
      "object_name": "your-service",
      "alertname": "TargetDown",
      "capability": "service.restart",
      "reason": "runbook: 探测失败自动重启",
      "require_probe_fail": true,
      "max_per_day": 3,
      "cooldown_sec": 1800
    }
  ]
}
```

说明：

- `required_checks` 的 key 是 **资产 id**（与 assets 表一致）
- `selector` 用来匹配 Prometheus 标签；与主机的 `prom_asset` / id 对齐
- `runbook_rules` 为空 = 不自动处置；需要时由运维显式添加
- 不要把口令、内网拓扑以外的敏感信息写进该文件；`config.json` 权限保持 640

---

## 回滚

1. `cp /etc/ayana/config.json.bak-v072 /etc/ayana/config.json`
2. 恢复旧版 `/opt/ayana` 代码（或从备份 tar）
3. `systemctl restart ayana`

配置迁移本身可独立回滚：删掉 `required_checks` / `runbook_rules` 两个键即可回到「无自动监视」状态。

---

## 全新安装

无需迁移。默认无个人资产、无 required checks、无自动 runbook。
在 Web「资源 → 一键接入监控」注册主机后，用 Prometheus 实测样本或原生检查观察状态。
