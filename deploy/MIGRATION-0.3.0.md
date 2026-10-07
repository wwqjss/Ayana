# Ayana v0.3.0 生产迁移计划（P0-01 收尾）

**状态**：计划完成，**未执行**。生产切换必须等待用户单独明确批准。

**前提**：Phase A–F 代码层完成；auto remediation 保持 **off**。

---

## 1. Pre-check（迁移前必过）

| 检查项 | 命令/方式 | 期望 |
|--------|-----------|------|
| 当前生产版本/进程 | `ps aux \| grep ayana` / `curl :6200/health` | 旧 setsid root 进程在跑 |
| DB backup | `ayana.backup.create_backup` 或 `sqlite3 .backup` | 一致性备份成功并离线保存 |
| config/secrets 权限 | `ls -l /root/Ayana/secrets.json config.json` | secrets 600 |
| SSH identity | NT describe / `known_hosts` | host_id 可核 |
| astrbot-describe readiness | 远端 `astrbot-nt-command describe` | 返回 mode+host_id |
| 6200/6199 listener | `ss -lntp \| grep -E '6199\|6200'` | 旧进程占用中 |
| rollback artifact | 旧 `/root/Ayana` tar / git tag | 可回退 |
| Incident/Action/Verification | Web 或 sqlite | 记录当前快照 |
| auto remediation | config `auto_remediation_enabled` | **false** |

任一项不过 → **停止迁移**。

---

## 2. Migration 步骤（批准窗口内执行）

```text
1. 停旧 setsid 进程
   kill <pid>；确认 PID 消失
2. 确认端口释放
   ss -lntp | grep -E '6199|6200' → 无监听
3. 备份 DB（再做一次）
   sqlite3 ayana.db ".backup /root/backup/ayana-pre-0.3.db"
4. 部署新代码到 /opt/ayana（或目标目录）
   不覆盖 secrets.json / config.json / ayana.db* / .venv
5. 以 non-root ayana 启动
   systemctl enable --now ayana
6. 确认 listener
   ss -lntp | grep -E '6199|6200'
7. /health  → ok
8. /ready   → ok（db/schema current）
9. Web 登录可用
10. QQ/OneBot（若生产仍启用）/ping
11. NT 只读 describe / probe
12. host_id describe 与登记一致
```

**禁止**：迁移窗口内开启 auto remediation；禁止顺手改业务权限。

---

## 3. Post-check

| 检查 | 期望 |
|------|------|
| schema version | `meta.schema_version == 3` |
| incidents/actions 行数 | 与 pre-check 快照一致（无意外丢失） |
| outbox | 可 flush；无永久失败 |
| Prom/AM ingestion | webhook/reconcile 正常 |
| Investigation 只读 | `/investigate` 或 Agent 调查成功 |
| 无 unexpected write | audit 中无未批准 exec |
| /ready checks | db/schema/outbox/worker 可见 |

---

## 4. Rollback

**立即回退条件**（任一）：
- /health 或 /ready 持续失败
- Web 无法登录
- schema migration 失败
- 出现未预期写操作
- 关键业务告警无法处理

**回退步骤**：
1. `systemctl stop ayana`
2. 确认新进程消失、端口释放
3. 恢复旧目录 `/root/Ayana`（保留）
4. 如 DB 已迁移：从 pre-migration backup 恢复
   ```bash
   sqlite3 ayana.db ".recover"  # 或直接拷回备份
   ```
5. 旧 `nohup setsid /root/Ayana/start.sh` 启动
6. 确认 /health 与业务

**DB 迁移兼容性**：
- v1→v3 为**加列/建表**，无破坏性 DROP
- 新代码读旧列用默认值；旧代码读新列可忽略
- **不能直接 downgrade 丢列**；若必须回退且已写入新列数据 → restore backup
- 回退后应恢复到迁移前 backup，避免旧代码写新 schema

---

## 5. 明确不在本窗口

- 不部署生产 astrbot-describe（除非已单独批准）
- 不开启 auto remediation
- 不改主机闸 commands.json
- 不迁 SSH HOME（除非单独批准）
