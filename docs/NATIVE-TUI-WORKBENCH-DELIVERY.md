# 原生 MiMoCode Agent 工作台交付

日期：2026-10-27（Asia/Shanghai）。分支：`speed-supreme`。接手基线：`dc8a410`。

原生技术路径、真实只读交互及 KANATA 部署已完成。浏览器内的视觉与人工操作验收由用户进行。

## 最终体验

1. 新建空手动会话直接显示 MiMoCode 原生欢迎页和输入框。
2. 工作中的会话显示同一 RID 的原生分析、工具调用、输出和回答。
3. 中栏只保留原生 TUI，删除网页聊天、额外输入框、外置思考条及「原生终端 / 返回对话」切换。
4. 左栏保留自动值班、手动和历史会话；右栏保留 Incident、任务、审批、执行与验证信息。
5. 离开、断线及重连不重提提示词，不另建空任务；观察默认，显式接管键盘。手动与自动会话生命周期独立。

## 技术路线与架构

KANATA MiMoCode 0.1.16 的真实 `serve + attach` 已能完整呈现后台同一 RID 的 Thinking、工具和回答，因此继续使用此执行入口。共享历史没有被当作实时接管的替代证据。

修改前，网页聊天和思考条与原生 TUI 分离，原生代理缺少关键接口；serve 在 Web 单元中，原生事件流也随 Web 生命周期断开。

修改后：

```text
告警 → Incident → DutySession → AutoInvestigator / SessionBridge
                                      │
原生输入 → 会话范围代理 → 同一会话锁 / 持久收据 / 输入准入
                                      │
                                唯一 serve RID
                                      │
                      原生消息 / 工具 / 状态 / 事件流
                                      │
                           tmux 原生 attach TUI
                                      │
                            WebSocket → xterm.js
```

`ayana-agent-runtime.service` 持有 serve、会话范围代理、tmux 及原生 TUI。Web 只持有浏览器附着连接和其 tmux attach-client。首次真实 Web 重启测试发现 MiMo 0.1.16 的原生视图漏掉断线期间输出；将代理迁入独立单元后，同场景实测通过，原生 TUI 进程也保持不变。

自动调查、原生输入和兼容 HTTP 输入共用会话锁与任务状态；运行中的业务调查、执行/验证阶段及未确认收据阻止人工并发提交。不同手动会话仍独立，保留现有资产写锁。

## 修复与安全边界

- 支持原生 `/global/event` 的 `{directory,payload}` 封装，补齐限定 RID 的 actors、task、recovery 等初始化读取。
- 严格按工作目录和 RID 筛选事件，拒绝无法确定归属的消息增量及其他会话事件。
- 原生欢迎页发送的空请求体按合法创建处理，映射到预留 RID；没有重复创建第二个模型任务。
- 保留 native messageID 和文本 part.id，强制当前已验证模型及受限调查 Agent。
- 正确处理真实 `claimed / settled / outcome / consumed` 收据；成功必须有本轮 parentID 对应结论，不能拿同会话其他回答作为结果。
- 会话锁持续续租。超时、断线、丢失响应均不自动重放；已知 unknown 收据通过只读对账恢复，缺少收据时继续阻断。
- 控制权绑定已认证 WebSocket，单窗口持有、定期续租；归档会话只读，续接是显式操作。
- 观察模式允许严格校验的终端设备、光标和颜色报告；普通文字、Return、编码按键和剪贴板指令不能借此越权。
- 禁止通过原生代理调用 shell、命令执行、权限批准、全局配置变更及其他会话写入口。原生输入建议不额外触发模型任务。
- MCP 子进程保持只读约束；业务写操作仍由 ActionService、Policy、审批、审计与幂等路径处理。没有放宽 unknown 禁止重放规则。
- 修复审批 TTL 边界为立即过期，零 TTL 无法执行；Incident 对账使用事件顺序判断代次，防止同一时刻的旧 Action 清除新代次人工义务。原有断言保留，补充固定时刻测试。
- HOME `/var/lib/ayana`，工作目录 `/var/lib/ayana/agent-workspace`，XDG 与 serve 一致，清除 `MIMOCODE_HOME`。Web 与 runtime 的 MCP 环境构造固定，避免继承环境造成运行证明不一致。

Incident、Action、历史 Council、审计、SSH 凭据与 host key、知识和通知能力均保留。SQLite 保持既有 v23，没有 DROP 或额外 schema 迁移。旧 Council 未重新启用。

## 真实验收证据

以下使用真实 MiMo 与真实 MCP，没有用模拟回复替代。

- 原生直连 RID：`ses_ffe5e864d0555ffeM9pOTKzLFY`。后台提交后在原生屏幕观察到 Thinking、真实 asset_list 和最终回答。
- 原生工作台会话：`sess_2d71b1ba3ff1`，RID `ses_ffe5e8632054cffe9J5zskvrAg`。从原生欢迎页经真实 PTY/WebSocket 输入，执行 asset_list、incident_list，原生屏幕显示工具和最终汇总。
- 原生输入收据 `01M5WWX0KTAY8DFN3GS2BZ22GW`：`settled / consumed=true / outcome=success`。busy 期间断开并重连，同一引擎及 pane 身份保持，只有一条用户输入。
- 最终 Web 重启收据 `01M5WYCDJZ63DT78J97CH116SV`。重启发生在 busy；Web PID `1373370 → 1375719`，runtime PID `1373257`、serve PID `1373281`、pane PID `1374954` 保持不变。
- serve 与 pane 均属于 `/system.slice/ayana-agent-runtime.service`。最终标识 `NATIVE_WEB_RESTART_c5c7a0e71c` 在原生屏幕显示，用户输入仅新增一次。
- 私有证据 `/var/lib/ayana/agent-runtime/native-scoped-probe.json` 及 `native-web-restart-proof.json`。最终 `passed=true`、`native_result_rendered=true`、`one_new_user_turn=true`。

两条 RID 共 4 次真实用户任务、10 条 assistant 消息、5 次 MCP 业务工具调用，另有 2 次 schema 检索。其中一次用于定位旧代理的 Web 重启视图问题：模型成功，视图初测失败；修复后同场景真实复测通过。初始化失败的未提交尝试没有触发模型调用。

本轮真实冒烟全部只读，没有实际批准生产写操作、自动修复或新增完成真实 Incident 关单；业务审批、执行、验证及告警链路通过隔离回归验证。

## 测试

| 项目 | 结果 | 口径 |
|---|---|---|
| 最终 Python 全量 | **1562 项，1558 通过、4 跳过** | 最终冻结代码，376.155 秒 |
| 原生代理、收据、互斥和配置专项 | 118 项，117 通过、1 平台跳过 | Windows；包含在全量内 |
| KANATA 原生专项 | **114 项，113 通过、1 平台跳过** | Linux，28.860 秒；协议与安全测试，无模型调用 |
| 网页交互自动回归 | 170/170 通过 | 原生工作台 22；既有 148 |
| 审批/代次问题修复专项 | 90/90 通过 | TTL、代次、审批协议、通知及闭环 |
| 语法、差异、敏感模式扫描 | 通过 | 无新增密钥、私钥或本机个人路径 |

网页自动测试执行真实前端回调，使用受控 API/WS 响应，不称为真实浏览器 E2E。用户未被代为操作浏览器。早期候选全量曾发现两个安全边界问题，均修复后复测；最终结果不把失败轮次记作通过。

## 部署

目标 KANATA `/opt/ayana`；配置 `/etc/ayana`；数据库 `/var/lib/ayana/ayana.db`。

- 切换前确认没有 busy 原生任务、queued/running Job 或未确认收据。旧残留 accepted 根据真实终态收据及 native idle 对账，记录审计，未重放。
- 私密备份 `/var/backups/ayana/native-tui-20261027-040935/` 保存源码、配置和 SQLite 一致性副本。
- 配置 `mimo_serve_external=true`，独立单元持有原生执行及代理；Web 仅在启动顺序上依赖它，没有 PartOf/传播重启关系。
- 保留既有 `auto_investigate.enabled=true`、`closed_loop=true`、`require_human_approval=0`；本轮没有启用生产自动调查、改变审批总开关或执行生产修复。
- 188 个部署文件逐一校验，不匹配为 0。部署清单保存在服务器私有 state 目录。
- 部署包 SHA-256：`ac8e5d0586ddd951e17eb81f88be82668cab49a2f047be9aaea800702b8aab7e`。
- `ayana` 与 `ayana-agent-runtime` active/running；代理仅监听 `127.0.0.1:6291`，监听者为 runtime PID `1373257`。静态文件 HTTP 200，未登录会话 API 401。
- 密钥、SSH 私钥、运行数据库、私有证据、临时依赖和本机测试文件未纳入 Git。

实现提交：`15bb3b1113ba24d90b7d67f06a7f99eec582fbf2`（`fix(agent): make native MiMo TUI the persistent workbench`），已推送 `origin/speed-supreme`。本报告随其后的交付记录提交；最终分支 HEAD 另在交付回复列明。临时产物保留并在本机 Git 排除，不删除用户已有文件。

## 验收与剩余范围

技术路线、原生真实只读交互、断开重连及运行中 Web 重启存活：**PASS**。浏览器内视觉及人工操作验收：**等待用户验收**。

用户验收欢迎页、中文输入、分析/工具/结果、尺寸与滚动、左右栏和审批入口。原生 TUI 的安全限制保持，不能用 Bash 或原生权限菜单绕过 Ayana。

Web 重启已实测不中断任务；整个主机或 runtime 重启会结束进程，随后按收据对账，unknown 不自动重放，不承诺保留同一 PID。模型配置轮换仅在已证明空闲时进行。

本轮结束后等待用户验收，不扩展其他阶段，不补做生产修复闭环。

## 2026-10-27 普通浏览器路径补验收

用户随后反馈普通新建黑屏、接管输入显示无响应。上述初轮验收没有覆盖真实终端解析后的普通创建路径，不能单独视为此路径通过。已修复大模型目录递归脱敏阻塞、终端探测回复及画面就绪误判，并通过实际 workbench.js 与真实 xterm 的全新会话、连续两次原生输入和同 RID 重连验收。最终结果与范围见 [后续修复报告](NATIVE-TUI-COLD-START-FIX.md)。
