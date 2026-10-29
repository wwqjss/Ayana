---
id: ayana-port-bind-failed
title: 示例：Web 端口不可用的排查
status: example
type: issue
objects: []
tags:
  - ayana
  - 6200
  - bind
  - restart
---

# 示例：Web 端口不可用的排查

本条是通用排查示例，不代表当前环境发生了故障。系统安装由 `ayana` 和 `ayana-agent-runtime` 两个服务分别管理 Web 与原生任务。

## 现象

浏览器访问 Ayana：

ERR_CONNECTION_REFUSED

6200 无监听。

## 一种需要核对的可能原因

部署重启时旧进程仍占用 6200，
新进程启动时 bind 失败：

Errno 98: address already in use

新进程退出，随后旧进程结束，最终导致 6200 无进程监听。

## 调查

检查：

- `systemctl status ayana ayana-agent-runtime --no-pager` 和实际进程
- TCP 6200 / 6199
- 启动日志
- 是否存在旧进程
- 最近是否发生部署或重启

不要把浏览器缓存作为 connection refused 的优先调查方向。

## 处置与验证

根据日志确认端口占用、配置或服务退出的具体原因。需要重启前，先核对任务和待确认写结果，释放接管连接。只重启 Web 可保留独立运行时中的任务；完整升级应等待任务结束。

启动后验证：

- 6200 正常监听
- 6199 正常监听
- `/health` 返回 200
- Web 页面可访问

`/health` 只证明 Web 进程响应。原生会话、模型配置、SSH 和实际业务状态需要分别验证，不能由 Web 成功直接推断业务恢复。

## 后续改进

部署流程应保证：

停止旧进程
→ 确认旧进程退出
→ 确认 6199/6200 释放
→ 启动新进程
→ 验证监听
→ 验证 `/health`
