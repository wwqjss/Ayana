---
id: ayana-port-bind-failed
title: Ayana 重启后 6200 拒绝连接
status: active
type: issue
objects:
  - kanata:ayana
  - kanata:ayana-6200
tags:
  - ayana
  - 6200
  - bind
  - restart
---

# Ayana 重启后 6200 拒绝连接

## 现象

浏览器访问 Ayana：

ERR_CONNECTION_REFUSED

6200 无监听。

## 已确认的一种原因

部署重启时旧进程仍占用 6200，
新进程启动时 bind 失败：

Errno 98: address already in use

新进程退出，随后旧进程结束，最终导致 6200 无进程监听。

## 调查

检查：

- Ayana 进程
- TCP 6200 / 6199
- 启动日志
- 是否存在旧进程
- 最近是否发生部署或重启

不要把浏览器缓存作为 connection refused 的优先调查方向。

## 已验证处置

清理残留进程后重新启动 Ayana。

启动后验证：

- 6200 正常监听
- 6199 正常监听
- `/health` 返回 200
- Web 页面可访问

## 后续改进

部署流程应保证：

停止旧进程
→ 确认旧进程退出
→ 确认 6199/6200 释放
→ 启动新进程
→ 验证监听
→ 验证 `/health`
