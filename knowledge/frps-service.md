---
id: frps-service
title: NERV frps 内网穿透服务
status: active
type: system
objects:
  - nerv:frps
  - nerv:frps-32659
  - nerv:frps-probe
tags:
  - frps
  - tunnel
  - nerv
---

# NERV frps 内网穿透服务

## 用途

NERV 上运行 frps，对外提供穿透入口。

`frps` 为 systemd 服务，`frps-32659` 监控 TCP 32659，
`frps-probe` 用黑盒 tcp_connect 验证外部可达性。

## 关系

frps（systemd）
→ TCP 32659
→ frps-probe 黑盒探测

任一异常都可能来自 frps 进程本身。

## 异常含义

frps-probe 失败通常表示 frps 未监听或端口不通，
不优先怀疑探测配置。

## 调查

1. `systemctl status frps`
2. TCP 32659 是否监听
3. frps 日志
4. 外部探测是否同时失败

## 处置

runbook 支持探测失败时重启 frps；执行仍走 Policy 与主机闸，重启后需验证 probe。
