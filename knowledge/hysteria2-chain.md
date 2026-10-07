---
id: hysteria2-chain
title: Hysteria2 代理链路
status: active
type: system
objects:
  - sora:hysteria-server
  - sora:hy2-443
  - sora:google
  - sora:youtube
tags:
  - hysteria2
  - proxy
  - network
---

# Hysteria2 代理链路

## 用途

Sora 上运行 Hysteria2 服务。

`hysteria-server` 是服务进程，`hy2-443` 用于监控 UDP 443，
`google` 和 `youtube` 用于验证实际外部代理链路可用性。

## 关系

hysteria-server
→ UDP 443
→ Hysteria2 链路
→ google / youtube 外部探测

google 与 youtube 共享 Hysteria2 链路。

## 异常含义

google 或 youtube 单独失败，不一定代表 Hysteria2 服务故障。

google 与 youtube 同时失败时，不应首先判断 Google 和 YouTube 同时故障。

应优先调查共同依赖：

- hysteria-server
- UDP 443
- Hysteria2 链路
- 外部网络

## 调查

优先检查：

1. hysteria-server 是否 active
2. UDP 443 是否监听
3. hysteria-server 日志
4. google / youtube 是否同时失败
5. 外部网络是否正常

## 处置

知识库只提供调查和处置建议。

任何实际操作仍必须经过：
Runbook → Capability / Policy → 主机侧安全闸 → Verification。
