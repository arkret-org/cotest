# Offline queue replay

当前 v1 full-client profile 要求客户端暴露 `offline_queue`、`conflict_records` 和 `pending_state`。inkson 在 `navigator.onLine=false` 时把 discussion compose 写入本地 outbox，保留 optimistic row，并在恢复联网后通过标准 `ak.message.create` 写路径 drain。排队条目使用稳定 `ak:message:` id，重放时应由 reducer 幂等折叠。

## Live 用例

1. Bob 离线发送消息后，inkson timeline 显示本地 queued-offline 状态，并暴露 outbox banner/count。
2. 断网期间，该排队消息不会出现在 soland 事件流中。
3. Bob 恢复联网后，inkson drain outbox，消息发送状态清空，并出现在 soland 事件流中。

## 不验证

- 本地 outbox 跨 reload 持久化（workflow smoke 里覆盖）。
- 离线期间成员资格变化后的 drain 冲突处理。
- Kanban card 离线重排和 epoch drift 重新加密。
