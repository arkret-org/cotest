# Offline queue replay

验证真实 yougen + soland 下的离线写入队列:客户端离线发消息时显示 pending,网络恢复后自动 flush;如果离线期间成员资格被移除,队列必须丢弃而不是无限重试或把消息写入服务器。

## Live 用例

1. Bob 离线发送消息后,yougen timeline 显示 `(pending)`。
2. Bob 恢复在线后,单条 pending message 自动持久化到 soland。
3. Bob 离线连续发送 3 条消息,恢复在线后全部 flush,本地 pending 标记清零。
4. Bob 离线期间被 Alice ban,恢复在线后 pending change 被丢弃。
5. 被丢弃的离线消息不会出现在 soland 事件流中。

## 不验证

- Kanban card 离线重排和 epoch drift 重新加密。这两段依赖更完整的本地 outbox/MLS epoch manager;本 scenario 先把用户最直接可见的消息队列语义转成 live。
