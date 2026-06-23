# Offline write fail-fast

当前 v1 spec 没有要求客户端必须提供持久离线写入队列；真实 yougen 也已经移除旧的 `offline_queue`/pending badge/drain worker 链路。离线 compose 需要 fail-fast：本地可以显示失败的 optimistic bubble 和重试入口，但不得把未经签名/未通过当前 auth frontier 的写入缓存成自动 replay 承诺。

## Live 用例

1. Bob 离线发送消息后,yougen timeline 显示本地失败状态,并暴露错误/重试入口。
2. 该离线失败消息不会出现在 soland 事件流中。

## 不验证

- 自动 pending replay、本地持久 outbox、离线期间成员资格变化后的 drain 决策。这些不是当前 v1 live contract;若未来重新引入,必须同时实现 DPoP/session 绑定、Event signing、actor frontier refresh 和 app-shell drain worker。
- Kanban card 离线重排和 epoch drift 重新加密。这两段同样依赖完整的本地 outbox/MLS epoch manager。
