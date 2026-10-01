# 离线期间写入 / 重连回补 / 有序 profile

本场景验证未轮询期间另一成员的已接受写入，在后续获准 stream scan 中按治理 Station 的 Commit 顺序出现。包含两个同站消息回补、一条有序 profile succession 与一条双站 peer 回补用例。浏览器实际断网、耐久 outbox 与重连自动发送由 `sync/offline-queue-replay` 独立验收；本文件的 API 夹具不代表该浏览器流程已通过。

## 规范依据

- `sync/client-sync.md` §2：客户端同步与游标。
- `sync/operations-sync.md` §9、`authz/event-auth-state-resolution.md` §6/§8：唯一 authority 的 stream_position、typed current 与 RealmCommit finality。
- `models/realm-and-space.md` §2.3.A：`ak.realm.profile` 为完整 profile 单例替换。
- `sync/federation.md` §3/§4.1.1：逐流 peer scan、exact pair复制与成员获准区间。
- `sync/service-http-binding.md` §3.1：本站授权 stream scan，读区间不可证时失败关闭。

## 当前步骤与断言

1. 同站 Alice/Bob 通过真实 Coauth/Soland API fixture 注册与加入；Bob 首次读取没有目标消息。Alice 写入后，Bob 再读包含目标消息；三条消息的回读顺序与接受顺序一致。
2. Profile succession 明确向 Bob 签发 `ak.realm.profile` grant，field_access 覆盖完整 profile。Alice 写 title A，Bob 随后写 B；scan 中顺序为[A,B]，Bob 浏览器的 Realm profile 输入显示 current B。不存在多头合并或通用 repair Event。
3. 双站回补要求 runner `-ServerCount 2`，每站独立身份与 PostgreSQL，DualCoauth、mock email 与 TLS 保留。Realm 明确 `since_join`，Alice 在 Bob join 前接受默认 discussion。
4. Bob 从自身 server2 的受保护邀请通知取得 locator，经本站 prepare、自签接受、提交本站，取得治理 Station covering Commit。随后在 Bob 本站等待包含完整 server2 AccountId 的获准成员 current；只允许200或暂未出现的404，其它错误致命。
5. Alice 在 Bob 未轮询期间接受消息。恢复阶段 Bob 读取本站当前持有集，server2 从 server1 的 `POST /_arkret/peer/streams/scan` 取得获准 source pairs，以 `committed_replication` 接收缺失的 exact Event/Commit；零 rejected。
6. Bob 通过 `POST /_arkret/self/streams/scan` 读回该消息；每个 source scan 披露的 Event 都在本站恰一次。不能要求加入前历史，不能把不可证明的区间503当空结果、绕过授权或伪造 source pairs。

双站用例的“离线”是读取间隔：它没有停止 server2 或断开浏览器网络，durable delivery 可能已经送达，此时无需再次写入。真实停站、重启持久性与浏览器断网分别由三站 P0 和 offline outbox 具名用例提供证据。API/session fixture 的通过不冒充真实注册产品分类。

## 尚需独立验收的边界

- outbox 容量与用户可见满队列状态。
- sequenced_state 旧 revision 的耐久拒绝，以及取得新 revision 后显式重建新 Event；服务不能改写原签 Event。
- 并发 profile 写入按 authority 接受位置序列化，要求 CAS 的 kind 另验 expected_revision loser 的重读重签。

这些边界不在本文件四个 live 定义内，不能由四项通过自动标记完成。
