# 离线编辑 / 重连同步 / 冲突修复

## 目标

bob 在网络断开时编辑(本地 outbox);重连后 sync 上传所有 pending Event。Realm title / summary / avatar 的唯一写入面 `ak.realm.profile` 是 `realm_profile` 单例的整值替换；同一 Realm stream 上的写入只按治理 Station 给出的 `stream_position` 排序，后接纳者即 current，不存在需要合并的多头或通用 repair event。

## Spec 锚点

- `sync/client-sync.md` §2 — Sync 协议 + cursor
- `sync/operations-sync.md` §9 — 单 authority 顺序裁决冲突，无通用合流
- `authz/event-auth-state-resolution.md` §6 — typed 当前值 = 该 stream 最后一个被接受的写入
- `authz/event-auth-state-resolution.md` §8 — RealmCommit 是唯一 finality
- `models/realm-and-space.md` §2.3.A — `ak.realm.profile` 是 title / summary / avatar 的唯一 carrier

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字  | 角色            |
| ----- | --------------- |
| alice | 在线,持续编辑   |
| bob   | 离线编辑,后重连 |

## Steps

### Phase A — Setup space

1. alice createRealm,seedMembers=[bob],bob acceptInvite
2. alice 和 bob 各自打开 `/timeline/<S>`

### Phase B — bob 离线

3. 测试 harness 用 `page.context().setOffline(true)` 把 bob 断网
4. bob 在 inkson 中尝试发消息 `M_b_offline`
5. inkson 客户端:看到网络错误,把 move 写入本地 outbox(IndexedDB / localStorage)
6. UI 显示 `M_b_offline` 标 "pending sync" (`pending-sync-message` testid)
7. 同时 alice 在线发 `M_a_online`

### Phase C — bob 重连

8. `page.context().setOffline(false)`
9. bob 客户端检测网络恢复 → 自动 flush outbox 到 soland
10. 断言:30s 内 `M_b_offline` 状态从 pending 变 persisted;UI 标记移除
11. 断言:alice 和 bob 双方都看到 `M_a_online` 和 `M_b_offline`

### Phase D — 因果有序 title update 按 stream 顺序收敛

12. alice 提交完整 `ak.realm.profile`（title=A）；bob 在 `ak.realm.profile` grant 下再提交完整 profile（title=B）
13. 断言：Realm stream scan 中这两条 profile Event 按 RealmCommit 顺序为 [A, B]
14. 断言：bob 打开 inkson Realm 设置 profile 区，`realm-name-input` 显示 B（current = 最后接纳的写入）

### Phase F — Backfill via pull

20. (sub-test)假设 bob 离线很久,本地缺很多 events;重连后先用 `GET /_arkret/self/account/subscribe?after=<old>&catchup=true`,缺口再用 `GET /_arkret/self/events?after=<old>`
21. 断言:bob timeline 自动补齐离线期间的所有消息

## Edge cases

- **E26.1 outbox 满**:bob 长期离线,outbox 满;客户端 UI 显示 "Too many pending changes, please reconnect"
- **E26.2 旧 revision 再写**:同一 `sequenced_state` 的首条确认命令推进 revision；其余旧 revision 命令持久拒绝且不改变状态
- **E26.3 重新 author**:客户端取得新 revision 后显式重建新 Event；旧签名 Event 本身不得被服务器改写或升级
- **E26.4 并发 profile 写入**：两条并发 `ak.realm.profile` 由治理 Station 串行化为两个 stream position，后者即 current；需要防覆盖的 kind 用 `expected_revision` CAS，loser 收到 `failed_precondition` 后重读重签

## Implementation notes

- **测试侧已激活**:offline outbox / pending reconcile 在 `sync/offline-queue-replay` live 覆盖；本 scenario 覆盖两条 `ak.realm.profile` 的 stream 顺序与 current 值。
- **剩余边界**:outbox capacity、旧 revision 持久拒绝与重新 author 仍保留为后续边界 fixme。

## 总耗时预估

约 90s。
