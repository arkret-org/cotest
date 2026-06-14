# Chat 高级功能(reactions / replies / mentions / polls / 输入指示 / presence)

## 目标

验证 chat 完整功能面:reactions(OR-Set 收敛)、replies、@-mention 触发通知(明文 / E2EE mention-sidecar hash)、polls 投票收敛、ephemeral typing + presence、read receipts(详见 messaging/read-receipts)。

不验证:基础 message 发/edit/redact(messaging/triad-collaboration 已覆盖)、E2EE 群组生命周期(encryption/mls-group)、read receipts 隐私开关(messaging/read-receipts 独立)。

## Spec 锚点

- `models/strand-and-message.md` §4.3 — Discussion track profile
- `models/strand-and-message.md` §8.2-§8.3 — Message schema + chat example
- `models/content-types.md` §4.1 — Text with mentions
- `models/content-types.md` §4.9 — Poll type
- `discovery/profiles-presence.md` §3.2-§3.5 — Presence states / Typing format
- `discovery/push-notifications.md` §4.3.1 — Mention routing hint
- `discovery/push-notifications.md` §4.5 — `evaluation_locus`

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | Realm owner,主驱动 |
| bob | 成员,被 @-mention、参与 reactions / poll |
| carol | 成员,投票 / 收 typing 指示 |

## Steps

### Phase A — Setup

1. alice createRealm,seedMembers=[bob, carol]
2. bob、carol 接受 invite

### Phase B — Reactions (OR-Set 收敛)

3. alice 发 `M1 = "ship it?"`
4. bob 对 `M1` 加 `👍` reaction → `ck.reaction.add`
5. carol 对 `M1` 加 `👍` reaction(并发)→ 第二条 `ck.reaction.add`
6. 断言:alice、bob、carol 视图都看到 `M1` 上有 2 个 `👍`(OR-Set 自然收敛)
7. bob 撤销自己的 reaction → `ck.reaction.remove`
8. 断言:三方视图都看到剩 1 个 `👍`(carol 的)

### Phase C — Replies + thread

9. bob 对 `M1` 点 reply → `chat-reply-banner` 显示
10. bob 发 `M2 = "yes, ship"`,自动 `reply_to: M1.event_id`
11. 断言:`M2` 在 timeline 渲染 `chat-reply-indicator`,展开后显示 `M1` 引用
12. carol 也 reply `M1` 发 `M3 = "agreed"`
13. 断言:三方都见 `M2`、`M3`,且都标记为 `M1` 的 reply(同一 thread)

### Phase D — Mentions + notification

14. alice 发 `M4 = "@bob please confirm"`
15. yougen 客户端:
    - 解析 `@bob` token,生成 `ck.relation.mention` payload
    - 在 plain text Realm:`ck.message.create.payload.mentions = [bob.did]`
    - 在 E2EE Realm:消息正文 encrypted,但 mention 用 `mention-sidecar hash`(SHA256(salt + bob.did))明文携带,让服务端能路由通知
16. 断言:bob 收到 push notification(检查 yougen 的 in-app notification panel,或测试侧调 `GET /_soland/self/notifications` 查 bob 的队列)
17. 断言:carol **没**收到 mention 通知(她没被点名)

### Phase E — Poll

18. alice 发一个 poll `M5`:
    - `content_type = ck.content.poll`
    - `options = [{ id: "p", label: "Pizza" }, { id: "q", label: "Poutine" }]`
    - `max_selections = 1`,`closes_at = +1h`
19. yougen `M5` 渲染投票按钮
20. bob 点 "Pizza" → `ck.content.poll.response` event {poll_id: M5.event_id, choice: "p"}
21. carol 点 "Poutine"
22. alice 后改主意,先选 "Pizza" 再改 "Poutine"(只允许 1 个 active vote per actor)
23. 断言:`M5` 卡片显示 `Pizza: 1, Poutine: 2`(alice 改后,Pizza 减 1 加给 Poutine)
24. (可选)alice 点 "Close poll" → reducer 拒绝新 response;断言:迟到的 vote 被拒

### Phase F — Typing indicator (ephemeral)

25. bob 在 composer 输入"hi" 但不发送
26. yougen 客户端:每 N ms 发 `ck.typing` ephemeral signal,payload `{ realm_id, actor, ttl_ms: 5000 }`
27. 断言:alice 的 timeline 上方显示 "bob is typing..." (`chat-typing-indicator` testid)
28. bob 停止输入 5s+
29. 断言:alice 视图的 typing 指示消失(过 ttl)

### Phase G — Presence

30. carol 关闭 yougen tab(或假装离线)
31. carol 的 client 在 onbeforeunload 发 `ck.presence` `{ state: "offline" }`
32. 断言:alice 视图 carol 的头像旁显示 offline icon(`presence-offline-indicator`)
33. carol 重新打开 → 发 `ck.presence` `{ state: "online" }` 
34. 断言:alice 视图 carol 又变 online

## Observable assertions(合并)

- Phase B 步骤 6/8:OR-Set reaction 收敛
- Phase C 步骤 11/13:reply chain 渲染
- Phase D 步骤 16-17:mention 精准通知
- Phase E 步骤 23:poll vote 收敛 + active vote 替换
- Phase F 步骤 27/29:typing 指示 + ttl 过期
- Phase G 步骤 32/34:presence 状态切换

## Edge cases / sub-tests

- **E14.1 reaction 并发竞态**:alice 和 bob 同时对 `M1` 加 + 撤 → OR-Set 仍正确(spec §8.5)
- **E14.2 mention E2EE sidecar**:E2EE Realm 中,服务端只能用 hash 路由,**不能**回推出 bob.did;断言服务端 log 不含 bob.did 明文
- **E14.3 poll closed**:`closes_at` 过后 vote 被 reducer 拒
- **E14.4 max_selections > 1**:多选 poll;一个 actor 可选 2 个 option;断言计数正确
- **E14.5 typing 在 redact 后**:bob 发了消息后 redact;typing 指示不应"复活"
- **E14.6 presence 隐私**:carol 在 client preferences 关 presence broadcast → 即使她在线,alice 看到的是 unknown / offline

## Implementation notes

- **soland 缺口**:`ck.content.poll{,.response}`、`ck.relation.mention`、mention sidecar hash 路由、`ck.typing` / `ck.presence` ephemeral channel — 实现度未知;reactions(OR-Set)应该已有
- **yougen 缺口**:poll UI(`poll-option-button`、`poll-close-button`、`poll-vote-count`)、typing indicator、presence indicator — 这些 testid 未确认存在
- **测试侧**:典型测 typing 需要"无 send" 状态;Playwright 用 `composer-input.fill()` 不 click send,等 N ms 然后查 alice 视图

## 总耗时预估

约 90s。
