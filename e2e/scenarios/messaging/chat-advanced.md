# Chat 高级功能(reactions / replies / mentions / polls / 输入指示 / presence)

## 目标

验证 chat 完整功能面:reactions(OR-Set 收敛)、replies、@-mention 触发通知(明文；E2EE 仅由客户端解密后求值)、polls 投票收敛、ephemeral typing + presence、read receipts(详见 messaging/read-receipts)。

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
4. bob 对 `M1` 加 `👍` reaction → `ak.reaction.add`
5. carol 对 `M1` 加 `👍` reaction(并发)→ 第二条 `ak.reaction.add`
6. 断言:alice、bob、carol 视图都看到 `M1` 上有 2 个 `👍`(OR-Set 自然收敛)
7. bob 撤销自己的 reaction → `ak.reaction.remove`
8. 断言:三方视图都看到剩 1 个 `👍`(carol 的)

### Phase C — Replies + thread

9. bob 对 `M1` 点 reply → `chat-reply-banner` 显示
10. bob 发 `M2 = "yes, ship"`,自动 `reply_to: M1.event_id`
11. 断言:`M2` 在 timeline 渲染 `chat-reply-indicator`,展开后显示 `M1` 引用
12. carol 也 reply `M1` 发 `M3 = "agreed"`
13. 断言:三方都见 `M2`、`M3`,且都标记为 `M1` 的 reply(同一 thread)

### Phase D — Mentions + notification

14. alice 发 `M4 = "@bob please confirm"`
15. inkson 客户端:
    - 解析 `@bob` token,生成 `ak.relation.mention` payload
    - 在 plain text Realm:`ak.message.create.payload.mentions = [bob.did]`
    - 在 E2EE Realm:mention 仅留在 ciphertext，Station 按 push-notifications §4.5 做 blind/batch wakeup；禁止专用 routing sidecar/hash 输入。
16. 断言:bob 收到由 account timeline 本地派生的 notification(检查 inkson 的 in-app notification panel)
17. 断言:carol **没**收到 mention 通知(她没被点名)

### Phase E — Poll

18. Alice 显式创建未激活 MLS 的明文 Realm，并创建投票：标准 `ak.message.create` 的 Content Block 为 `ak.content.poll`，使用 `poll.answers[{id,text}]` 和 `poll.max_selections=1`；题目位于 fallback `body`。
19. Bob、Carol 加入后，由 Alice 分别授予 `ak.message.create`。成员身份本身不授予发送或投票权限。
20. Bob 发送标准 Message，Content Block 为 `ak.content.poll.response`，其中 `poll_response.poll_ref` 是原投票的 Message ID，`selections` 是 answer ID 数组。
21. Bob 从选项 A 改选 B，Carol 选 B；精确断言 `poll-vote-count` 的 A=0、B=2，不匹配包含时间戳的选项整行。
22. v1 只允许明文 `payload.content` 中的正式 poll／response；不得放入 `encrypted_content`，也不得为投票降级 E2EE scope。Alice 的卡片须取得正式 Message ID 和已验证的 open 状态后才进入成员投票流程，不能把本地乐观卡片视为接受结果。
23. 当前“Close poll”只关闭本地卡片控件。v1 没有关闭投票的 wire carrier；该 UI 操作不声称改变其他客户端或服务端的投票权限，也不以其拒绝迟到的合法 response。

### Phase F — Typing indicator (ephemeral)

25. bob 在 composer 输入"hi" 但不发送
26. inkson 客户端:每 N ms 发 `ak.typing` ephemeral signal,payload `{ realm_id, actor, ttl_ms: 5000 }`
27. 断言:alice 的 timeline 上方显示 "bob is typing..." (`chat-typing-indicator` testid)
28. bob 停止输入 5s+
29. 断言:alice 视图的 typing 指示消失(过 ttl)

### Phase G — Presence

30. carol 关闭 inkson tab(或假装离线)
31. carol 的 client 在 onbeforeunload 发 `ak.presence` `{ state: "offline" }`
32. 断言:alice 视图 carol 的头像旁显示 offline icon(`presence-offline-indicator`)
33. carol 重新打开 → 发 `ak.presence` `{ state: "online" }` 
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
- **E14.2 E2EE mention 隐私**:真实 MLS mention 只保留在密文内，Bob 本地解密可读；服务端 Event 不含 Bob 主体或正文明文，不携带专用 mention 路由字段。携带旧 mention sidecar 字段的请求必须 schema reject 且不发布 Event（push-notifications.md §4.5）。
- **E14.3 poll closed**:本地关闭后隐藏该客户端的选项按钮；v1 不存在关闭 carrier，不能据此断言 reducer 拒绝合法迟到 vote
- **E14.4 max_selections > 1**:多选 poll;一个 actor 可选 2 个 option;断言计数正确
- **E14.5 typing 在 redact 后**:bob 发了消息后 redact;typing 指示不应"复活"
- **E14.6 presence 隐私**:carol 在 client preferences 关 presence broadcast → 即使她在线,alice 看到的是 unknown / offline

## Implementation notes

- **soland 缺口**:`ak.content.poll{,.response}`、`ak.relation.mention`、`ak.typing` / `ak.presence` ephemeral channel — 实现度未知;reactions(OR-Set)应该已有。v1 禁止专用 mention sidecar/hash 路由。
- **inkson 缺口**:poll UI(`poll-option-button`、`poll-close-button`、`poll-vote-count`)、typing indicator、presence indicator — 这些 testid 未确认存在
- **测试侧**:典型测 typing 需要"无 send" 状态;Playwright 用 `composer-input.fill()` 不 click send,等 N ms 然后查 alice 视图

## 总耗时预估

约 90s。
