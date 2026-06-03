# Read receipts + 隐私开关

## 目标

验证 read receipt 三层语义:client preference(关闭自己的 receipt 发送)、space disclosure policy(`optional`/`required`/`disabled`)、actor-private read marker(多设备同步)。alice 关掉自己的 receipt,bob 看不到 alice 读;alice 重开,bob "catch up";policy=required 时强制覆盖 client 偏好。

不验证:E2EE 中 receipt 的具体加密路径(留到后续)、基础消息收发(messaging/triad-collaboration)。

## Spec 锚点

- `discovery/read-receipts.md` §2.1-§2.4 — ephemeral receipt 格式 + debounce + flush
- `discovery/read-receipts.md` §2.5 — Space disclosure policy(`disabled` / `optional` / `required` / `scope_overrides_allowed`)
- `discovery/read-receipts.md` §3.1-§3.2 — Read Marker actor-private(多设备同步)
- `discovery/client-preferences.md` — Read receipt 偏好键

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | 读消息的人,验证 client/policy 开关 |
| bob | 发消息的人,观察 alice 的 receipt 是否到达 |

## Steps

### Phase A — Setup

1. alice createSpace `S_a`,seedMembers=[bob]
2. bob acceptInvite
3. space 默认 `disclosure = optional`(yougen 应有默认 setting,或测试侧设置)

### Phase B — 默认开启,alice 读 10 条 → bob 看到 receipt

4. bob 在 `S_a` 连发 `M1..M10`
5. alice 进 timeline,自顶向下滚动阅读
6. yougen 客户端用 debounce window(≥1s)合并多个 read,在 alice 停顿时发 **一个** `ck.receipt.read` ephemeral,payload `{ space_id, up_to_event: M10.event_id }`
7. 断言:bob 视图 `M10` 旁出现 alice 的"已读"头像 + 时间戳(`read-receipt-alice` testid)
8. bob 视图的 `M9..M1` 也应隐式显示已读(receipt cover 到 `M10` 表示前面都读了)

### Phase C — alice 关闭 receipt 发送(client preference)

9. alice 进 `/settings/privacy`,把"Send read receipts"关掉
10. 客户端存 `yougen.preferences.send_read_receipts = false`
11. bob 再发 `M11..M15`
12. alice 进 timeline 读完
13. 客户端**不发** `ck.receipt.read` ephemeral
14. 断言:bob 视图 `M11..M15` **不** 显示 alice 的已读;`M10` 的旧 receipt 仍在(老 receipt 不会被撤回)
15. 断言:服务端 sync 队列里不应有 alice 对 `M11..M15` 的 ephemeral receipt(可通过 service log 验证)

### Phase D — alice 重开 receipt

16. alice 把开关重新打开
17. bob 再发 `M16..M20`
18. alice 进 timeline 读完
19. 客户端发 `ck.receipt.read { up_to_event: M20.event_id }`
20. 断言:bob 视图 `M16..M20` 都显示 alice 已读;`M11..M15` 仍**未** 显示 alice 已读(receipt 不回溯到关闭期间的消息)

### Phase E — Space disclosure = `required` 强制开

21. alice(owner)把 `S_a` 的 read receipt policy 改成 `disclosure = required`
22. alice 在自己的 `/settings/privacy` 把"Send read receipts"再次关闭(尝试 bypass)
23. yougen 客户端:检测到 space policy = required,把 toggle 锁定;UI 提示"This space requires read receipts"
24. bob 再发 `M21`
25. alice 读
26. 即使 client preference = false,policy = required 强制让客户端发 receipt
27. 断言:bob 看到 alice 已读 `M21`

### Phase F — Space disclosure = `disabled`

28. alice 把 policy 改成 `disabled`
29. bob 发 `M22`
30. alice 读
31. 客户端**不**发 receipt;就算发了,Sync Service MUST reject / silently drop(spec §2.5)
32. 断言:bob **不** 看到 alice 已读 `M22`

### Phase G — Read marker 多设备同步(actor-private)

33. alice 在 device-1 读到 `M30`(假设 disclosure 回到 optional)
34. yougen 在 device-1 写 actor-private encrypted account data:`ck.read_cursor.advance = M30.event_id`
35. alice 在 device-2 拉 sync → 读 marker → 自动滚动到 `M30`
36. 断言:device-2 timeline 上 `M30` 标"上次读到这里"(`last-read-cursor` testid)
37. (read marker 不广播给 bob;它是 actor-private)

## Observable assertions(合并)

- Phase B 步骤 7-8:默认情况 receipt 到达
- Phase C 步骤 14-15:client preference off,receipt 不发
- Phase D 步骤 20:重开后只对新消息生效
- Phase E 步骤 27:required policy 强制
- Phase F 步骤 32:disabled policy 阻断
- Phase G 步骤 36:多设备 read marker 同步

## Edge cases / sub-tests

- **E22.1 高频滚动 debounce**:alice 1s 内滚过 100 条消息,客户端只发 1 个 receipt(覆盖最远的 event)
- **E22.2 redacted message receipt**:bob 的 `M5` 被 redact,alice receipt 指向 `M10` 仍合法
- **E22.3 multi-device receipt 协调**:alice 同时在 device-1/device-2 各读到不同位置;Sync Service 用 HLC 决定 broadcast 哪个 receipt(spec §3.2 末尾)
- **E22.4 E2EE space 中的 receipt**:E2EE space 中 receipt 是否能"contains keyword" 类规则?客户端本地求值,服务端只见 blind wake(spec push-notifications.md §4.5)
- **E22.5 toggle 在阅读中**:alice 在读到 `M50` 时关 toggle → 客户端 flush 已 debounce 的 receipt 还是丢弃?spec §2.3 说允许 flush 或 discard,看 yougen 实现

## Implementation notes

- **soland 缺口**:`ck.receipt.read` ephemeral 路由、policy enforcement(`required` 强制 / `disabled` reject)、`ck.read_cursor.advance` actor-private account data — 实现度未知
- **yougen 缺口**:`/settings/privacy` 的 send-read-receipts toggle、space disclosure policy 编辑入口、receipt 头像渲染(`read-receipt-<actor>` testid)— 这些当前可能不全
- **测试侧**:用 `Promise.race` 等 receipt 出现 vs 超时 5s 来断言"不出现"

## 总耗时预估

约 90s。
