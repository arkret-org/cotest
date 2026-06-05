# 通知(push prefs / DnD / per-space mute / mark-all-read)

## 目标

通知偏好的端到端:bob 在 space `S` 中订阅默认通知;mute `S` 后不再收;DnD 时段内静音所有;到期自动恢复;mark-all-read 清空 unread count;mention 触发 push;`evaluation_locus` 在 E2EE 中 client-side 求值。

## Spec 锚点

- `discovery/push-notifications.md` §2 — Push delivery model
- `discovery/push-notifications.md` §3 — Notification rules engine
- `discovery/push-notifications.md` §4.3.1 — Mention routing hint
- `discovery/push-notifications.md` §4.5 — `evaluation_locus`(server / client)
- `discovery/client-preferences.md` — 客户端偏好键(notification per-space)

## 拓扑

- 1 × soland + 1 × coauth + (可选 mock push gateway)

## Actors

| 名字 | 角色 |
|---|---|
| alice | space owner,发消息触发通知 |
| bob | 接收方,调 notification preferences |

## Steps

### Phase A — 默认通知

1. alice createRealm,seedMembers=[bob];bob acceptInvite
2. alice 发消息 `M1`
3. 断言:bob 的 `/notifications` 显示 `M1` 通知;in-app badge unread=1

### Phase B — Mute per-space

4. bob 进 `/notifications`,点 `S` 旁的 "Mute"
5. 客户端写 `yougen.preferences.notifications.<spaceId> = "muted"`
6. alice 发 `M2`
7. 断言:bob 的 `M2` **不**触发 push 通知(in-app badge 不增);消息**仍** 在 timeline(mute ≠ block)

### Phase C — Mention 在 muted space 中也通知(覆盖规则)

8. alice 发 `M3 = "@bob urgent"`
9. spec §3:即使 `S` 被 mute,direct mention 应当通知(可配置)
10. 断言:bob 收到 mention 通知(`mention-notification` testid)

### Phase D — Do-not-disturb 时段

11. bob 进 `/settings/notifications`,设 DnD `22:00 – 08:00`
12. 测试 harness 把系统时间 stub 到 23:00
13. alice 发 `M4`
14. 断言:bob 没收到 push;DnD 状态下,即使 mention 也安静 (取决于 policy)
15. 把时间 stub 到 10:00 → DnD 结束
16. alice 发 `M5`
17. 断言:bob 立即收到 `M5` 通知

### Phase E — Mark-all-read

18. 制造 N 条未读消息(alice 连发 5 条)
19. bob 进 `/notifications`,点 "Mark all read"
20. 断言:unread count = 0,所有通知行标 `read`

### Phase F — `evaluation_locus` 在 E2EE 中

21. 重建一个 E2EE space,加 notification rule `contains_keyword: "urgent"`(只 client 可求值,因为服务端看不到明文)
22. alice 发 `"this is urgent"`
23. 服务端发 blind wake-up push(spec §4.5)
24. 客户端解密 → 求值 rule → 显示 urgent notification

## Edge cases

- **E23.1 push gateway offline**:notification 仍写入 in-app `/notifications` 列表;push 单独失败不阻塞
- **E23.2 unmute 立即生效**:bob unmute `S` 后,下一条新消息触发通知
- **E23.3 DnD overrides**:超紧急(spec 可能定义 priority)能穿透 DnD
- **E23.4 cross-device read state**:bob 在 device-2 mark read 后,device-1 的 unread count 也清零

## Implementation notes

- **soland 缺口**:notification queue projection、rule engine、mention sidecar(参见 messaging/chat-advanced)
- **yougen 缺口**:`/notifications` panel 完整 UI、per-space mute toggle、`/settings/notifications` DnD picker
- **harness 缺口**:可选 mock push gateway 接收 push payload(为了断言 push 真发了)

## 总耗时预估

约 60s(含 DnD 时间 stub)。
