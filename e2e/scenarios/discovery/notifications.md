# 通知(push prefs / DnD / per-Realm mute / mark-all-read)

## 目标

通知偏好的端到端:bob 在 Realm `R` 中显式订阅全部通知;mute `R` 后普通与定向通知都不再收;DnD 时段内静音所有;到期自动恢复;mark-all-read 清空 unread count;mention 在未 muted 时触发 push;`evaluation_locus` 在 E2EE 中 client-side 求值。

## Spec 锚点

- `discovery/push-notifications.md` §2 — Push delivery model
- `discovery/push-notifications.md` §3 — Notification rules engine
- `discovery/push-notifications.md` §4.3.1 — Mention routing hint
- `discovery/push-notifications.md` §4.5 — `evaluation_locus`(server / client)
- `discovery/client-preferences.md` — 客户端偏好键(notification per-Realm)

## 拓扑

- 1 × coland + 1 × coauth + (可选 mock push gateway)

## Actors

| 名字 | 角色 |
|---|---|
| alice | Realm owner,发消息触发通知 |
| bob | 接收方,调 notification preferences |

## Steps

### Phase A — 显式 watch-all 通知

1. alice createRealm,seedMembers=[bob];bob acceptInvite
2. bob 对默认 discussion Strand 写入 `ak.strand.watch.set level=all`
3. alice 发消息 `M1`
4. 断言:bob 的 `/notifications` 显示 `M1` 通知;in-app badge unread=1

### Phase B — Mute per-Realm

5. bob 进 `/notifications`,点 `R` 旁的 "Mute"
6. 客户端写 `inkson.preferences.notifications.<realmId> = "muted"`
7. alice 发 `M2`
8. 断言:bob 的 `M2` **不**触发 push 通知(in-app badge 不增);消息**仍** 在 timeline(mute ≠ block)

### Phase C — Mention 在 muted Realm 中同样被抑制

9. alice 发 `M3 = "@bob urgent"`
10. spec §4.3.2:`watch_state=muted` MUST 收敛到 `dont_notify`
11. 断言:bob 不收到 mention 通知

### Phase D — Do-not-disturb 时段

12. bob 进 `/settings/notifications`,设 DnD `22:00 – 08:00`
13. 测试 harness 把系统时间 stub 到 23:00
14. alice 发 `M4`
15. 断言:bob 没收到 push;DnD 状态下,即使 mention 也安静 (取决于 policy)
16. 把时间 stub 到 10:00 → DnD 结束
17. alice 发 `M5`
18. 断言:bob 立即收到 `M5` 通知

### Phase E — Mark-all-read

19. 制造 N 条未读消息(alice 连发 5 条)
20. bob 进 `/notifications`,点 "Mark all read"
21. 断言:inkson 本地 unread badge 清零,所有通知行标 `read`;客户端按
    `discovery/read-receipts.md` 提交 `ak.read_cursor.advance`,通知投影继续通过
    `GET /_arkret/self/account/subscribe?catchup=true` 读取

### Phase F — `evaluation_locus` 在 E2EE 中

22. 重建一个 E2EE Realm,加 notification rule `contains_keyword: "urgent"`(只 client 可求值,因为服务端看不到明文)
23. alice 发 `"this is urgent"`
24. 服务端为 `mention_sidecar_digest` 命中的接收者派生脱敏 notification projection,并在 push 面走 blind wake-up(spec §4.5)
25. 客户端从 `/_arkret/self/account/subscribe` 拉取 projection,本地解密 → 求值 rule → 显示 urgent notification

## Edge cases

- **E23.1 push gateway offline**:notification 仍写入 in-app `/notifications` 列表;push 单独失败不阻塞
- **E23.2 unmute 立即生效**:bob unmute `S` 后,下一条新消息触发通知
- **E23.3 DnD overrides**:超紧急(spec 可能定义 priority)能穿透 DnD
- **E23.4 cross-device read state**:bob 在 device-2 mark read 后,device-1 的 unread count 也清零

## Implementation notes

- **coland 约束**:notification projection 只经 `/_arkret/self/account/subscribe` 暴露
- **inkson 缺口**:`/notifications` panel 完整 UI、per-Realm mute toggle、`/settings/notifications` DnD picker
- **harness 缺口**:可选 mock push gateway 接收 push payload(为了断言 push 真发了)

## 总耗时预估

约 60s(含 DnD 时间 stub)。
