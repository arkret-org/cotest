# 个人 blocklist (client-side filter)

## 目标

验证用户**个人 blocklist** 的端到端语义:alice 把 bob 加入个人 blocklist 后,bob 的新消息不再在 alice 的 timeline / notifications 中渲染(client-side filter);unblock 后可见性恢复;blocklist 记录走 actor-private account_data,跨设备 sync;跨服务器场景下 server1 将 alice 的 block 状态推送到 server2,使后者减少 bob → alice 方向的 push。

不验证(明确区分):
- Realm-level ban / kick / quarantine — 那是**服务端**对内容/成员的强制隔离,见 `spaces/moderation-ban`、`governance/content-moderation` 的 quarantine 流程
- mute(通知静默,消息仍可见)— 见 `discovery/notifications.md`
- appeal flow — 见 `governance/organization-policy`

## Spec 锚点

- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §4 — Personal blocklist 概念、与 quarantine 的边界
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §5 — Mute vs block 语义差异
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §6 — Federation 中的 block propagation(server hint,非 PII 泄露)
- `cokret-spec/spec/v1/zh/discovery/client-preferences.md` §2 — account_data 写 blocklist entry 的 schema(`ck.account.blocklist`)

## 拓扑

- Phase A–F:1 × soland (principal server) + 1 × coauth(单服务器即可覆盖个人 blocklist 主流程)
- Phase G:2 × soland (`server1`、`server2`) + 共享 coauth — 用于 federation 跨服务器 block hint

## Actors

| 名字 | DID | 角色 | 注册时机 |
|---|---|---|---|
| alice | `did:web:alice-s31-<uuid>.example` | 执行 block 的 user | 测试开始前 |
| bob | `did:web:bob-s31-<uuid>.example` | 被 block 的 user;同 Realm 成员 | 测试开始前 |

## Pre-conditions

- alice / bob 都通过 `POST /_soland/self/account/register` 注册
- alice / bob 都持有有效 dev session token
- 两个 actor 的 browser context 都注入了 `yougen.config.v1` localStorage

## Steps

### Phase A — 注册 + 共享 Realm

1. alice、bob 注册
2. **alice** 通过 `/setup` 建 Realm `R`(`discoverability=listed`、`join_rule=invite`、`history_visibility=joined`、`seed_members=[bob.did]`)
3. **bob** acceptInvite(`S`);双方都能进 `/timeline/${realmId}`

### Phase B — bob 发 M1,alice 可见(基线)

4. **bob** 进 `/timeline/${realmId}`,发 `M1 = "bob says hi ${stamp}"`
5. **alice** 进 `/timeline/${realmId}` 同步
   - 断言:`timeline-event` 含 `M1` 文本
   - 这是 baseline:未 block 时一切正常

### Phase C — alice 进 settings 把 bob 加入 blocklist

6. **alice** 进 `/settings/blocked-users`
   - 断言:`blocked-users-panel` 可见;`blocked-users-list` 渲染(可能为空)
7. **alice** 在 `block-target-input` 填 `bob.did`,点 `block-user-button`
   - 断言:`blocked-users-list` 新增一条 `blocked-user-row`,显示 bob.handle / bob.did
   - 断言:`write-status` 含 `blocklist updated` 或等效文本

### Phase D — client 提交 account_data blocklist event

8. alice 的 yougen client 应该把这次 block 持久化为 soland 的 actor-private account_data event:
   - 调用:`POST /_cokret/self/events`,提交 `ck.account_data.set`,payload `{ key: "ck.account.blocklist", owner: alice.did, body: { version: 1, entries: [{ target: { kind: "actor", did: bob.did }, mode: "block", applies_to: ["messages", "mentions", "dm", "calls", "presence", "notifications", "directory"], created_at: <ts> }] }, updated_at: <ts> }`
   - 断言 (HTTP 层):events submit 返回 `status=accepted`
   - 断言 (跨设备 sync):`GET /_cokret/self/account/subscribe?catchup=true` 的 `account_data.events` 返回同样的 entries
   - 备注:这是 actor-private — 只对 alice 自己的 device 同步,bob 拿不到

### Phase E — bob 发 M2,alice 看不到(client-side filter)

9. **bob** 进 `/timeline/${realmId}`,发 `M2 = "bob says hi again ${stamp}"`
   - bob 自己的 timeline 上 `M2` 正常显示(他不知道被 alice block 了)
10. **alice** 同步 `/timeline/${realmId}`
    - 断言:`timeline-event` **不含** `M2`(client-side filter 把 author=bob.did 的事件过滤掉)
    - 断言:`timeline-event` 仍含 `M1`(Phase B 时已经渲染,实现可选:是否回溯隐藏旧消息;spec §4 倾向于只过滤 block 之后的新事件,旧消息保留 — 这一条要在断言里写清)
11. **alice** 进 `/notifications`
    - 断言:`notifications-panel` 中没有 bob 在 Phase E 发的 `M2` 通知

### Phase F — unblock 恢复可见

12. **alice** 回 `/settings/blocked-users`,在 bob 那行点 `unblock-button`
    - 断言:`blocked-users-list` 不再含 bob 行
    - 断言:client 提交 `ck.account_data.set` 把 entry 移除(或 mark `kind: "unblock"`)
13. **bob** 再发 `M3 = "bob is back ${stamp}"`
14. **alice** sync `/timeline/${realmId}`
    - 断言:`timeline-event` 含 `M3`
    - (可选)断言:Phase E 的 `M2` 此时也可见(如果 client 实现的是 "filter 在渲染时实时判断" 而非 "首次接收时丢弃" — spec §4 倾向于实时判断,以保证 unblock 后历史可恢复)

### Phase G — Federation 跨服务器 block hint

15. 拓扑切到 2 server:`alice@server1`、`bob@server2`,通过 federation peering 共享 Realm `R_fed`
16. **alice@server1** 在 `/settings/blocked-users` 中 block `bob@server2`
17. server1 写 alice 的 account_data;同时 server1 应该向 server2 发一个 federation hint:
    - `POST {server2}account_data blocklist event`,payload `{ actor: alice.did, blocked: bob.did }`
    - 这个 hint **不泄露** alice 的 PII(只告诉 server2:bob → alice 方向的 push 可以减少 / 完全不送)
18. **bob@server2** 在 `S_fed` 发 `M_fed`
19. 断言:
    - server2 不再向 server1 推送 `bob → alice` 的 push notification(可通过 server2 的 federation outbox audit log / 测试 hook 验证)
    - alice@server1 的 timeline 仍 client-side 过滤掉 `M_fed`(双重保险:server hint 减负载,client filter 保正确性)

## Observable assertions(合并清单)

- Phase B 步骤 5:alice 在 block 之前能看到 `M1`
- Phase C 步骤 7:`blocked-users-list` 新增 bob 行
- Phase D 步骤 8:`ck.account_data.set` 与 `ck.self.account.stream.subscribe` 返回一致的 entries
- Phase E 步骤 10:alice timeline 不含 `M2`
- Phase E 步骤 11:alice notifications 不含 `M2` 通知
- Phase F 步骤 12-14:unblock 后 `M3` 可见
- Phase G 步骤 19:server2 federation outbox 不再向 server1 推 bob 的 push;alice client 仍过滤 `M_fed`

## Edge cases / sub-tests

- **E11.1 Quarantine vs block**:同一个 Realm 中 admin 把 bob 的某条消息 quarantine(`POST /_cokret/self/moderation/quarantine`)— 这是**服务端**操作,影响**所有**成员;alice 的个人 block 只影响 alice 自己。验证两者**互不依赖**:即使 alice 没 block bob,quarantine 的消息对 alice 也不可见(以 placeholder 渲染);即使 admin 没 quarantine,alice block 也能让 bob 的消息对 alice 单独不可见。
- **E11.2 mute vs block 差异**:alice 在 `/settings/notifications` 把 bob mute(不是 block)→ bob 的消息在 alice timeline **仍可见**,但 push notification 不送达(`notifications-panel` 中无新条目)。这与 block 的"完全隐藏"形成对照。
- **E11.3 被 block 的用户视角**:bob 在 `/timeline/${realmId}` 自己看自己的消息,M1/M2/M3 都正常显示,`write-status` 全部 `persisted`;bob 的 `/notifications` 不会出现"You were blocked by alice"这类提示(spec §4 明确:block 不可被被 block 方探测,反 social-graph 泄露)。

## Implementation notes

- **yougen 实现**:`/settings/blocked-users` 页面已写入 `LocalStateStore::client_blocklist` 并通过 `ck.account.blocklist` account_data 同步;`blocked-users-panel` / `blocked-users-list` / `blocked-user-row` / `block-target-input` / `block-user-button` / `unblock-button` / `write-status` testids 已接入。
- **soland 实现**:`ck.account_data.set` + `ck.self.account.stream.subscribe` 已用于个人 blocklist;事件 query、account sync timeline、`/_soland/self/notifications` 与 `index/notifications` 都会按 actor-private blocklist 过滤;`POST account_data blocklist event` 与 `GET account_data blocklist events` 支持 block hint 记录和 unblock retract。
- **测试侧**:主流程、E11.1、E11.2、E11.3 均为 live tests;Phase G 的跨服务器成本用本地 blocklist account_data 记录/撤回端点验证,完整双 soland outbox suppression 可在 `federation/cross-server` harness 扩展时继续加深。

## 风险

- Phase G 的远端 outbox 减载目前通过本地 blocklist account_data contract 验证,未强制要求双服务器拓扑。
- spec §4-§6 是 SHOULD/MUST 混合 — 主流程 (block / unblock / client filter) 是 MUST,federation hint 是 SHOULD,当前测试覆盖本地 contract 和撤回语义。

## 总耗时预估

约 60-90s(单服务器主流程);Phase G federation 子测试加 30-45s。
