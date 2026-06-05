# 单服务器三方协作

## 目标

验证在同一个 principal server 上,三个 actor 完成「建空间 → 邀请 → 接受 → 双向消息 → 编辑 / 撤回 / 反应 / 回复 → 晚到成员按 `history_visibility` 看到正确历史」的完整协作链路;过程中 anchor frontier 在所有成员之间收敛一致。

不验证:跨服务器联邦 (见 federation/cross-server)、审核封禁 (见 spaces/moderation-ban)、knock 申请 (见 spaces/knock-application)、第三方邮件邀请 (后续 invites/third-party)、设备授权 (后续 identity/account-device-auth)。

## Spec 锚点

- `cokret-spec/spec/v1/zh/models/space-and-place.md` §2 — Space 概念与字段
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.4 — `default_join_rule` 与 discoverability / history_visibility 三个轴独立
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.8 — Membership 状态机扩展
- `cokret-spec/spec/v1/zh/models/flow-and-message.md` §8 — Message 概览
- `cokret-spec/spec/v1/zh/models/flow-and-message.md` §8.4 — Chat 模式示例 (mention、reply、reaction、edit 的事件链)
- `cokret-spec/spec/v1/zh/models/flow-and-message.md` §8.5 — 冲突与收敛规则 (revision chain、redact tombstone)

## 拓扑

- 1 × soland (principal server) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 共享同一个 coauth;所有 actor 的 access token 都来自这个 coauth

(都是 cotest 现有 harness 直接提供的,不需要改 scripts/run-joint-e2e.ps1。)

## Actors

| 名字 | DID | 在 messaging/triad-collaboration 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:web:alice-s1-<uuid>.example` | 空间创建者 / owner | 测试开始前 |
| bob | `did:web:bob-s1-<uuid>.example` | 早期成员;邀请阶段加入 | 测试开始前 |
| carol | `did:web:carol-s1-<uuid>.example` | 晚到成员;在前 N 条消息之后才加入 | 测试开始前注册,但延后加入空间 |

## Pre-conditions

- 三个 DID 都通过 `POST /_soland/self/account/register` 注册过 (与现有 `ensureRegistered` 行为一致)
- 三个 actor 都持有有效 dev session token (`POST /_soland/gate/auth/dev-login`)
- 三个 actor 的 browser context 都通过 `yougen.config.v1` localStorage 注入 server_url + account_did + device_id + session_token

## Steps

### Phase A — 建空间 + 早期邀请

1. **alice** 通过 `/setup` 多步向导建空间 `S`:
   - title = `"messaging/triad-collaboration Triad Space ${stamp}"`
   - discoverability = `listed`
   - join_rule = `invite`
   - history_visibility = `joined` ← 关键:carol 加入前的消息对她不可见
   - seed_members = `[bob.did]` ← 在 Seed 步骤填,触发 alice 对 bob 的 invite 事件
2. 断言:`realm-lifecycle-flow` 显示 `created ck:space:...`,记录 `spaceId`
3. **bob** 加载 yougen,进入空间;隐式接受 invite (现有 helper 的行为是 seed members 已经被 alice 直接加成员,等于 invite + accept 一起);如果未来 yougen 把 invite/accept 拆开,这里要补一个 `bob 接受邀请` 的子步
4. 断言:bob 的 `/realms/${spaceId}/admin` 可访问、`realm-admin-panel` 渲染

### Phase B — 双向消息 + reactions + reply + edit

5. **alice** 进 `/timeline/${spaceId}`,发消息 `M1 = "alice hello ${stamp}"`
   - 断言:`timeline` 出现 `M1`、`write-status` 文本含 `persisted`
6. **bob** 进 `/timeline/${spaceId}` (通过 yougen 同步),timeline 包含 `M1`
7. **bob** 对 `M1` 加一个 reaction (chat-react-button → reaction-picker 选第一个)
   - 断言:`chat-reactions` 在 `M1` 卡片上可见
8. **bob** 回复 `M1`,发 `M2 = "bob replying ${stamp}"`
   - 断言:`M2` 渲染、`chat-reply-indicator` 可见
9. **alice** 同步;timeline 包含 `M2`,且 `M2` 上的 reply indicator 指向 `M1`
10. **bob** 编辑 `M2` → `M2' = "bob replying edited ${stamp}"`
    - 断言:`write-status` 含 `revised`;`timeline-event` 含 `M2'` 文本

### Phase C — 晚到成员 + history_visibility 验证

11. **alice** 通过 `/realms/${spaceId}/admin` 的 `invite-member` 流程邀请 `carol.did`
    - 断言:`realm-admin-panel` 状态文本含 `invited carol.did`
12. **carol** 加载 yougen,进入空间
13. **carol** 看 `/timeline/${spaceId}`
    - 断言 (history_visibility = joined 的语义):**carol 看不到** `M1` / `M2`(她加入之前的消息);timeline 是空的,或者只显示一个"history starts here"占位
    - (实现侧检查:`getByTestId("timeline-event")` 的数量为 0;或者出现 `joined-from-here-marker`)
14. **alice** 发新消息 `M3 = "welcome carol ${stamp}"`
15. **carol** 同步,timeline 包含 `M3`,且**不含** `M1/M2`

### Phase D — Redact + tombstone 收敛

16. **bob** 对自己的 `M2'` 触发 redact (`redact-button` → `confirm-redact-button`)
    - 断言:`redacted-tombstone` 在 `M2'` 位置渲染;`write-status` 含 `tombstoned`
17. **alice** 同步;原 `M2'` 卡片现在显示为 tombstone(不再显示原文)
18. **carol** 不受影响 — 她本来就看不到 `M2'`

### Phase E — 三方 anchor frontier 一致

19. 三方各调一次 `GET /_cokret/self/account/subscribe?catchup=true`(或读 `sync-cursor` testid),分别记录 anchor frontier
20. 断言:三个 frontier 集合一致(忽略 carol 那侧因 history_visibility 被裁掉的部分,只比较 carol 可见的 `M3` 之后的 anchor 集合)

## Observable assertions (合并清单)

- 步骤 2 之后:`spaceId` 形如 `ck:space:...`
- 步骤 5-6:alice 写的 `M1` 在 bob 那侧 30s 内出现
- 步骤 7-9:reaction、reply indicator 双向同步
- 步骤 10:edit 后 `write-status` 含 `revised`,旧文本不再显示
- 步骤 13:carol 看不到加入前的消息(`timeline-event` 数 = 0 或仅 marker)
- 步骤 15:carol 加入后的 `M3` 对所有三方可见
- 步骤 17:redact 后 alice 看到 tombstone,carol 不受影响
- 步骤 20:三方 anchor frontier 在可见集合上一致

## Edge cases / sub-tests

- **E1.1 idempotent invite**:alice 在 Phase C 之前对 carol 连发两次 invite,只产生一个 `ck.invite.create` 事件,后续 accept 仍能成功
- **E1.2 history_visibility=shared**:同样的步骤改用 `shared` 而不是 `joined`,carol 应该看到 `M1/M2/M2'/tombstone`(`shared` 允许新成员读"应该共享的"历史) — spec §3.4 / §3.7
- **E1.3 history_visibility=world_readable**:carol 在加入空间**之前**就能通过 `/timeline/${spaceId}` 看到消息(在 spec 里 `world_readable` 允许未加入者读历史) — 这一条要小心,因为它跨过了 join_rule 的 gate

后两条建议拆成独立的小 spec(`messaging/triad-collaboration.2`、`spaces/history-world-readable`),保持主 scenario 紧凑。

## Implementation notes

- Yougen 当前的 `seedMembers` 通过 `/setup` 注入,语义可能等价于 "alice 直接添加" 而非 "alice invite + bob accept"。如果 spec 严格要求 invite-then-accept 顺序,这一条要么补 yougen 的 accept UI,要么换成 `/realms/:id/admin` 的 `invite-member` 流程驱动
- `/realms/:id/admin` 的 invite UI (`invite-member`、`invite-target-input`、`send-invite-button`) 已经存在,Phase C 直接用
- Timeline 现有的 testid:`composer-input`、`send-button`、`timeline`、`timeline-event`、`write-status`、`edit-button`、`save-edit-button`、`redact-button`、`confirm-redact-button`、`redacted-tombstone`、`chat-react-button`、`chat-reactions`、`chat-reply-button`、`chat-reply-indicator`
- 不需要新 helper,基本能用现有 `JointUserPage.createRealm` + `JointUserPage.gotoRealmAdmin` + 直接 `page.goto("/timeline/${spaceId}")` 覆盖
- 步骤 13 的 "carol 看不到旧消息" 是新增断言点,要确认 yougen 实现了 history_visibility 的 client-side 过滤(否则 fail 不代表 spec 不对,而是 yougen 漏实现)— 跑测前**先确认或挂 TODO**

## 总耗时预估

单次跑约 60-90s(三个 browser context、4 阶段、20 步左右)。
