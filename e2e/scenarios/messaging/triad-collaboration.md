# 单服务器三方协作

## 目标

验证在同一个 Station 上,三个 actor 完成「建 Realm → 邀请 → 接受 → 双向消息 → 编辑 / 撤回 / 反应 / 回复 → 晚到成员按 `history_access` 看到正确历史」的完整协作链路;过程中 accepted Event frontier 在所有成员之间收敛一致。

不验证:跨服务器联邦 (见 federation/cross-server)、审核封禁 (见 spaces/moderation-ban)、第三方邮件邀请 (后续 invites/third-party)、设备授权 (后续 identity/account-device-auth)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/models/realm-and-space.md` §2 — Space 概念与字段
- `arkret-spec/spec/v1/zh/models/realm-and-space.md` §3.4 — `default_join_rule` 与 discoverability / history_access 三个轴独立
- `arkret-spec/spec/v1/zh/models/realm-and-space.md` §3.8 — Membership 状态机扩展
- `arkret-spec/spec/v1/zh/models/strand-and-message.md` §8 — Message 概览
- `arkret-spec/spec/v1/zh/models/strand-and-message.md` §8.4 — Chat 模式示例 (mention、reply、reaction、edit 的事件链)
- `arkret-spec/spec/v1/zh/models/strand-and-message.md` §8.5 — 冲突与收敛规则 (revision chain、redact tombstone)

## 拓扑

- 1 × coland (Station) — 假设监听 `http://127.0.0.1:<coland_port>`
- 1 × coauth (private authentication process) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 共享同一个 coauth;所有 actor 的 session credential 都来自这个 coauth

(都是 cotest 现有 harness 直接提供的,不需要改 scripts/run-joint-e2e.ps1。)

## Actors

| 名字 | DID | 在 messaging/triad-collaboration 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s1-<uuid>.example` | Realm 创建者 / owner | 测试开始前 |
| bob | `did:webvh:z6mkfixture:bob-s1-<uuid>.example` | 早期成员;邀请阶段加入 | 测试开始前 |
| carol | `did:webvh:z6mkfixture:carol-s1-<uuid>.example` | 晚到成员;在前 N 条消息之后才加入 | 测试开始前注册,但延后加入 Realm |

## Pre-conditions

- UI 旅程通过既有 `openDpopUserPage` 完成真实 Coauth 注册、DPoP session-grant 登录和 Inkson 设备初始化，各 actor 使用隔离的 browser context。
- 邀请由创建者提交，成员显式接受；membership 本身不授予消息写入能力，所需 capability 由创建者通过正式权限 UI 授予。
- API 子用例与 UI 旅程分别计数；API helper 的执行不替代真实 UI 断言。

### 明确拒绝后的持久终态回归（Inkson #38）

- 依据 `authz/capabilities.md` §3.2 和 `models/event-and-patch.md` §5.1 的提交生命周期，在 Bob 获得 `ak.message.create` 前通过真实 composer 发送独特消息，断言明确失败、草稿恢复。
- 完整 document navigation 后，原本地消息仍须为 `Message send failed`，不得显示 `data-send-state=sending`。
- Alice 通过正式 UI 授权，Bob 发送另一条独特消息；Alice 必须实际接收新消息且看不到原拒绝消息。
- Bob 再次完整 document navigation 后，新消息须为 accepted Event，旧拒绝行仍失败，不因后续成功而复活为 Sending。
- Carol 晚加入后，两条加入前消息均不可见。该 UI 旅程保持既有明文拓扑；真实 MLS 现场和原生 unknown-outcome 反向控制分别留存，不以此测试冒充覆盖。

## Steps

### Phase A — 建 Realm + 早期邀请

1. **alice** 通过 `/setup` 多步向导建 Realm `R`:
   - title = `"messaging/triad-collaboration Triad Realm ${stamp}"`
   - discoverability = `listed`
   - join_rule = `invite`
   - history_access = `since_join` ← 关键:carol 加入前的消息对她不可见
   - seed_members = `[bob.did]` ← 在 Seed 步骤填,触发 alice 对 bob 的 invite 事件
2. 断言:`realm-lifecycle-strand` 显示 `created ak:realm:...`,记录 `realmId`
3. **bob** 加载 inkson,进入 Realm;隐式接受 invite (现有 helper 的行为是 seed members 已经被 alice 直接加成员,等于 invite + accept 一起);如果未来 inkson 把 invite/accept 拆开,这里要补一个 `bob 接受邀请` 的子步
4. 断言:bob 的 `/realms/${realmId}/admin` 可访问、`realm-admin-panel` 渲染

### Phase B — 双向消息 + reactions + reply + edit

5. **alice** 进 `/timeline/${realmId}`,发消息 `M1 = "alice hello ${stamp}"`
   - 断言:`timeline` 出现 `M1`、`write-status` 文本含 `persisted`
6. **bob** 进 `/timeline/${realmId}` (通过 inkson 同步),timeline 包含 `M1`
7. **bob** 对 `M1` 加一个 reaction (chat-react-button → reaction-picker 选第一个)
   - 断言:`chat-reactions` 在 `M1` 卡片上可见
8. **bob** 回复 `M1`,发 `M2 = "bob replying ${stamp}"`
   - 断言:`M2` 渲染、`chat-reply-indicator` 可见
9. **alice** 同步;timeline 包含 `M2`,且 `M2` 上的 reply indicator 指向 `M1`
10. **bob** 编辑 `M2` → `M2' = "bob replying edited ${stamp}"`
    - 断言:`write-status` 含 `revised`;`timeline-event` 含 `M2'` 文本

### Phase C — 晚到成员 + history_access 验证

11. **alice** 通过 `/realms/${realmId}/admin` 的 `invite-member` 流程邀请 `carol.did`
    - 断言:`realm-admin-panel` 状态文本含 `invited carol.did`
12. **carol** 加载 inkson,进入 Realm
13. **carol** 看 `/timeline/${realmId}`
    - 断言 (history_access = since_join 的语义):**carol 看不到** `M1` / `M2`(她加入之前的消息);timeline 是空的,或者只显示一个"history starts here"占位
    - (实现侧检查:`getByTestId("timeline-event")` 的数量为 0;或者出现 `joined-from-here-marker`)
14. **alice** 发新消息 `M3 = "welcome carol ${stamp}"`
15. **carol** 同步,timeline 包含 `M3`,且**不含** `M1/M2`

### Phase D — Redact + tombstone 收敛

16. **bob** 对自己的 `M2'` 触发 redact (`redact-button` → `confirm-redact-button`)
    - 断言:`redacted-tombstone` 在 `M2'` 位置渲染;`write-status` 含 `tombstoned`
17. **alice** 同步;原 `M2'` 卡片现在显示为 tombstone(不再显示原文)
18. **carol** 不受影响 — 她本来就看不到 `M2'`

### Phase E — 三方 accepted Event frontier 一致

19. 三方各调一次 `GET /_arkret/self/account/subscribe?catchup=true`(或读 `sync-cursor` testid),分别记录 accepted Event frontier
20. 断言:三个 frontier 集合一致(忽略 carol 那侧因 history_access 被裁掉的部分,只比较 carol 可见的 `M3` 之后的 anchor 集合)

## Observable assertions (合并清单)

- 步骤 2 之后:`realmId` 形如 `ak:realm:...`
- 步骤 5-6:alice 写的 `M1` 在 bob 那侧 30s 内出现
- 步骤 7-9:reaction、reply indicator 双向同步
- 步骤 10:edit 后 `write-status` 含 `revised`,旧文本不再显示
- 步骤 13:carol 看不到加入前的消息(`timeline-event` 数 = 0 或仅 marker)
- 步骤 15:carol 加入后的 `M3` 对所有三方可见
- 步骤 17:redact 后 alice 看到 tombstone,carol 不受影响
- 步骤 20:三方 accepted Event frontier 在可见集合上一致

## Edge cases / sub-tests

- **E1.1 live-target slot**:同一 Realm 内对同一 `invitee_account_id` 连发两次 direct invite,第二条命中已登记的 `ak.component.invite.live_target.v1` 名额,被 `failed_precondition` / `invite_live_target_occupied` 原子拒绝:Realm 权威日志只出现一条 `ak.invite.create`,持有 active invite consent 的被邀请方也只看到一份 private delivery 凭据。客户端不得换新 `event_id` 重发 create。
- **E1.2 history_access=all_history_for_current_members**:同样的步骤改用 `all_history_for_current_members` 而不是 `since_join`，carol 成为当前成员后应看到 `M1/M2/M2'/tombstone`；未加入者仍不得读取 Realm 历史。
- **E1.4 membership leave/rejoin**:bob 主动 `leave` 后不再出现在 Realm `members[]`,普通消息写入被拒绝;owner 重新提交 `join` 后,bob 可以再次写入同一 Realm

E1.3 建议拆成独立的小 spec(`spaces/history-world-readable`),保持主 scenario 紧凑。

## Implementation notes

- Inkson 当前的 `seedMembers` 通过 `/setup` 注入,语义可能等价于 "alice 直接添加" 而非 "alice invite + bob accept"。如果 spec 严格要求 invite-then-accept 顺序,这一条要么补 inkson 的 accept UI,要么换成 `/realms/:id/admin` 的 `invite-member` 流程驱动
- `/realms/:id/admin` 的 invite UI (`invite-member`、`invite-target-input`、`send-invite-button`) 已经存在,Phase C 直接用
- Timeline 现有的 testid:`composer-input`、`send-button`、`timeline`、`timeline-event`、`write-status`、`edit-button`、`save-edit-button`、`redact-button`、`confirm-redact-button`、`redacted-tombstone`、`chat-react-button`、`chat-reactions`、`chat-reply-button`、`chat-reply-indicator`
- 不需要新 helper,基本能用现有 `JointUserPage.createRealm` + `JointUserPage.gotoRealmAdmin` + 直接 `page.goto("/timeline/${realmId}")` 覆盖
- 步骤 13 的 "carol 看不到旧消息" 是新增断言点,要确认 inkson 实现了 history_access 的 client-side 过滤(否则 fail 不代表 spec 不对,而是 inkson 漏实现)— 跑测前**先确认或挂 TODO**

## 总耗时预估

单次跑约 60-90s(三个 browser context、4 阶段、20 步左右)。
