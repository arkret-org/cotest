# Consent grant 决策机制

## 目标

验证 holder 对 peer 的联系/邀请同意决策机制的完整生命周期:peer 发起 contact 请求 → 被 gate (没 consent) → holder 在 settings 中查看 pending consent → holder 通过 `ck.consent.grant` Move 写入 or-set lattice → peer 重试成功 → holder revoke 后 peer 后续请求再次被 gate。Consent cell 与 capability / membership 完全解耦,仅决定「allow contact at all」这一层 gate。

不验证:capability 授权(account-device-auth、key-management 中的 device cap)、membership 状态机(messaging/triad-collaboration §3.8)、第三方邀请的 transport 层(后续 invites/third-party)、E2EE handshake 后的 MLS Add(crypto-media/device-lifecycle §9)。

## Spec 锚点

- `cokret-spec/spec/v1/zh/identity/consent-model.md` §2 — Consent cell 的 or-set lattice 结构、scope 粒度 (invite/message/call)、time window (not_before/valid_until)
- `cokret-spec/spec/v1/zh/identity/consent-model.md` §3 — `ck.consent.grant` / `ck.consent.revoke` Move,or-set add/remove 的收敛规则
- `cokret-spec/spec/v1/zh/identity/consent-model.md` §4 — Gate 语义:contact request 被 holder 当前 consent state 评估,无 grant 则进入 pending,有 grant 则放行;revoke 立即生效到后续请求(已建立的会话不强制断开,在 spec §4.3)

## 拓扑

- 1 × soland (principal server) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 共享同一个 coauth;alice / bob 的 session credential 都来自这个 coauth

(都是 cotest 现有 harness 直接提供的,不需要改 scripts/run-joint-e2e.ps1。)

## Actors

| 名字 | DID | 在 identity/consent-grant 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-consent-<uuid>.example` | holder,consent 决策者;持有 consent cell | 测试开始前 |
| bob | `did:webvh:z6mkfixture:bob-consent-<uuid>.example` | peer,发起 contact 请求;被 alice 的 consent gate 评估 | 测试开始前 |

## Pre-conditions

- 两个 DID 都通过 `POST /_soland/self/account/register` 注册过(与现有 `ensureRegistered` 行为一致)
- 两个 actor 都持有有效 dev session token(`POST /_soland/gate/auth/dev-login`)
- 两个 actor 的 browser context 都通过 `yougen.config.v1` localStorage 注入 server_url + account_did + device_id + session_credential
- alice 的 consent cell 初始为空 or-set(没有任何 `ck.consent.grant` 历史事件)

## Steps

### Phase A — Baseline 注册

1. `ensureRegistered` × 2 (alice、bob)
2. `issueDevSession` × 2,拿到两个 token
3. `openUserPage` × 2,得到 `alicePage` / `bobPage`
4. 断言:两侧的 yougen 已经加载、`yougen-config-loaded` testid 可见

### Phase B — bob 试图 contact alice (没 consent),被 gate

5. **bob** 通过 yougen 的 `/contacts/new` 流程发起对 `alice.did` 的 contact request
   - 填入 `contact-target-input` = `alice.did`,scope 选 `invite`,点 `send-contact-request-button`
6. 断言:bob 侧 `contact-request-status` 显示 `pending` (而不是 `accepted` / `failed`);spec §4 要求 holder 没 grant 时进入 pending,不返回 hard fail
7. 断言:soland 侧投影出 `ck.consent.pending` 事件(可观测的事件类型,具体名以 spec §3 为准),且 `holder = alice.did`、`peer = bob.did`、`scope = invite`

### Phase C — alice 查看 settings 中 pending consent

8. **alice** 进 `/settings/consent`(或当前 yougen 等价路径,先确认 testid)
   - 断言:`consent-settings-panel` 可见
   - 断言:`consent-pending-row` 中存在一行,文本含 `bob.did`、`scope=invite`
9. **alice** 点开 `consent-pending-row` 的 detail
   - 断言:`consent-pending-detail` 显示 peer DID、scope、`requested_at` 时间戳

### Phase D — alice grant consent (`ck.consent.grant` Move,or-set add)

10. **alice** 在 `consent-pending-detail` 上点 `grant-consent-button`
    - 表单填:scope = `invite`、`not_before` = now、`valid_until` = now + 30d
    - 提交触发 `ck.consent.grant` Move
11. 断言:`write-status` 含 `granted` 或 `consent-grant-success`
12. 断言:soland 侧 alice 的 consent cell 投影含一个 or-set member `{peer: bob.did, scope: invite, not_before: ..., valid_until: ...}`
13. 断言:bob 侧 `contact-request-status` 在 sync 之后(30s 内)从 `pending` 变为 `accepted`

### Phase E — bob 重试 contact,本次成功

14. **bob** 在 yougen 触发 contact 流程的下一步(发邀请/打开 DM,具体由 yougen 现有 UI 定),target = `alice.did`
15. 断言:本次请求 **不再** 进 pending,直接通过 gate,返回 `accepted` / 建立 contact link
16. 断言:alice 侧 `contact-inbox` 出现来自 `bob.did` 的 contact entry

### Phase F — alice revoke consent,bob 后续请求再次被 gate

17. **alice** 在 `/settings/consent` 的 `consent-granted-row` 上点 `revoke-consent-button`
    - 触发 `ck.consent.revoke` Move,or-set remove
18. 断言:`write-status` 含 `revoked`;alice 的 consent cell 投影中 bob 对应的 or-set member 被移除(或被加上 tombstone,具体看 spec §3 收敛规则)
19. **bob** 等 sync 后再次发起一个 **新的** contact 请求(同一 target、同一 scope)
20. 断言:本次请求再次进入 `pending`(spec §4.3:revoke 立即对 **后续** 请求生效)
21. 断言:已经建立的 contact link / DM 频道 **不被强制销毁**(spec §4.3 明确「revoke 不回溯」)

## Observable assertions (合并清单)

- 步骤 6:bob 侧 `contact-request-status` = `pending`
- 步骤 7:soland 侧 `ck.consent.pending`(holder=alice, peer=bob, scope=invite)
- 步骤 8:alice 的 `/settings/consent` 显示 pending row
- 步骤 11-12:`ck.consent.grant` Move 写入,or-set 添加成员
- 步骤 13:bob 30s 内看到状态变 `accepted`
- 步骤 15-16:重试请求绕过 gate,alice contact-inbox 出现 bob
- 步骤 18:`ck.consent.revoke` Move 写入,or-set 移除成员
- 步骤 20:revoke 后的新请求再次 `pending`
- 步骤 21:revoke 不强制销毁已建立链路

## Edge cases / sub-tests

- **E1.1 time window (not_before/valid_until) 失效**:alice grant 一个 `valid_until = now + 5s` 的 consent,bob 在 5s 内能 contact;5s 后再发新请求被 gate(consent 已自然过期,不需要 revoke);spec §2 time window 段
- **E1.2 revoke 后再次 grant**:在 Phase F 之后,alice 重新 grant 同一 peer 同一 scope,bob 再次能 contact;验证 or-set add-after-remove 在 LWW / add-wins 规则下的收敛(具体规则看 spec §3)
- **E1.3 scope 粒度 (invite/message/call) 隔离**:alice 只 grant `scope=message`,bob 试图发起 `scope=call` 的请求应该被 gate(`pending`),而 `scope=message` 请求放行;spec §2 scope 段
- **E1.4 pairwise DID 上的 consent (privacy 增强)**:alice 对 bob 的 pairwise DID(而非 root DID)grant consent,bob 用 pairwise DID 走 contact 流程能通过,用其他 pairwise / root DID 则被 gate;验证 consent cell 的 key 是 (holder, peer) 元组而非仅 holder;spec §4 pairwise 段

后三条建议拆成独立的小 spec(`identity/consent-grant.2`、`identity/consent-grant.3`、`identity/consent-grant.4`),保持主 scenario 紧凑。

## Implementation notes

- soland 侧的 `ck.consent.*` reducer 截至当前 **未实现**,因此本 scenario 的所有 test 都先用 `test.fixme` 挂起,等 reducer + projection landing 后再去掉 `.fixme`
- yougen 侧 `/settings/consent` 路由、`consent-settings-panel` / `consent-pending-row` / `grant-consent-button` / `revoke-consent-button` 等 testid 也未实现,跑测前要先确认或者补 UI
- contact request 的发起入口当前可能是 `/contacts/new`,也可能是 DM 邀请按钮里的子流程;具体 testid 以 yougen 现有 UI 为准,先挂 TODO
- `ck.consent.grant` / `ck.consent.revoke` 的 Move payload 字段(scope、not_before、valid_until、peer)以 spec §3 schema 为准,实现时直接对齐 schema,不要在 e2e 这边自创字段
- E1.1 的 time-window 测试如果设 5s 会让套件总耗时拉长,生产代码 land 后可以考虑用 mock time / time-travel helper(若 cotest harness 引入)替换真实 sleep

## 总耗时预估

单次跑约 30-45s(两个 browser context、6 个 phase、20 步左右,无 E2EE handshake)。E1.1 time-window 子测试会再加 ~10s。
