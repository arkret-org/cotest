# Realm 之间的有向图链接 (governed_by / discoverable_from / inherits_policy_from / mirrors / confidential_extension_of)

## 目标

验证 Realm 之间的显式 link graph 行为：alice 创建治理 Realm G 与团队 Realm T，T 通过 `ck.realm.link {link_kind: "governed_by", target: G.id}` 声明被 G 治理；G 在自身 `ck.realm.inheritance_policy` 中允许 T 继承一组收窄型 moderation policy；当 bob 在 T 中违规时，soland 在 T 的 effective policy projection 中 include 来自 G 的 inherited rule 并执行 moderation；alice 通过把 link `status` 置为 `rejected` 解除继承，T 的 policy 立即恢复独立形态（不再 inherit）。

不验证：Space hierarchy 跨 Realm 导航（见 spaces/hierarchy）、cross-realm membership 迁移（见 federation/realm-migration）、capability bundle 全量派生（spec §6 之外的扩展 profile）。

## Spec 锚点

- `arkret-spec/spec/v1/zh/models/realm-links.md` §2 — 设计原则（有向图、无隐式级联、narrow-only 继承）
- `arkret-spec/spec/v1/zh/models/realm-links.md` §3 — 标准 link kind 表（`governed_by` / `inherits_policy_from` / `confidential_extension_of` / `discoverable_from` 等）
- `arkret-spec/spec/v1/zh/models/realm-links.md` §4 — Link 状态机（`active` / `rejected` / `tombstoned`，派生 `confirmed` / `unconfirmed_link`）
- `arkret-spec/spec/v1/zh/models/realm-links.md` §5 — 禁止隐式级联清单（membership / capability / history / E2EE key / policy / notification …）
- `arkret-spec/spec/v1/zh/models/realm-links.md` §6 — 显式继承（`ck.realm.inheritance_policy` opt-in，narrow-only，本地 deny 覆盖，`max_depth=1`）

## 拓扑

- 1 × soland (principal server) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 共享同一个 coauth；alice / bob 的 session credential 都来自这个 coauth

(都是 cotest 现有 harness 直接提供的，不需要改 scripts/run-joint-e2e.ps1。)

## Actors

| 名字 | DID | 在 models/realm-links 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s1-<uuid>.example` | org admin；创建 governance Realm G 与 team Realm T，签 `ck.realm.link` Move | 测试开始前 |
| bob | `did:webvh:z6mkfixture:bob-s1-<uuid>.example` | team member；在 T 中发违规消息，被 G 的 inherited policy 处理 | 测试开始前 |

## Pre-conditions

- 两个 DID 都通过 `POST /_soland/self/account/register` 注册过（与现有 `ensureRegistered` 行为一致）
- 两个 actor 都持有有效 dev session token (`POST /_soland/gate/auth/dev-login`)
- 两个 actor 的 browser context 都通过 `inkson.config.v1` localStorage 注入 server_url + account_did + device_id + session_credential

## Steps

### Phase A — 创建 governance Realm G + moderation policy

1. **alice** 通过 `/setup` 创建 governance Realm `G`：
   - title = `"models/realm-links Gov Realm ${stamp}"`
   - realm_kind = `governance`（profile 标签；在没有专用 UI 时由测试直接调 soland API 创建）
2. **alice** 在 G 中写一条 moderation policy（`ck.policy.moderation`），含 `banned_keywords = ["forbidden-word-${stamp}"]`，并在同一 Realm 内发 `ck.realm.inheritance_policy` 允许下游 `governed_by` 子 Realm 继承该 moderation rule（narrow-only）。
3. 断言：`realm-overview-panel` 显示 `realmId` 形如 `ak:realm:...`，记录 `govRealmId`；G 的 effective policy 中含 `banned_keywords` 且 `inheritable = true`。

### Phase B — 创建 team Realm T + 声明 governed_by link

4. **alice** 通过 `/setup` 创建 team Realm `T`：
   - title = `"models/realm-links Team Realm ${stamp}"`
   - seed_members = `[bob.did]`
5. **alice** 在 T 中发送 `ck.realm.link` Move：
   ```json
   {
     "kind": "ak.realm.link",
     "payload": {
       "target_realm_id": "<govRealmId>",
       "link_kind": "governed_by",
       "status": "active",
       "label": "Gov realm ${stamp}"
     }
   }
   ```
6. **alice** 在 T 中显式 opt-in：发 `ck.realm.inheritance_policy` 声明从 `govRealmId` 继承 `moderation.banned_keywords`（必须本地声明；只继承不会自动发生 — spec §6.1）。
7. 断言：`realm-link-list` 显示一条 outbound `governed_by → govRealmId`，`edge_status = unconfirmed_link`（G 没有 reciprocal event，但 `governed_by` profile 不要求双方确认 → 测试侧根据 profile 容忍 `confirmed` 或 `active` 任一）；记录 `teamRealmId`。

### Phase C — T 的 effective policy projection include G 的 inherited rule

8. 调 `GET /_arkret/self/realms/${teamRealmId}/policy/effective`：响应中 `moderation.banned_keywords` 包含来自 G 的 `forbidden-word-${stamp}`；`source` 字段标注 `derived_from: govRealmId`，`max_depth: 1`。
9. 断言：T 本地直接策略（不含 inherited）中**不**含该 keyword（验证 inherited 是合并出来的，不是写到 T 本地的副本）。

### Phase D — bob 在 T 发违规消息

10. **bob** 加载 inkson，进入 T 的默认 Space（seed 后自动加入），打开 timeline。
11. **bob** 发消息 `MV = "this contains forbidden-word-${stamp} test"`。
12. 断言：`write-status` 含 `moderation_hold` 或 `rejected`；timeline 上 `MV` 显示为 `policy-hold-marker`（而非正常 `timeline-event`）。
13. 断言：moderation decision 的 `applied_rule.source_realm = govRealmId`（来自 inherited，而非 T 本地）。

### Phase E — soland 检查 effective policy 并执行 moderation

14. 调 `GET /_arkret/self/realms/${teamRealmId}/moderation/decisions?message=MV`：返回 1 条 decision，`rule_id` 指向 G 的 banned_keywords rule；`derived_via_link = governed_by`。
15. 断言：bob 的 `/notifications` 收到一条 `moderation_held` 通知（in-app）；alice（T owner）的 `/notifications` 也收到一条 `moderation_action_required`。

### Phase F — alice reject the link，T 的 policy 恢复独立

16. **alice** 把 step 5 的 link 状态置为 `rejected`：发送一条新的 `ck.realm.link` Move（同 `target_realm_id` + `link_kind`，`status = "rejected"`）。spec §4 — `status` 是 link 的最终态字段，新事件覆盖旧 active link。
17. 调 `GET /_arkret/self/realms/${teamRealmId}/policy/effective`：`moderation.banned_keywords` **不再** 含 `forbidden-word-${stamp}`；`derived_from` source list 为空。
18. **bob** 重发同样的 `MV` 文本：`write-status` 含 `persisted`；timeline 出现正常 `timeline-event`。
19. 断言：`realm-link-list` 中 step 5 的 link 显示 `edge_status = rejected`；T 的 inheritance_policy（step 6）虽仍 active，但 link 既然 rejected，derived policy 不再触发（spec §6.3 — 本地 deny / revoke / link reject 覆盖 inherited allow）。

## Observable assertions (合并清单)

- 步骤 3：`govRealmId` 形如 `ak:realm:...`，G 的 inheritable policy 可被下游引用
- 步骤 7：T 的 outbound link 列表含一条 `governed_by → govRealmId`
- 步骤 8-9：T 的 effective policy include G 的 keyword；T 本地 policy 不含（验证是合并产物）
- 步骤 12-13：bob 的违规消息被 inherited rule 拦截，decision 标注 source = G
- 步骤 14-15：moderation API + notification 双侧路径一致
- 步骤 17：link reject 后 inherited keyword 立即从 effective policy 消失
- 步骤 18：bob 重发同样消息成功 persist

## Edge cases / sub-tests

- **E6.1 循环 link**：alice 尝试构造 A → B → C → A 的 `governed_by` 环（A 是 G、B 是 T，再发一条从 G 指回 T 的 `governed_by`）— soland MUST 拒绝构成环的第三条 Move（cycle detection；返回 `link_cycle_detected` 错误）。spec §5 不允许隐式级联，§6.4 `max_depth = 1`，但环本身在 link graph 层面就该被拒（projection 不能容忍环）。
- **E6.2 多个 governed_by target，narrow-only 合并**：T 同时 `governed_by` G1 与 G2。G1 banned_keywords = `["w1", "w2"]`，G2 banned_keywords = `["w2", "w3"]`。spec §6.2 — derived grant 不得宽于 source grant；多 source 时，policy 合并取**交集**（narrow-only），最终 effective banned_keywords = `["w2"]`。注意：moderation 是 deny-style，"narrow" 在 deny 语义上是只 deny 双方都 deny 的；profile 解释由 soland 决定，测试侧只断言「实际生效集合 ⊆ 任一 source」即可。
- **E6.3 link graph 遍历时跨 realm 权能验证**：alice 在 G 持有 `realm.admin` capability。link 建立后，alice 调 `POST /_arkret/self/realms/${teamRealmId}/admin/*` —— soland MUST **拒绝**（spec §5：capability grant 不因 link 自动级联，§3 表中 `governed_by` 的「是否允许授权派生」是「MAY，但必须由本 Realm policy 显式声明」，本测试中 T 没声明派生 admin capability，所以 alice 在 T 不应有 admin 权）。断言：HTTP 403 + `reason = "capability_not_propagated_via_link"`。

后两条建议拆成独立的小 spec（`models/realm-links.2`、`models/realm-links.3`），保持主 scenario 紧凑。

## Implementation notes

- inkson 当前没有 `ck.realm.link` 专用 UI；Phase B 的 step 5/6、Phase F 的 step 16 在 inkson 落地前需要直接调 soland 的 `POST /_arkret/self/realms/${realmId}/events`（或对应 Move endpoint）写 Move。这是已知 gap，主流程留 fixme。
- `realm-link-list`、`realm-overview-panel`、`policy-hold-marker` 是计划中的 testid；inkson 实现时统一加。
- effective policy projection (`/_arkret/self/realms/:id/policy/effective`) 也是 spec §6 的 derived 端点；soland 当前是否已经实现 link-aware 合并需要先确认 — Phase C 与 Phase E 在 soland 项目逻辑落地前会全员 fixme。
- 不需要新 helper：`ensureRegistered` / `issueDevSession` / `openUserPage` 已覆盖 actor 准备；`request` (Playwright APIRequestContext) 直接打 soland 处理 Move 与 effective policy 查询。
- E6.1 cycle detection 是 soland 端拒绝路径，断言 HTTP 4xx + `error_code = "link_cycle_detected"`；不需要 browser context。
- E6.3 是纯 API 检查，不需要 browser context。

## 总耗时预估

单次跑约 30-45s（两个 browser context + 多条 API 直调；不含 fixme 的子用例）。
