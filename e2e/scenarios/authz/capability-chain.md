# Capability 授权链（事件面：grant 收窄 / revoke 级联）

## 目标

验证 capability 在事件面上的完整生命周期：grant 与 revoke 都是提交到 `/_arkret/self/events` 的事件
（`ak.capability.grant` / `ak.capability.revoke`），由 reducer 投影；以 `kind="grant"` 的
`issuer_authority_refs[]` 签发的 child grant 必须收窄、不得扩权/扩时；revoke 必须显式且沿 authority
chain 传播。同步 REST 授权面（`POST/DELETE /_arkret/self/authz/grants*`、
`GET /_soland/self/audit/events`）已从 spec 移除，本 scenario 不得复活它（SPEC-CR-020：零新增
operation）；仅存的同步读面是注册端点 `POST /_arkret/self/authz/check`
（`ak.self.authz.read.check.v1`，诊断/预检，非签名决定）与
`GET /_arkret/self/authz/effective-grants`（`ak.self.authz.grants.read.effective.v1`）。

## Spec 锚点

- `authz/capabilities.md` §3 — Grant 对象与事件铸造;§3.1a 首发 grant 的 issuer 自身权限上界(`grant_exceeds_issuer_authority`)
- `authz/capabilities.md` §10 — Authority chain；§10.1 收窄不变量（actions ⊆ issuer authority、resources 收窄、`effective_expires_at` ≤ issuer authority，违反 → `failed_precondition` reason=`authority_expiry_widening`（窗口）或 `schema_violation`（actions/resources 越界））；§10.3 revoke 因果传播（`grant_revoked_upstream`）
- `authz/capabilities.md` §12 — Revocation 必须显式事件,不是删除记录
- `authz/event-auth-state-resolution.md` §6 — authority chain revocation 传播
- openapi:`ak.self.authz.read.check.v1`(AuthzCheckOutcome 五值 `decision`)、`ak.self.authz.grants.read.effective.v1`(GrantList)

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | Realm owner,grant issuer |
| bob | grantee → child-grant issuer |
| carol | child-grant subject |

## Steps

### Phase A — §3 grant 生命周期

1. alice 建 Realm(API 面 `ak.realm.create`)
2. 断言:`POST /_arkret/self/authz/check {actor_id: bob, action: ak.message.create, resource: {kind: realm}}` → `decision = "hard_deny"`(grant 之前)
3. alice 提交 `ak.capability.grant` 事件(issuer=alice、subject=bob、actions=[`ak.message.create`]、`expires_at=+1h`,grant 对象带 detached-JWS proof)
4. 断言:同一 authz/check → `decision = "allow"`
5. 断言:`GET /_arkret/self/authz/effective-grants?subject=<bob>&realm_id=<R>`(realm owner 可查)返回的 GrantList 含该 grant id

### Phase B — §10 合法收窄再授权

6. alice → bob parent grant(`expires_at=+1h`)
7. bob 提交 child grant：`ak.capability.grant` 且 `issuer_authority_refs=[{kind:"grant",grant_id:<parent>}]`、同 action 集、`expires_at=+30min`（严格早于 issuer authority）
8. 断言：carol 的 authz/check → `allow`（沿 authority chain 生效）

### Phase C — 再授权不得扩权（§10.1 / §3.1a）

9. bob 只持有 `ak.message.create`；bob 试图以该 grant 为 issuer authority 给 carol 签发 `ak.moderation.decision`
10. 断言:事件提交被 reducer fail-closed 拒绝(4xx;code ∈ {`failed_precondition`,`schema_violation`,`grant_exceeds_issuer_authority`})
11. 断言:carol 对 `ak.moderation.decision` 的 authz/check 仍 `hard_deny`

### Phase D — 再授权不得扩时（§10.1）

12. parent grant `expires_at=+30min`;bob 试图给 carol 子 grant `expires_at=+2h`
13. 断言：拒绝（code ∈ {`failed_precondition`,`authority_expiry_widening`,`grant_exceeds_issuer_authority`}）
14. 断言:carol authz/check 仍 `hard_deny`

### Phase E — §12 显式 revoke + §10.3 级联

15. alice 提交 `ak.capability.revoke { grant_id: <parent> }`
16. 断言:bob 与 carol 的 authz/check 双双 `hard_deny`(child grant 在 revoke 的因果后继中失效)
17. bob 再以已 revoke 的 grant 为 issuer authority 发起新 grant
18. 断言:拒绝(code ∈ {`failed_precondition`,`grant_revoked_upstream`})——上游 revoke 的本地可见性优先于 child 的 causal 视图

## Edge cases(后续扩展,当前未覆盖)

- **expiry 自动失效**:grant 到期后无需显式 revoke 自动失效(需要时间推进 hook)
- **resource selector 收窄**：child resources 必须是 issuer authority 的 selector-narrowing 子集（`resource-selector-grammar.md`）
- **authority cycle / depth**：§10.2 cycle detection（`authority_cycle`）与 `max_authority_depth`（`authority_depth_exceeded`）
- **audit 事实面**:grant/revoke 作为事件本身即审计事实,经事件查询面(`/_arkret/self/events` query)或 `/_soland/` 产品审计面读取;旧 `GET /_soland/self/audit/events` 端点已移除

## Implementation notes

- 事件面 helper:`grantCapabilityEventApi` / `buildCapabilityGrantEnvelope`(负例 raw 提交)/ `revokeCapabilityApi`(`e2e/helpers/soland-api.ts`)
- soland 的 child grant 校验在 reducer（`apply_capability.rs`）：issuer 必须是 referenced grant 的 subject、realm 一致、actions/resources 不超过 issuer authority union、expiry 不得晚于对应 authority、ancestor 被 revoke → `grant_revoked_upstream`
- 高层写事件引用授权走信封 `refs[role="authorized_by"]` 直接指向不可变 grant（`ak:grant:` id），不得使用承载 Event id alias。

## 总耗时预估

约 30-45s(纯 API 面,无浏览器)。
