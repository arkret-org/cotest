# Capability 授权链(grant / revoke / delegate / constraints / audit)

## 目标

验证 capability 完整生命周期:alice 给 bob grant 写消息 capability,带 expiry 约束;bob 用该 capability 写消息;bob delegate 给 carol(sub-constraint);alice revoke bob 后,bob/carol 双双失效;所有变更进 audit log。

## Spec 锚点

- `authz/capabilities.md` §3 — Capability schema(grantor、grantee、actions、constraints)
- `authz/capabilities.md` §3.2 — Delegation
- `authz/capabilities.md` §3.3 — Revoke
- `authz/capabilities.md` §3.4 — Audit trail
- `authz/constraint-schema.md` — 约束 grammar(temporal、resource-selector)
- `authz/resource-selector-grammar.md` — 资源选择器(space-scoped、message-scoped)
- `authz/event-auth-state-resolution.md` §3 — Capability 是 allow 的唯一来源

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | space owner,初始 capability 持有者 |
| bob | grantee → delegator |
| carol | sub-delegatee |
| mallory | 第三方,不应有任何 capability |

## Steps

### Phase A — alice grant capability 给 bob

1. alice createSpace,seedMembers=[bob, carol, mallory]
2. alice 进 `/space/${spaceId}/admin` → "Capabilities" 区
3. 点 "Grant" → 选 grantee = bob.did,actions = `[cx.space.write_message]`,constraints = `{ expires_at: +1h }`
4. yougen 提交 `ck.capability.grant`,event 落到 `cx.cell:cx.component.capability.<grant_id>.v1`
5. 断言:`/space/${spaceId}/admin` Capabilities 列表显示 bob 的 grant + expires_at

### Phase B — bob 用 capability 写消息

6. bob 在 timeline 发消息 `M_b`
7. reducer 校验 bob 持有 `cx.space.write_message` capability + constraint(未过期)→ 接受
8. 断言:`M_b` 渲染

### Phase C — bob delegate 给 carol(sub-constraint)

9. bob 进 `/settings/capabilities` 或 space admin → "Delegate"
10. 输入 grantee = carol.did,actions = `[cx.space.write_message]`,sub-constraints = `{ expires_at: +30min }`(在 bob 自己 expiry 之前)
11. yougen 提交 `ck.capability.delegate`
12. 断言:capability tree 显示 alice → bob → carol 三层

### Phase D — carol 用 delegated capability

13. carol 发消息 `M_c`
14. reducer 沿 delegation chain 上溯:bob → alice → space owner;全 OK,carol 写入成功
15. 断言:`M_c` 渲染

### Phase E — alice revoke bob

16. alice 进 capabilities 列表,点 bob 旁的 "Revoke"
17. 提交 `ck.capability.revoke { grant_id: bob_grant_id }`
18. reducer cascade:revoke bob → carol 的 delegated capability 也自动失效(spec §3.3 cascade rule)
19. 断言:capability tree 中 bob/carol 都标 `revoked`
20. bob 再发消息 → reducer 拒,reason `capability_revoked`
21. carol 再发消息 → 同样拒(级联)

### Phase F — Audit trail

22. alice 查 `/space/${spaceId}/audit` 或调 `GET /_cokret/self/audit/events?space_id=<S>&kind=cx.capability.*`
23. 断言:看到一行 grant、一行 delegate、一行 revoke;每行含 grantor / grantee / timestamp / actions / constraints

## Edge cases

- **E20.1 over-grant**:bob 试 delegate carol 一个 bob 自己没有的 action(`cx.space.moderate`)→ reducer 拒,reason `capability_not_held`
- **E20.2 over-expire**:bob 试 delegate 给 carol 一个 expiry 比 bob 自己晚的 → 拒,reason `delegation_exceeds_grantor_expiry`
- **E20.3 mallory 无 capability 写消息**:reducer 拒,reason `missing_capability`
- **E20.4 expiry 自动失效**:bob 的 grant 到期后,无需 explicit revoke,后续消息自动被拒
- **E20.5 resource selector**:capability 限定到具体 flow_id;bob 给 flow A 写消息 OK,给 flow B 写拒(spec resource-selector-grammar)

## Implementation notes

- **soland 缺口**:`cx.capability.{grant,revoke,delegate}` event kinds;capability tree projection;cascade revoke;constraint evaluator(temporal + resource selector)
- **yougen 缺口**:`/settings/capabilities` 或 space admin 的 capability UI,delegation tree viewer

## 总耗时预估

约 60-90s。
