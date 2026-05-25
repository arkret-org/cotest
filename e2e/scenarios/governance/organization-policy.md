# 组织 directory + moderation policy 继承

## 目标

`Acme` Organization 拥有一个 organization moderation policy(`cx.organization.moderation_policy`);Acme 的 space `S_acme` 默认继承该 policy(deny_join、deny_write 规则);space-level policy 可以 override 但要走 governance approval。

## Spec 锚点

- `governance/content-moderation.md` §7 — Organization 级 moderation
- `identity/identity-did.md` §6 — Organization 是 Principal(DID 而非 Space)
- `models/governance-objects.md` §3 — Policy 对象

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| acme-org | Organization,持 `cx.policy.manage` 顶层 capability |
| alice | Organization member + space owner |
| bob | Acme member |
| mallory | 非 Acme 成员 |

## Steps

### Phase A — Setup organization

1. 测试 harness 注册 organization DID `did:web:acme.example`
2. acme-org 提交 `cx.organization.moderation_policy`,payload `{ targets: [{ kind: "actor", did: mallory.did, action: "deny_join" }], content_filters: [], appeal: { enabled: true } }`
3. 断言:`GET /api/v1/organizations/acme/policy` 返回该 policy

### Phase B — alice 在 Acme 下建 space

4. alice 持 Acme membership;alice createSpace `S_acme`,关联到 `acme-org.did`
5. soland reducer:`S_acme.organization_ref = acme-org.did`
6. 断言:space `S_acme` 上的 policy chain 含 organization 层(可通过 `GET /api/v1/spaces/<S>/effective-policy` 查)

### Phase C — mallory 被 organization 层 deny_join

7. mallory 尝试 join `S_acme`(通过 invite 或 knock)
8. reducer:capability OK,但 organization 层 policy 拒(deny_join targets 含 mallory.did)
9. 断言:mallory 收到 403 + reason `organization_policy_denied`

### Phase D — Space-level override

10. alice 觉得 mallory 特殊情况要放行;在 `S_acme` 层提交 `cx.realm.moderation_policy { allow_override: [{ target: mallory.did, action: "allow_join" }] }`
11. 但 spec 可能要求 override organization policy 必须有 `cx.organization.override_approval` 由 acme-org 签 → 验证这个 gating
12. (sub-test:无 approval)reducer 拒 alice 的 override;reason `requires_organization_approval`
13. (sub-test:有 approval)acme-org 签 approval → reducer 接受;mallory 现在能 join

### Phase E — Organization 改 policy fan-out 给所有 spaces

14. acme-org 更新 policy,新增 `{ kind: "domain", domain: "malicious.example", action: "quarantine_message" }`
15. 断言:Acme 旗下所有 spaces 自动继承该规则,无需逐个 space 改

### Phase F — Organization directory

16. mallory 在 `/directory` 选 `tab-organizations`,搜 "Acme"
17. 断言:看到 acme-org profile,member count、verified badge

## Edge cases

- **E30.1 cross-org space**:space 同时关联到两个 organization → policy 怎么 join?spec 须查;一般 most_restrictive 优先
- **E30.2 organization deactivate**:acme-org 被注销(罕见)→ spaces 的 policy 回到 server default
- **E30.3 appeal flow**:mallory 被 deny,通过 `appeal.endpoint` 提交 appeal flow → moderator 评审

## Implementation notes

- **soland 已落地**:`/api/v1/organizations` 提供本地 organization registry/policy surface;`cx.realm.create.object.owning_organizations[]` 自动建立 Realm→Organization 继承链;`/api/v1/spaces/{id}/effective-policy` 返回 organization layers、fanout space list、Space override。
- **join gate 已落地**:`cx.member.state{membership="join"}` 会读取 inherited organization policy,命中 `deny_join` target 时返回 `organization_policy_denied`。
- **override approval 已落地**:Space 级 `allow_join` override 若覆盖组织 `deny_join`,必须携带 `organization_approval`;否则返回 `requires_organization_approval`。
- **yougen directory 已落地**:Organization directory tab 会显示 verified badge、member count,并根据 linked Realm 数量提示 organization policy inheritance 状态。

## 总耗时预估

约 90s。
