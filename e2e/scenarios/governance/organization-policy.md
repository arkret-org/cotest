# 组织治理：已验证关系与显式 target-scoped moderation deny

## 目标

cotest 是“**声明的 owning organization != 已验证的组织治理关系**”的回归闸门。

协议治理语义的唯一真相源是 **`ak.realm.organization` 关系声明(`RealmOrganizationPayload`)**:

- `realm.create.object.owning_organization_ids[]` 只是 Realm 单方面**声明**的归属,**不**授予任何 authority、official badge 或 governance policy。
- organization 侧签发、active 且通过验证的 `ak.realm.organization` 只建立已验证关系；它本身不传播 policy 或 capability。
- Organization moderation 是独立 `ak.organization.moderation_policy` deny 层，document scope 必须显式覆盖目标 Realm／service，且目标 Realm 的 active relationship 必须背书该适用性。
- `revoked`、过期、not-before 未到或 scope 不覆盖的关系不生效；但失效语义不是删除一条继承链，因为 current-v1 没有 Realm automatic inheritance。

cotest **不再**用 `_coland/self/organizations`(本地部署面,非标准协议面)判断协议治理语义;它至多是 directory/UI 的产品面镜像。

## Spec 锚点

- `governance/content-moderation.md` §7 — Organization 级 moderation 与继承
- `identity/identity-did.md` §6 — Organization 是 DID Principal(不是 Space)
- `models/governance-objects.md` §3 — Policy 对象
- `event-payload.schema.json#/$defs/realm_organization_payload` — 关系声明 wire shape
- SDK:`arkret_policy::verify_realm_organization_statement` — 组织侧验证不变量

## 拓扑

- 1 × coland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| acme-org | Organization Principal(DID),通过 `ak.realm.organization` 签发关系声明 |
| alice | Realm owner / 写入 organization 声明到 Realm history 的人(需持 `ak.realm.admin`) |
| mallory | organization moderation policy 的 deny_join 目标 |
| sponsor-org | 仅与 Realm 建立 `sponsor` 关系的组织 |

## Cases(协议语义)

### Case A — 仅 `owning_organization_ids` 声明，不产生已验证关系或 deny 层

1. alice 创建 Realm,`owning_organization_ids: [acme-org.organization_id]`,但**不**写入任何 `ak.realm.organization` 声明。
2. 断言 organization relationship list 只把该 ID 放在 unverified hints；official badge **未**点亮，organization
   moderation admission 也不应用 acme-org 的 rule。
3. 含义：单方声明归属不等于已验证治理关系，更不能成为 policy carrier。

### Case B — active verified 声明 + 显式 target-scoped policy 才形成额外 deny 层

4. acme-org 签发 active `ak.realm.organization`,`relationship=owner`、`status=active`、
   `control_scopes` 含 `moderation_policy`(及/或 `official_badge`),proof 合法、在有效期窗口内。
5. alice(持 `ak.realm.admin`)把该声明写入 Realm history。
6. acme-org 另行签发 `ak.organization.moderation_policy`，其 closed document scope 显式覆盖该 Realm；断言 mallory
   命中 `deny_join`，且当关系 scope 含 `official_badge` 时 badge 点亮。
7. **scope 不覆盖**变体：关系不含 `moderation_policy`，或 organization policy document 没有显式覆盖目标 Realm →
   不应用 deny；关系不含 `official_badge` → badge 不点亮。

### Case C — revoke 后关系与依赖该关系的 deny 适用性失效

8. acme-org 签发 `status=revoked` 的 `ak.realm.organization`(携带 `revokes_statement_id` 指向 Case B 的声明)。
9. 断言 organization relationship 不再是 verified active；依赖该关系适用性的 organization deny 不再命中，official badge 熄灭。
10. 过期 / not-before 未到的声明同样不生效(等价于 revoke 后的最终态)。

### Case D — sponsor 关系不得当 owner / governance authority

11. sponsor-org 仅签发 `relationship=sponsor` 的 active 声明。
12. 断言 sponsor-org 不成为 Realm authority；它的 policy 不因 relationship 自动传播，official badge 不因 sponsor 关系点亮。

## Verified organization badge(COT-ORG-04,directory / flagon)

cotest 还守护 directory / flagon 的 verified badge 与上面**同一**已验证关系语义:

- **declared-only**:Realm 只在 `owning_organization_ids` 声明 acme-org,无 active 声明 → directory **不**显示 verified organization badge。
- **active owner / directory_certifier**:存在 active `ak.realm.organization`(`relationship` ∈ {`owner`, `directory_certifier`} 且 scope 覆盖 `directory_listing` / `official_badge`)→ 显示对应 badge。
- **revoked / expired / stale**:关系被 revoke / 过期 / 陈旧后 → badge 消失。
- 验收:inkson / flagon UI 与 API 读取的是**同一** verified relationship 语义,而非各自的本地镜像。

## coauth organization bootstrap / delegation(COT-ORG-05)

回答“没有共享账号时谁控制了组织 principal”:

- human admin 登录但**无** organization delegation 时,创建 `ak.realm.organization` 声明**失败**(组织 principal 不是某个人的账号)。
- DID controller / governance service / Account Authority 通过 delegation 成功签发 organization authorization。
- expired / revoked delegation **不能**继续签发,且即便签出也**不**被 coland 接受。

## Implementation notes / blocking-on

- 旧实现把 `owning_organization_ids[]` 的单方声明或 organization relationship 当自动 policy merge 链；这是已删除行为。
- 新的协议语义依赖 coland 侧:
  - SOL-ORG-02:`ak.realm.organization` reducer + 验证(proof / delegation / 窗口 / scope / revoke)。
  - SOL-ORG-03:organization delegation 解析(供 governance_service / account_authority issuer 使用)。
  - SOL-ORG-05：admission 只在 active verified 关系与显式 target-scoped organization policy 同时成立时应用额外 deny；
    不恢复已删除的 effective-policy operation、inheritance mode 或 merge DTO。
  - SOL-ORG-06 / TBY-ORG-*:directory verified badge 读同一关系语义。
  - COA-ORG-02/03/04:coauth organization bootstrap / delegation 签发面。
- 在上述 coland / coauth / flagon 端点落地前,对应 e2e 以 `test.fixme` + `@blocking-on` 标注(见 `e2e/tests/governance/organization-policy.spec.ts`)。scenario 文档(本文件)与 `ak.realm.organization` 的 payload/向量回归(`tests/fixtures/event-kind-payload-coverage-fixture.json`、`tests/fixtures/realm_organization_statement_negative_vectors.json`、`tests/realm_organization_statement_negative.rs`)已经实做并由 SDK validator 消费。

## 总耗时预估

约 120s(全部 case 落地后)。
