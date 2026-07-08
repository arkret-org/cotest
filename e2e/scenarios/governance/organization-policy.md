# 组织治理:已验证关系 vs 声明 + moderation policy 继承

## 目标

cotest 是“**声明的 owning organization != 已验证的组织治理关系**”的回归闸门。

协议治理语义的唯一真相源是 **`ck.realm.organization` 关系声明(`RealmOrganizationPayload`)**:

- `realm.create.object.owning_organizations[]` 只是 Realm 单方面**声明**的归属,**不**授予任何继承、official badge 或 governance policy。
- 只有 organization 侧签发的、**active** 且通过验证(proof / delegation / 有效期窗口 / scope 覆盖)的 `ck.realm.organization` 关系声明,才建立可继承的治理关系。
- `relationship` ∈ {`owner`, `governance`, `sponsor`, `directory_certifier`};只有 `owner` / `governance` 关系并且 `control_scopes` 覆盖 `moderation_policy` 时,才继承 organization moderation policy。`sponsor` 是赞助/背书关系,**不**承载 owner / governance 控制。
- `revoked` 状态(或过期 / not-before 未到 / scope 不覆盖)的声明**立即失效**,继承关系随之消失。

cotest **不再**用 `_soland/self/organizations`(本地部署面,非标准协议面)判断协议治理语义;它至多是 directory/UI 的产品面镜像。

## Spec 锚点

- `governance/content-moderation.md` §7 — Organization 级 moderation 与继承
- `identity/identity-did.md` §6 — Organization 是 DID Principal(不是 Space)
- `models/governance-objects.md` §3 — Policy 对象
- `event-payload.schema.json#/$defs/realm_organization_payload` — 关系声明 wire shape
- SDK:`cokret_core::models::verify_realm_organization_statement` — 组织侧验证不变量

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| acme-org | Organization Principal(DID),通过 `ck.realm.organization` 签发关系声明 |
| alice | Realm owner / 写入 organization 声明到 Realm history 的人(需持 `ck.realm.admin`) |
| mallory | organization moderation policy 的 deny_join 目标 |
| sponsor-org | 仅与 Realm 建立 `sponsor` 关系的组织 |

## Cases(协议语义)

### Case A — 仅 `owning_organizations` 声明,不继承

1. alice 创建 Realm,`owning_organizations: [acme-org.did]`,但**不**写入任何 `ck.realm.organization` 声明。
2. 断言:`GET .../effective-policy` 不含 acme-org 的 organization policy 层;
   `inheritance_mode == none`;official badge **未**点亮。
3. 含义:单方声明归属不等于已验证治理关系。soland 若回退到“`owning_organizations` 直接继承”旧行为,本 case 应当变红。

### Case B — active verified 声明 + scope 覆盖才继承

4. acme-org 签发 active `ck.realm.organization`,`relationship=owner`、`status=active`、
   `control_scopes` 含 `moderation_policy`(及/或 `official_badge`),proof 合法、在有效期窗口内。
5. alice(持 `ck.realm.admin`)把该声明写入 Realm history。
6. 断言:`effective-policy` 出现 acme-org organization policy 层;mallory 命中 `deny_join`;
   official badge 点亮(当 scope 含 `official_badge`)。
7. **scope 不覆盖**变体:声明 `control_scopes` 仅含 `realm_admin`(不含 `moderation_policy`)→ 不继承 moderation policy;仅含 `realm_admin`(不含 `official_badge`)→ badge 不点亮。

### Case C — revoke 后继承立即失效

8. acme-org 签发 `status=revoked` 的 `ck.realm.organization`(携带 `revokes_statement_id` 指向 Case B 的声明)。
9. 断言:`effective-policy` 不再含 acme-org 层;mallory 的 join 不再被 organization policy 拒;official badge 熄灭。
10. 过期 / not-before 未到的声明同样不生效(等价于 revoke 后的最终态)。

### Case D — sponsor 关系不得当 owner / governance 继承

11. sponsor-org 仅签发 `relationship=sponsor` 的 active 声明。
12. 断言:`effective-policy` 不把 sponsor-org 当作 owner / governance policy 来源;
    sponsor 的任何 moderation 规则**不**被继承;official badge 不因 sponsor 关系点亮。

## Verified organization badge(COT-ORG-04,directory / teabay)

cotest 还守护 directory / teabay 的 verified badge 与上面**同一**已验证关系语义:

- **declared-only**:Realm 只在 `owning_organizations` 声明 acme-org,无 active 声明 → directory **不**显示 verified organization badge。
- **active owner / directory_certifier**:存在 active `ck.realm.organization`(`relationship` ∈ {`owner`, `directory_certifier`} 且 scope 覆盖 `directory_listing` / `official_badge`)→ 显示对应 badge。
- **revoked / expired / stale**:关系被 revoke / 过期 / 陈旧后 → badge 消失。
- 验收:inkson / teabay UI 与 API 读取的是**同一** verified relationship 语义,而非各自的本地镜像。

## coauth organization bootstrap / delegation(COT-ORG-05)

回答“没有共享账号时谁控制了组织 principal”:

- human admin 登录但**无** organization delegation 时,创建 `ck.realm.organization` 声明**失败**(组织 principal 不是某个人的账号)。
- DID controller / governance service / Account Authority 通过 delegation 成功签发 organization authorization。
- expired / revoked delegation **不能**继续签发,且即便签出也**不**被 soland 接受。

## Implementation notes / blocking-on

- 旧实现把 `owning_organizations[]` 直接当继承链、把 `_soland/self/organizations` 当治理真相源;**这是被本 scenario 推翻的行为**。
- 新的协议语义依赖 soland 侧:
  - SOL-ORG-02:`ck.realm.organization` reducer + 验证(proof / delegation / 窗口 / scope / revoke)。
  - SOL-ORG-03:organization delegation 解析(供 governance_service / account_authority issuer 使用)。
  - SOL-ORG-05:`effective-policy` 仅从 **active verified** 关系派生 organization 层,并暴露 official badge / inheritance_mode。
  - SOL-ORG-06 / TBY-ORG-*:directory verified badge 读同一关系语义。
  - COA-ORG-02/03/04:coauth organization bootstrap / delegation 签发面。
- 在上述 soland / coauth / teabay 端点落地前,对应 e2e 以 `test.fixme` + `@blocking-on` 标注(见 `e2e/tests/governance/organization-policy.spec.ts`)。scenario 文档(本文件)与 `ck.realm.organization` 的 payload/向量回归(`tests/fixtures/event_kind_payload_coverage_fixture.json`、`tests/fixtures/realm_organization_statement_negative_vectors.json`、`tests/realm_organization_statement_negative.rs`)已经实做并由 SDK validator 消费。

## 总耗时预估

约 120s(全部 case 落地后)。
