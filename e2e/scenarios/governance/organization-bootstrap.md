# 组织 principal bootstrap / delegation

## 目标

COT-ORG-05 回答:“**没有共享账号时,谁控制了组织 principal?**”

组织是一个 DID Principal,不是某个人的账号。签发 `ak.realm.organization` 关系声明必须由组织 DID controller 本身,或一个**显式 delegation**(governance service / Account Authority)代签;某个登录的 human admin **不会**自动成为组织 principal。

## Spec 锚点

- `identity/identity-did.md` §6 — Organization 是 DID Principal
- `governance/content-moderation.md` §7
- `event-payload.schema.json#/$defs/realm_organization_payload`(`authorization.issuer_role` ∈ {`organization`, `governance_service`, `account_authority`, `threshold_quorum`};后两者必须携带 `delegation_ref`)

## 拓扑

- 1 × coland + 1 × coauth

## Cases

### Case A — human admin 无 delegation 不能签发

1. human admin 登录(普通账号),无组织 delegation。
2. 尝试创建 / 签发组织的 `ak.realm.organization` authorization。
3. 断言:coauth 拒绝(或签出的声明被 coland 拒);组织 principal 不等于这个 human 账号。

### Case B — DID controller / governance service / Account Authority 通过 delegation 成功签发

4. coauth 为组织 DID 颁发 delegation,purpose 覆盖 `ak.realm.organization` + 目标 relationship/control_scopes。
5. 以 `issuer_role=governance_service`(或 `account_authority`)携带 `delegation_ref` 签发声明。
6. 断言:coauth 成功签发,coland 接受;`issuer_role=organization`(DID controller 直签)同样成功。

### Case C — expired / revoked delegation 不能继续签发,且不被 coland 接受

7. delegation 过期或被 revoke。
8. 断言:coauth 不再用它签发;即便强行构造携带该 delegation_ref 的声明,coland 也拒(`grant_revoked_upstream`)。

## 验收

测试能回答“没有共享账号时谁控制了组织 principal”:控制权来自组织 DID controller 或其活跃 delegation,而非任意登录的 human。

## blocking-on

- COA-ORG-02:组织 principal bootstrap(PCR / 控制状态)。
- COA-ORG-03:签发 `ak.realm.organization` authorization(delegation 解析 + issuer_role 耦合)。
- COA-ORG-04:session grant / 组织控制边界。
- SOL-ORG-03:coland 侧 delegation 解析 + 接受门禁。
- 上述落地前,e2e 以 `test.fixme` + `@blocking-on` 标注。`ak.realm.organization` 的 issuer-role/delegation 不变量已由 `tests/realm_organization_statement_negative.rs`(SDK verifier)静态守护。
