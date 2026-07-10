# Directory / teabay 已验证组织 badge

## 目标

COT-ORG-04 守护:directory / teabay 的 **verified organization badge** 与协议治理 badge 同源 —— 它来自 **active verified `ak.realm.organization` 关系**,而不是 Realm 单方面在 `owning_organizations[]` 里的声明,也不是本地 `_soland/self/organizations` 镜像。

## Spec 锚点

- `discovery/discovery-directory.md` §2 — directory 的 organization 轴
- `governance/content-moderation.md` §7 — 已验证组织关系
- `event-payload.schema.json#/$defs/realm_organization_payload`

## Cases

### Case A — declared-only 不显示 badge

1. alice 建 Realm,`owning_organizations: [acme-org.did]`,不写 `ak.realm.organization`。
2. directory `tab-organizations` 搜该组织。
3. 断言:行存在(若组织本身可被发现),但**不**显示 `organization-verified-badge`;API `verified_badge` 为 false / 缺省。

### Case B — active owner / directory_certifier 显示 badge

4. acme-org 签发 active `ak.realm.organization`:
   - `relationship=owner`,scope 含 `official_badge` → 显示 owner verified badge;
   - 或 `relationship=directory_certifier`,scope 含 `directory_listing` → 显示 directory-certified badge。
5. 断言:UI `organization-verified-badge` 可见;API `verified_badge=true`;inkson 与 teabay 读同一关系语义。

### Case C — revoked / expired / stale 后 badge 消失

6. 对 Case B 的声明 revoke(或令其过期 / 陈旧)。
7. 断言:`organization-verified-badge` 消失;API `verified_badge` 回到 false。

## 验收

inkson / teabay UI 或 API 读取**同一** verified relationship 语义;directory 不再把 declared-only 当 verified。

## blocking-on

- SOL-ORG-06:directory verified-badge 投影只从 active verified 关系派生。
- TBY-ORG-01/02/03:teabay 侧 verified relationship 读取与镜像。
- 上述落地前,e2e 以 `test.fixme` + `@blocking-on` 标注。
