# Models — Morph Schema Migration

## 目标

把 `models/morph.md` §4.1 (`schema_refs[]` Evolution Policy) 与 `ck.profile.morph.schema_migration_transformations.v1` opt-in profile 当作 e2e 合约:验证 soland 对 `ck.morph.schema_migrate` 与 `ck.morph.update`-on-`schema_refs[]` 两条演进路径的判定 — additive fast-path 必须接受、breaking / transformation 必须 opt-in profile + capability,未声明 profile 时 reducer fail-closed,且支持的 transformation 类型与 capability point 必须严格落在 profile 声明的清单内。同时把 `morph-type-decision-table.json` 当作 reducer 选源真源,断言 soland describe / event 路径不混淆 §4 顺序 1–4 的来源。

不验证:`morph_type` create-lock(见 models 通用 invariants suite, G1.T6)、reducer 对 Morph lifecycle (`active/archived/redacted`) 的 transition 校验、Morph reducer 在跨 Realm capability `allowed_morph_types` 上的判定(归 authz/capability-chain)。本文件只聚焦 *schema EVOLUTION over time*。

## Spec 锚点

- `cokret-spec/spec/v1/zh/models/morph.md` §2 — Morph schema 字段表(`schema_refs[]` 是字段验证真源)
- `cokret-spec/spec/v1/zh/models/morph.md` §4.0 — 决策矩阵(Schema 演进 → §4.1 S2/S3 真源)
- `cokret-spec/spec/v1/zh/models/morph.md` §4.1 — `schema_refs[]` Evolution Policy
  - §4.1 S1 — per-event `requirements.schema[]` 版本绑定
  - §4.1 S2 — `ck.morph.update` schema_refs[] 变化必须走 schema-evolution gate;非 additive MUST reject
  - §4.1 S3 — `ck.morph.schema_migrate` 一等 event;`compatibility_class ∈ {additive, breaking, transformation}`;breaking/transformation 需 `ck.profile.morph.schema_migration_transformations.v1` opt-in
- `cokret-spec/spec/v1/zh/models/morph.md` §6 — Schema Evolution 通用约束
- Profile 定义:`cokret-spec/spec/v1/artifacts/profiles/conformance-profiles.json` → `ck.profile.morph.schema_migration_transformations.v1`(`required_event_kinds: [ck.morph.schema_migrate]`、`feature_discovery.required: [supported_compatibility_classes, transformation_rules_dialect, schema_migrate_capability_action]`)
- Type 决策表(canonical):`cokret-spec/spec/v1/artifacts/registry/morph-type-decision-table.json`(4 个 precedence 顺序、3 条 merge_rules、4 个 conflict_resolution case、4 个 conformance_must_test)
- Event kind:`cokret-spec/spec/v1/artifacts/registry/event-kind-registry.json` → `ck.morph.schema_migrate` (category=morph, reducer_input=true, status=active)
- Error code:`cokret-spec/spec/v1/artifacts/registry/error-code-registry.json`
  - `morph_schema_refs_evolution_unauthorized`(`ck.morph.update` 修改 schema_refs[] 缺 capability)
  - `morph_schema_refs_transformation_unsupported`(非 additive 走 `ck.morph.update` 或缺 profile)
  - `morph_schema_version_binding_missing`(event 未填 `requirements.schema[]`)
- 关联实现:soland Morph reducer / event submission 路径;yougen 对未知 Morph type 的 generic fallback render(spec §6)

## 拓扑

- 1 × soland (principal) — `${COTEST_SOLAND_BASE_URL}`,暴露 `/_cokret/describe`、`/_cokret/self/realms`、`/_cokret/self/realms/:id/events`
- 1 × coauth (auth) — 给 alice 颁 dev session;`ck.morph.schema.migrate` capability action 通过 dev token 默认 grant 或在 Realm policy 中显式声明
- 1 × cotest harness (Playwright `request` fixture) — 加载 `morph-type-decision-table.json` + `conformance-profiles.json` 中的 profile 块,把 capability 点清单直接作为 negative input source

不需要 dual-soland;不需要 browser context;不需要新增 mock。

## Actors

| 名字 | DID | 角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-morph-<uuid>.example` | Realm owner;发 `ck.morph.create` / `ck.morph.update` / `ck.morph.schema_migrate` event;Phase A/B/C/D 用她的 dev session | 测试开始前 |
| 无 (Phase E) | n/a | Phase E 是纯 artifact 解析 + describe 自检,不需要 actor | n/a |

## Pre-conditions

- soland live 监听 `${COTEST_SOLAND_BASE_URL}` 且 `GET /_cokret/describe` 返回 200 + JSON
- harness 能 ESM resolve `cokret-spec/spec/v1/artifacts/{registry,profiles}/*.json`(相对 `tests/models/*.spec.ts` 向上 4 级到 repo root)
- alice 通过 `POST /_soland/self/account/register` + `POST /_soland/gate/auth/dev-login` 拿到 bearer token
- alice 已创建一个 test Realm `R`,记录 `realmId`,作为 Morph 容器

## Steps

### Phase A — Unsupported transformation 类型 fail-closed

1. **harness** 加载 `ck.profile.morph.schema_migration_transformations.v1` 块,抽出 `feature_discovery.required` 列表(`supported_compatibility_classes`、`transformation_rules_dialect`、`schema_migrate_capability_action`)
2. **harness** 通过 `GET /_cokret/describe` 读取 soland 自称的 supported transformation set(如 describe 暴露了该 profile 的 feature discovery hint,例如 `describe.implemented_features.profile_features["ck.profile.morph.schema_migration_transformations.v1"].supported_compatibility_classes[]`)
3. **alice** 在 `R` 中先发一条 `ck.morph.create`,得到 `morphId`,该 Morph 的初始 `schema_refs = ["ck.schema.morph.customer_risk.v1"]`
4. **alice** 发一条 `ck.morph.schema_migrate`,`payload` 形如:
   ```json
   {
     "morph_id": "<morphId>",
     "from_schema_refs": ["ck.schema.morph.customer_risk.v1"],
     "to_schema_refs": ["ck.schema.morph.customer_risk.v2"],
     "compatibility_class": "transformation",
     "transformation_rules": [
       { "rule": "ck.transform.bogus.unsupported.v1", "field": "fields.status" }
     ]
   }
   ```
   即 `transformation_rules[*].rule` 引用了一个明显不在 profile `transformation_rules_dialect` 中的伪 rule id。
5. 断言:
   - HTTP 4xx (期望 400 / 422)
   - response body `error.code ∈ {failed_precondition, schema_violation, morph_schema_refs_transformation_unsupported, unsupported_transformation_rule}`
   - 若 Realm 未声明 profile → 不论 rule id 是否合法,reducer 都 MUST 用 `morph_schema_refs_transformation_unsupported` 拒绝(spec §4.1 S3)
   - response body **不含** 已 apply 的 Morph echo(reducer 必须在 registration 阶段 fail,不能进入 transformation 执行)

### Phase B — Compatible (additive) migration 接受 + 历史 event 兼容

6. **alice** 重置一个新 Morph `morphId_B` (同 `R`),`schema_refs = ["ck.schema.morph.customer_risk.v1"]`,写入若干 v1 字段
7. **alice** 发一条 `ck.morph.update`,在 `payload` 中把 `schema_refs` 改为 `["ck.schema.morph.customer_risk.v1", "ck.schema.morph.customer_risk.optional_ext.v1"]`(后者只添加 optional 字段 → additive)。该 event 的 `requirements.schema[]` 同时包含旧/新 schema(spec §4.1 S2 重叠期声明)
8. 断言:
   - HTTP 2xx,Morph 当前 `schema_refs[]` = new set
   - 后续 `GET /_cokret/self/realms/${realmId}/morphs/${morphId_B}` 投影成功,v1 时期写入的字段未被丢弃
   - audit log(`GET /_soland/self/audit/recent` 或等价)含一条 `schema_evolution` entry,记录 issuer + old/new schema_refs + authorization_ref
9. **alice** 再发一条 `ck.morph.schema_migrate`,`compatibility_class = "additive"`:
   - to_schema_refs 在 v2 的 optional 扩展位上再叠一层
   - 不需要 profile opt-in,reducer MUST 接受(spec §4.1 S3 additive 段)
10. 断言:HTTP 2xx;并且 spec §4.1 S1 — reader 重放历史 v1 event 时仍按 v1 schema 验证(harness 通过 `GET /_cokret/self/realms/${realmId}/events?morph_id=...` 拉历史,断言 event-level `requirements.schema[]` 与写入时绑定一致,未被静默改写)

### Phase C — Breaking / transformation migration 需 profile + capability

11. **alice** 在不声明 `ck.profile.morph.schema_migration_transformations.v1` 的 Realm `R` 中,尝试发 `ck.morph.schema_migrate` 带 `compatibility_class = "breaking"`(payload e.g. `to_schema_refs[]` 删除一个 required field)
12. 断言:HTTP 4xx,`error.code = morph_schema_refs_transformation_unsupported`,`error.reason` 引用 `ck.profile.morph.schema_migration_transformations.v1` 未声明
13. **alice** 在 Realm `R` 中发 `ck.realm.profile.update` 声明 opt-in 该 profile (含 capability action `ck.morph.schema.migrate` granted to alice)
14. **alice** 重发 step 11 的 breaking migrate
15. 断言:
   - HTTP 2xx
   - audit log 出现一条 `schema_migration_breaking` 类型记录,字段含 `issuer = alice.did`、`from_schema_refs[]`、`to_schema_refs[]`、`compatibility_class = "breaking"`、`capability_used = "ck.morph.schema.migrate"`、`profile_ref = "ck.profile.morph.schema_migration_transformations.v1"`(确切 audit kind 名以 soland 实现为准,test 用宽 regex `/schema_migration|morph_schema_migrate|breaking/` 匹配)
   - 再发 `compatibility_class = "transformation"` + 合法 `transformation_rules[]`(每条 rule id 在 profile `transformation_rules_dialect` 内)→ HTTP 2xx
16. 反向:撤销 capability(`ck.realm.policy.update` 删除 grant),再发 transformation → HTTP 4xx,`error.code = capability_denied`(spec §4.1 S3 capability 缺失分支)

### Phase D — Deterministic transform 向量(若有 fixture)

17. **harness** 尝试加载 `cokret-spec/spec/v1/artifacts/fixtures/ck.vector.morph.*.json` 形态的 transform fixture(若未来 spec 引入)
18. 若 fixture 存在:对每个 vector,driver alice 写入 `input` Morph 状态,发对应 `ck.morph.schema_migrate` event,然后 `GET` 该 Morph 当前投影
19. 断言:投影 bytes(`canonical_json` after sort)与 vector `expected_output` 字节相等;digest 也匹配(若 vector 暴露 `expected_digest`)
20. 当前 spec 仓库**无** `ck.vector.morph.*` fixture(本 scenario 写作时已 grep 确认),Phase D 整体 `test.fixme` 钉住 contract,等 spec 侧 publish 后再 live

### Phase E — Type registry alignment (LIVE)

21. **harness** 加载 `cokret-spec/spec/v1/artifacts/registry/morph-type-decision-table.json` → 收集 `precedence[*].source` 4 项与 `precedence[*].consumed_by[*]` decision name set(`reducer.field_validation`、`capability.allowed_morph_types_match`、`view.default_renderer_pick`、...)
22. **harness** 同时加载 `ck.profile.morph.schema_migration_transformations.v1` profile 块,断言以下结构性约束:
    - `required_event_kinds` 含 `ck.morph.schema_migrate`
    - `additional_requirements` 含 `capability_must`、`from_set_check_must`、`deterministic_transformation_must`
    - `feature_discovery.required` 列出 3 个 discovery key (含 `schema_migrate_capability_action`)
23. **harness** 通过 `GET /_cokret/describe` 读取 soland 自称支持的 Morph 行为(若 describe 暴露 `implemented_features.morph_decision_sources[]` 或等价 hint):每个 claim 都必须能映射到 precedence 表中的某个 `source`;若 describe 自称支持一个表外 source(典型:`facets` 作为 reducer 决策来源)→ fail
24. 当前 soland describe 未必暴露此 hint;若字段缺失,Phase E 的 describe 维度 `test.skip("describe 未暴露 morph_decision_sources hint — 无法验证 type registry alignment, only artifact load asserted")`
25. 不变量:`precedence.length >= 4`(spec §4 顺序 1-4),且任何一条 `precedence[*]` 的 `consumed_by[*]` 与 `MUST_NOT_consume_by[*]` 集合 disjoint(防 spec 自身 drift)

## Observable assertions (合并清单)

- Phase A:每个 unsupported transformation_rules POST → HTTP 4xx + `morph_schema_refs_transformation_unsupported` 或 `unsupported_transformation_rule`;无 partial echo
- Phase B:additive `ck.morph.update` schema_refs[] 接受;additive `ck.morph.schema_migrate` 不需 profile;v1 历史 event `requirements.schema[]` 未被 silently rewrite
- Phase C:breaking/transformation 在无 profile 时 reject;Realm 声明 profile + capability 后接受;audit 含 `schema_migration_breaking` marker;撤 capability 后 `capability_denied`
- Phase D (fixme):`ck.vector.morph.*` fixture 驱动的 transform 投影与 expected_output byte-equal(等 fixture 落地)
- Phase E (LIVE):`morph-type-decision-table.json` 与 `ck.profile.morph.schema_migration_transformations.v1` profile 块结构正确解析;`precedence[*].consumed_by` ∩ `MUST_NOT_consume_by` 为空;`required_event_kinds` 含 `ck.morph.schema_migrate`

## Edge cases / sub-tests

- **M7.1 schema_refs set-equal 校验**:Phase B/C 中,event payload `from_schema_refs[]` 与 Morph 当前 `schema_refs[]` 必须 set-equal;若 alice 故意把 `from_schema_refs` 写错(漏一个 id),reducer MUST `failed_precondition`(spec profile `additional_requirements.from_set_check_must`)
- **M7.2 requirements.schema[] 必填**:任何 reducer-input event 若未在 `requirements.schema[]` 中绑定生效 schema 版本 → `schema_violation` reason=`morph_schema_version_binding_missing`(spec §4.1 S1 末段);Phase B step 7 反例可加 sub-test
- **M7.3 `ck.morph.update` non-additive 走错路**:在 `ck.morph.update`(非 `schema_migrate`)payload 里写一个 breaking shape(删字段)→ reducer MUST 拒绝并提示客户端改走 `ck.morph.schema_migrate`(spec §4.1 S3 fast-path 收窄段);error.reason 含 `morph_schema_refs_transformation_unsupported`
- **M7.4 facet 作为 reducer 决策来源**:作为 conformance 反例(spec §4.0 表 + decision-table `MUST_NOT_consume_by`),把 `facets.assignable = true` 作为唯一权威发 `ck.morph.update`,但不带对应 capability → reducer MUST 不读 facets 做 authz 决策(本 sub-test 与 G1.T6 Core Object Invariants 有重叠,morph-schema-migration 只在 Phase E 的 artifact-side 钉住该约束,不重复写 live 反例)
- **M7.5 unknown profile id`feature_discovery.required` drift**:若 spec 后续给该 profile 加 discovery key,Phase E step 22 的硬编码 `required` 列表会变红 — 这是 *期望* 行为(测试就是 spec drift detector);此时更新 test 一并更新

## Implementation notes

- **artifact loader**:复用 G1.T4 (`tests/conformance/registry-drift.spec.ts`) 的 `import.meta.url` + `dirname` + `resolve` 模式;artifacts 落在 `<repo_root>/cokret-spec/spec/v1/artifacts/`,相对 `cotest/e2e/tests/models/*.spec.ts` 是 `../../../../cokret-spec/spec/v1/artifacts`。Playwright 配置 `"type": "module"`(见 `e2e/package.json`),原生支持 ESM `import.meta.url`
- **profile loader**:`conformance-profiles.json` 是单个大对象,profile-id → requirements 映射在 `profile_requirements.<profile_id>`,全局 v1 catalog 列表在 `implementation_profiles[]`;harness 解析后直接索引 `parsed.profile_requirements["ck.profile.morph.schema_migration_transformations.v1"]`,不要 deep-walk(profile id 是稳定 wire key,不存在 fallback)
- **describe key 名 fallback**:Phase A step 2 / Phase E step 23 — soland 暴露的 profile feature discovery 字段路径未敲定,harness 按顺序尝试:`describe.implemented_features.profile_features[<profile_id>]` → `describe.profile_features[<profile_id>]` → `describe.feature_discovery[<profile_id>]`,第一个非空对象即视为有效 hint;全部 missing 时该子断言 `test.skip()`
- **audit log scope**:Phase C 的 `schema_migration_breaking` 检查需要一个 audit query 端点;若 soland 仅暴露 per-event 检索而无 audit kind 过滤,harness 改为拉 `/_cokret/self/realms/${realmId}/events?kinds=ck.audit.*` 后 filter `audit_kind` field
- **error code 集合宽松匹配**:registry `error-code-registry.json` 已显式列出 `morph_schema_refs_evolution_unauthorized` / `morph_schema_refs_transformation_unsupported` / `morph_schema_version_binding_missing`;但 reducer 早期实现可能用通用 `schema_violation` / `failed_precondition` + reason 字段。Phase A/B/C 用 `{ code, reason }` 双轨匹配,任一命中即视为通过
- **fixme 范围**:Phase A / B / C / D 全部 `test.fixme`(Morph reducer 在 soland 当前是 partial,gap report §1.2/1.3 列为 schema 演进 implementation 缺口);Phase E 是纯 artifact + 可选 describe probe,LIVE
- **no new helper**:全部逻辑放在 spec 文件内,只依赖 `helpers/env.ts` 的 `solandBaseUrl()` 与 `helpers/users.ts` 的 `ensureRegistered` / `issueDevSession` / `uniqueUser`

## 总耗时预估

LIVE 部分:< 1s(artifact JSON.parse + 可能一次 GET describe + set diff)。
fixme 部分实现后:8-15s(Phase A 1 次 POST + Phase B 4-5 次 POST + Phase C 5-6 次 POST + audit query + Phase D vector loop 视 fixture 数量)。
