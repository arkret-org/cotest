# Conformance — Registry Drift / Removed IDs

## 目标

把 `cokret-spec/spec/v1/artifacts/migration/*.json` 中的 removed/deprecated 真源与 `artifacts/registry/operation-registry.json` 当作 e2e 级别的 schema-drift detector,对 soland 实际暴露的 wire surface (`/_cokret/describe`、事件写入、operation 调用) 做反向扫描:确保移除的 event kind / operation id 在写入路径上 hard-reject,deprecated profile 在 describe 中不被声明,且 describe 自称的 operation 在 `operation-registry.json` 中全部有 canonical 条目。

不验证:具体 profile 内部 `requirements_role` 的 MUST/SHOULD 行为 (见 conformance/profile-gates.md);也不验证 `/server/describe` 的 envelope shape / `claimed_profiles` 分区 (见 sync/service-surface-contract.md)。本文件只关心 *registry vs. wire* 的 drift。

## Spec 锚点

- `cokret-spec/spec/v1/zh/conformance/schema-registry.md` §1 (真源声明)、§3 (event type 设计约束 — `ck.` 前缀 + critical extension fail-closed)、§5 (extension 命名)、§6 (演进约束 — schema_violation / 未知 critical fail-closed)
- `cokret-spec/spec/v1/artifacts/migration/removed-event-kinds.json` — 32 个被移除的 `ck.*` event.kind,`hard_reject` rejection level
- `cokret-spec/spec/v1/artifacts/migration/removed-operation-ids.json` — 11 个被移除的 operation id (HTTP / gRPC / MQ binding)
- `cokret-spec/spec/v1/artifacts/migration/deprecated-profile-ids.json` — 被废弃的 profile id
- `cokret-spec/spec/v1/artifacts/registry/forbidden-model-terms.json` — prose / identifier 级别的禁用术语
- `cokret-spec/spec/v1/artifacts/registry/operation-registry.json` — canonical operation 注册表 (82 个 operation_id × 14 个 surface_groups),HTTP / gRPC / MQ 绑定的唯一真源
- 关联 OpenAPI 视图: `cokret-spec/spec/v1/artifacts/openapi/cokret-service-api.openapi.yaml` (按 `registry_rules` 中 "MUST NOT introduce/rename/remove operation_id" 的约束,是 operation-registry 的派生 view,不是第二个 namespace)
- 关联实现: soland `/_cokret/describe` 处的 `implemented_features` / `supported_operations` / `claimed_profiles` 字段 (确切 key 名 see Implementation notes)

## 拓扑

- 1 × soland (principal) — `${COTEST_SOLAND_BASE_URL}`,暴露 `/_cokret/describe`、`/_cokret/self/events/*`、`/_cokret/self/operations/*` (或等价 operation binding)
- 1 × coauth (auth) — 仅用来给 alice 颁 dev session,使 Phase A/B (写入 / 调用 operation 的尝试) 能携带真实 bearer token
- 1 × cotest harness (Playwright `request` fixture) — 加载 `artifacts/migration/*.json` 与 `artifacts/registry/*.json`,把 entry list 直接当 negative input source

不需要 dual-soland; 不需要 browser context; 不需要新增 mock。

## Actors

| 名字 | DID | 角色 | 注册时机 |
|---|---|---|---|
| alice | `did:web:alice-drift-<uuid>.example` | 尝试写入 removed event kind / 调用 removed operation id 的发起者 (用 dev session token) | 测试开始前;仅 Phase A/B/F 需要 |
| 无 (live phases) | n/a | Phase C/E 是纯 describe + artifact diff,不需要 actor | n/a |

## Pre-conditions

- soland live 监听 `${COTEST_SOLAND_BASE_URL}` 且 `GET /_cokret/describe` 返回 200 + JSON
- harness 能 ESM resolve `cokret-spec/spec/v1/artifacts/{migration,registry}/*.json` (相对 `tests/conformance/<spec>.spec.ts` 向上 4 级到 `cokret-spec/`)
- `removed-event-kinds.json.entries[*].rejection_level === "hard_reject"` 的子集在 cotest 看来是测试输入(其他 `migration_only` 等暂不构造)
- alice 通过 `POST /_soland/self/account/register` + `POST /_soland/gate/auth/dev-login` 获取了 bearer token (仅 Phase A/B/F)

## Steps

### Phase A — Removed event kinds hard-reject

1. **harness** load `artifacts/migration/removed-event-kinds.json`,filter `entries[*].rejection_level === "hard_reject"`
2. 对每个 `entry.id` (e.g. `ck.field.position.move`, `ck.realm.lifecycle.set`, `ck.space.policy`),构造一个最小合法 EventEnvelope:
   ```json
   { "kind": "<removed_id>", "actor_id": "<alice>", "realm_id": "<test_realm>", "payload": {} }
   ```
3. `POST /_cokret/self/events` (或等价 `/_cokret/self/events/submit` operation) with bearer token
4. 断言:
   - HTTP 4xx (期望 400 / 422)
   - response body `error.code` 在 `{schema_violation, unknown_event_kind, removed_event_kind, invalid_event_kind}` 集合中
   - **NOT** 200 / 201 (即使 reducer 静默丢弃也算 drift — reducer 必须 fail-closed)
   - response body 不含被写入 event 的 echo (没有 partial accept)
5. **harness** 再调 `GET /_cokret/describe` 一次,断言 `describe.implemented_features.event_kinds[]` (或等价数组) **不包含** 任何 removed id — 实现不得在 describe surface 自称还支持这些 kind

### Phase B — Removed operation IDs hard-reject

6. **harness** load `artifacts/migration/removed-operation-ids.json`,filter `entries[*].rejection_level === "hard_reject"` (e.g. `ck.strand.track.member.add`, `ck.realm.lifecycle.set.apply`)
7. 对每个 `entry.id`,尝试通过 soland 的 generic operation endpoint 调用:
   - 若 soland 暴露 `POST /_cokret/self/operations/{operation_id}` → POST with `{}` body + bearer
   - 否则 fallback 到 `POST /_cokret/self/server/operation/invoke` with `{ operation_id, input: {} }` body
8. 断言:
   - HTTP 4xx,优先 410 Gone / 404 Not Found / 400 Bad Request
   - response body `error.code` 在 `{unknown_operation, removed_operation, gone, operation_not_found}` 集合中
   - **NOT** 200 + result (operation 必须从 routing table 完全消失,不能是 stub-success)
9. **harness** 再次调 `/_cokret/describe`,断言 `describe.implemented_features.operations[]` (或 `supported_operations[]`) 与 removed-operation-ids 的 entries 完全 disjoint

### Phase C — Deprecated profile IDs absent from describe (LIVE)

10. **harness** load `artifacts/migration/deprecated-profile-ids.json` → set of `entries[*].id`
11. `GET /_cokret/describe` → parse JSON
12. Collect *all* profile id strings advertised by the server,across **every** profile-bearing array:
    - `describe.claimed_profiles[]`
    - `describe.verified_profiles[]`
    - `describe.self_claimed_profiles[]`
    - `describe.implemented_features.profiles[]` (defensive)
    - 任何嵌套的 `{ profile_id: ... }` 对象 (deep-walk; 如出现)
13. 断言:claimed set ∩ deprecated set = ∅
14. 若违例,失败信息必须列出哪个 profile id 来自哪个 describe 数组 (便于定位)

### Phase E — Operation registry coverage (LIVE)

19. **harness** load `artifacts/registry/operation-registry.json` → 收集 `operations[*].operation_id` (82 个) 进 `canonical_op_ids: Set<string>`
20. `GET /_cokret/describe` → 抽出 `describe.implemented_features.operations[]` (或 `supported_operations[]` / fallback `describe.operations[]` — 三个 key 名都尝试,取第一个非空)
21. 对每个 `claimed_op_id`:
    - 断言 `canonical_op_ids.has(claimed_op_id)` (no rogue claim — 任何 describe 自称的 operation 都必须有 canonical 注册表条目)
    - 若失败,attach 整个 claimed list 到 testInfo,便于人工 diff
22. **不**反向断言 `canonical_op_ids ⊆ claimed_op_ids`:soland 是 partial implementation,registry 比 describe 大是合法的;只 warn (log) 未实现的 canonical ops,不 fail

### Phase F — Forbidden model terms in audit / log surfaces (OPTIONAL fixme)

23. **harness** load `artifacts/registry/forbidden-model-terms.json` → entries 主要是 prose 级别禁用术语
24. 收集所有 *string 值* (而非 key) 出现在 `/_cokret/describe` 中的字面量
25. 断言:no string value contains `\bRoom\b` / `\bPlace\b` (word-boundary,避免误伤 `RoomTitleSection` 这类合成词;同时 `interop_module` / `changelog` 在 describe 中不豁免)
26. 同样扫描 `/_soland/self/audit/recent` (若 alice 有权限) 与一个 list operation 的 JSON 序列化结果
27. 注意:本 phase 容易误报 (e.g. user-generated content 含 "Room");在 production 实现中应限定到 *server-managed* 字段;在测试中以 fixme 形式钉住,等 soland 明确 surface scope 后再 live 化

## Observable assertions (合并清单)

- Phase A:每个 hard_reject removed event.kind POST → HTTP 4xx + `schema_violation` 类错误码;describe.implemented_features.event_kinds 与 removed 集合 disjoint
- Phase B:每个 hard_reject removed operation_id 调用 → HTTP 4xx (优先 410);describe.implemented_features.operations 与 removed 集合 disjoint
- Phase C (LIVE):`/server/describe` 中所有 profile id 数组与 deprecated-profile-ids disjoint
- Phase E (LIVE):describe 自称的每个 operation 都在 operation-registry.json 中存在;reverse coverage 仅 warn 不 fail
- Phase F (fixme):describe / audit / list 响应中的 string 值不包含 forbidden-model-terms (word-boundary 匹配)

## Edge cases / sub-tests

- **R4.2 case-sensitivity**:registry 中的 id 都是 lowercase + `ck.` 前缀;Phase A/B/C 的 set 比对必须 case-sensitive,**不要** lowercase normalize (避免假阴性 — 服务器若返回 `Cx.Realm.Lifecycle.Set` 也是 drift)。
- **R4.3 nested profile arrays**:Phase C 的 deep-walk profile id 收集要考虑 nested structures,e.g. `describe.implemented_features.requirements_role_map[*].profile_id`。harness 实现:遇到任何 key 名匹配 `/profile_id?$/` 的 string value,即纳入 claimed set。
- **R4.4 describe 缺字段时的 fallback**:若 soland describe 未实现 `implemented_features.operations` 字段,Phase E 应 `test.skip("describe.implemented_features.operations 字段不存在 — 无法验证 operation coverage")`,不应让测试静默 pass。
- **R4.5 batch artifact reload**:每个 LIVE phase 在 `beforeAll` 中一次性 readFileSync + JSON.parse,不在 per-test 重复 IO。

## Implementation notes

- **artifact loader**:用 `import { readFileSync } from "node:fs"` + `import.meta.url` 推 `__dirname`;artifacts 落在 `<repo_root>/cokret-spec/spec/v1/artifacts/registry/`,相对 `cotest/e2e/tests/conformance/*.spec.ts` 是 `../../../../cokret-spec/spec/v1/artifacts`。Playwright (package.json `"type": "module"`) 原生支持 `import.meta.url`。
- **describe key 名**:scenario 写的是 `describe.implemented_features.operations`,但当前 soland 的实际字段名可能是 `supported_operations` / `operations`。spec ref:`sync/service-api-schema.mdx` + `service-surface.md`。spec 实现时 harness 应按以下顺序回退:`describe.implemented_features?.operations` → `describe.supported_operations` → `describe.operations`,第一个 non-empty array 即视为 claimed list。
- **deep-walk helper**:不要新增 `helpers/deep-walk.ts`;直接在本 spec 文件顶部写一个 `function* walkKeys(node, path = []): Iterable<{ path: string[]; key: string; value: unknown }>` generator,handle object 与 array 两类容器,leaf primitive 跳过,用于 profile id 与 model-term 扫描。
- **错误码集合**:registry 没有强制一个统一的拒绝码 (spec 写 `schema_violation`),实测 soland 可能返回 `unknown_event_kind` / `kind_not_supported`。Phase A/B 使用宽集合 + status 是 4xx 即视为通过,以免过早咬死。
- **no new helper**:全部逻辑放在 spec 文件内;只依赖 `helpers/env.ts` 的 `solandBaseUrl()`。
- **fixme 范围**:Phase A / B / F 写为 `test.fixme`,因为 (a) Phase A/B 依赖 soland 真实拒绝路径,(b) Phase F 容易误报且 surface scope 未定。Phase C/E 是纯 describe diff,完全可 live;放在 `@fully-implemented` describe block 中跑 joint-smoke。

## 总耗时预估

LIVE 部分:< 1s (单次 GET describe + 3 个 set diff)。
fixme 部分实现后:5-10s (Phase A 32 次 POST + Phase B 11 次 POST + Phase F 多 surface 扫描)。
