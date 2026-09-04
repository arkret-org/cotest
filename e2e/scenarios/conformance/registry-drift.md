# Conformance — Registry Drift / Current Catalog

## 目标

以 arkret-spec 当前 candidate v1 的 canonical 工件为唯一真源，检查 soland 实际暴露的 `/_arkret/describe`、事件写入和读取 surface 是否发生漂移。当前 v1 尚未发布，规范明确不维护历史 migration 清单或兼容登记表；Cotest 不得依赖已删除的 `artifacts/migration/*.json`。

本 scenario 验证：

- describe 声明的 profile id 必须存在于 `conformance-profiles.json.profile_roles`。
- describe 声明的 operation id 必须存在于 `operation-registry.json`。
- `forbidden-wire-fields.json` 登记的 hard-reject event kind 必须被写入路径 fail-closed 拒绝。
- 服务器管理的读取面不得泄露 hard-reject model term 或 forbidden wire field。

## Spec 锚点与真源

- `arkret-spec/spec/v1/zh/conformance/schema-registry.md` §1：JSON registry 是唯一机读真源。
- `arkret-spec/spec/v1/zh/overview/release-readiness.md` §2：当前 candidate v1 不维护历史迁移清单或兼容登记表。
- `arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json`：当前 profile graph，`profile_roles` 是 profile id 的 canonical 索引。
- `arkret-spec/spec/v1/artifacts/registry/event-kind-registry.json`：当前 active event kind 清单。
- `arkret-spec/spec/v1/artifacts/registry/operation-registry.json`：当前 canonical operation 清单。
- `arkret-spec/spec/v1/artifacts/registry/forbidden-wire-fields.json`：当前 wire hard-reject 守卫，包括仍需负向测试的旧 event kind 值。
- `arkret-spec/spec/v1/artifacts/registry/forbidden-model-terms.json`：服务器管理字段中的禁用术语。

## 拓扑和前置条件

- 1 × soland，暴露 `/_arkret/describe` 和 `/_arkret/self/events`。
- 1 × coauth，用于给负向写入探针颁发真实 dev session。
- Cotest Playwright request fixture 可从同级 arkret-spec 仓库读取 `artifacts/{profiles,registry}/*.json`。
- 不需要 multi-server、browser context 或 mock service。

## Steps

### Phase A — Forbidden event kind hard-reject

1. 从 `forbidden-wire-fields.json` 选取 `context=event_kind`、`rejection_level=hard_reject` 且允许 `negative_test` 的条目。
2. 断言该 id 不存在于 `event-kind-registry.json.event_kinds`。
3. 使用真实 bearer token 构造最小 Event Envelope，提交到 `/_arkret/self/events`。
4. 断言 HTTP 为 4xx，错误码为 `schema_violation` 或 `unknown_event_kind`，且响应不得显示 accepted。

### Phase C — Claimed profile catalog coverage

1. 从 `conformance-profiles.json.profile_roles` 建立 canonical profile id set。
2. 收集 describe 中 `claimed_profiles`、`verified_profiles`、`self_claimed_profiles` 和嵌套 `profile_id` 值。
3. 断言 claimed set 是 canonical set 的子集；未登记 profile 属于 rogue claim。

### Phase E — Claimed operation catalog coverage

1. 从 `operation-registry.json.operations[*].operation_id` 建立 canonical operation set。
2. 只从当前角色 `ServiceDescribe.supported_operation_bundles[]` 按本地注册表展开精确 operation 声明；未知 bundle 必须 fail closed。
3. 断言每个 claimed operation 都在 canonical set 中。不反向要求 soland 实现全部 registry operation。

### Phase F/G — Server-managed response scanning

1. 从 `forbidden-model-terms.json` 加载 hard-reject term，按字面值扫描 describe、health、提交 receipt 和授权读取面。
2. 从 `forbidden-wire-fields.json` 分类 field name、nested path、enum pair、typed-id prefix、forbidden value 和 patch path。
3. 对实际提交与读回的 Event Envelope/receipt 执行结构扫描，断言违规集为空。

## 边界规则

- 所有 id 比较都区分大小写，不做 lowercase normalization。
- describe 没有 operation 声明字段时，Phase E 必须显式 skip，不得静默 pass。
- profile deep-walk 只收集 profile-bearing 路径，避免把其它 `id` 字段误当 profile。
- 工件在 spec 模块加载时一次性读取；缺失当前 canonical 工件应立即使测试收集失败。

## 总耗时预估

全部 phase 为 API 级探针，通常在 10 秒内完成。
