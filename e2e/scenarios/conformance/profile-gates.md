# Conformance — Profile Claim Gates

## 目标

验证 Cokret `claimed_profiles` / `verified_profiles` 在 wire 层的分区语义与 fail-closed
守门:soland / coauth 的 `/server/describe` 输出 MUST 把 `self_claimed` 与 cotest-verified
entries 严格分开;dev mode MUST 让 `verified_profiles=[]`;声明里的 profile id MUST 都
在 `artifacts/profiles/conformance-profiles.json` 目录中存在;声明 profile 范围之外的标准
Event kind MUST fail closed (不能 silent accept-and-drop);profile 涉及的 critical
extension 服务端未执行时,describe 或 runtime MUST 报错。

不验证:`/server/describe` 的基础形状(`implemented_features`、standard error envelope、
pagination、idempotency)由 `scenarios/sync/service-surface-contract.md` 负责。Encoding /
redaction / HLC / cursor vector 由 `scenarios/conformance/encoding-vectors.md` 负责。
Schema/operation/event 注册表 drift 由 `scenarios/conformance/registry-drift.md` 负责。

## Spec 锚点

- `cokret-spec/spec/v1/zh/conformance/conformance-profiles.md`
  - §2 / §2.1 — Profile 命名与 v1 MVP 分层(`v1_profile_catalog` /
    `v1_minimal_interop_floor` / `extension_profile_implementation`);写入接收方收到不在
    声明 profile 内的 active 标准 Event kind 时 MUST 返回 `unsupported_event_kind` /
    `unsupported_feature` / `schema_violation` / quarantine;`requirements.critical_extensions[]`
    不支持时 fail closed 优先级高于 "可忽略可选功能";`default_unsupported_behavior` 是
    conformance lint 机读来源
  - §3 — 通用强制要求(标准 `ck.*` kind MUST 注册、auth 不可豁免、`causal` 关系
    fail-closed)
- `cokret-spec/spec/v1/zh/sync/service-surface.md` §3.0 — `claimed_profiles` /
  `verified_profiles` 分区 wire 形态、`claim_kind` 枚举、`development_mode=true` MUST
  `verified_profiles=[]`
- 关联 artifact:
  - `cokret-spec/spec/v1/artifacts/profiles/conformance-profiles.json` —
    `implementation_profiles[]` / `profile_tiers.v1_profile_catalog` /
    `extension_profile_implementation` / `default_unsupported_behavior`
  - `cokret-spec/spec/v1/artifacts/registry/event-kind-registry.json` — Phase B 用来挑
    "在目录中但不在 soland 声明范围内" 的标准 kind
- 关联实现:
  - `soland/src/routing/system/describe.rs::apply_claim_level_partition` —
    `claimed_profiles` 4 条 self_claimed,`verified_profiles=[]`
  - `coauth/crates/backend/src/handlers/cokret.rs` (T6.3) —
    `claimed_profiles=Vec::new()` + `verified_profiles=Vec::new()`,coauth 不假 claim
    `ck.profile.identity_registry.v1` (跟踪项 `_codex_test_gaps.md` G3.C3)

## 拓扑

- 1 × soland (principal server) — `COTEST_SOLAND_BASE_URL`,暴露 `/_cokret/describe`
- 1 × coauth (auth server,可选) — `COTEST_COAUTH_BASE_URL`,缺省时 coauth-specific 子
  测试 skip
- 1 × profile-gates harness (Playwright `request` fixture) — 纯 HTTP,无 browser context;
  另读本地 catalog JSON 做 set 运算

Phase B / Phase C 依赖 soland 尚未落地的 event-submit reject 路径,先 fixme。

## Actors

| 名字 | DID | 角色 | 注册时机 |
|---|---|---|---|
| alice | `did:web:alice-pg-<uuid>.example` | Phase B event submitter | 测试开始前 |
| profile harness | n/a | describe 调用 + catalog loader + 集合差比对 | n/a |

## Pre-conditions

- soland `/_cokret/describe` 已暴露 T6.1 claim-level partition
  (`implemented_features` / `claimed_profiles` / `verified_profiles` /
  `experimental_features` / `compat_surfaces`)
- soland 启动时 `development_mode=true`(cotest harness 默认配置)
- catalog 通过 `path.resolve(__dirname, "../../../../cokret-spec/spec/v1/artifacts/profiles/conformance-profiles.json")`
  解析(相对于 `cotest/e2e/tests/conformance/`)
- 当 coauth 测试运行时,`COTEST_COAUTH_BASE_URL` 已就位

## Steps

### Phase A — claim_kind 分区(`claimed_profiles` ∩ `verified_profiles` = ∅)

1. **harness** `GET ${solandBaseUrl}/_cokret/describe`
2. 断言 `claimed_profiles` 是数组,每条 entry MUST 有 `profile_id` + `claim_kind`
3. 断言 `claimed_profiles[].claim_kind` 全部等于 `self_claimed`(`verified` 只能由
   cotest verifier 写入 `verified_profiles`)
4. 断言 `verified_profiles` 是数组;若 entries 非空,每条 MUST 携带 `cotest_run_id`
   + `artifact_digest` + `artifact_ref` + `cotest_issuer_did` + `signature`
   + `timestamp`(`VerifiedProfileDescriptor` schema)
5. 集合断言 `set(claimed_profiles[].profile_id) ∩ set(verified_profiles[].profile_id)
   === ∅`(违反则违反 §3.0 partition 语义)

### Phase B — 未声明的标准 event kind fail-closed

6. **harness** 从 `event-kind-registry.json` 挑一个 active durable 但 soland
   claimed profile 不覆盖的 kind(候选 `ck.applet.transaction.v1` ↔
   `ck.profile.applet_service.v1`,后者不在 soland claimed 列表)
7. alice 注册 + dev-login
8. `POST /_cokret/self/events` with a minimal Event envelope whose `kind` is `<unsupported_kind>`
   + Bearer token
9. 断言:
   - HTTP 4xx
   - `error.code` ∈ `{unsupported_event_kind, unsupported_feature, schema_violation}`
     (`default_unsupported_behavior.write_receiver_unknown_active_standard_kind.allowed_results`)
   - response NOT include `accepted: true` / `event_id`
10. `GET .../actor/frontier?actor=alice.did` 调用前后 `actor_seq` 严格相等(无 silent
    accept-and-drop)

### Phase C — critical extension fail-closed

11. **harness** POST 一条 event,`requirements.critical_extensions:
    ["<not-implemented-ext>"]`(参考 soland claimed profile 中的真实 critical extension
    标识)
12. 断言任一:
    - submit fail-closed(`schema_violation` / `unsupported_feature` / `soft_fail` /
      `quarantine`,见 `default_unsupported_behavior.unknown_required_feature_or_critical_extension.allowed_results`)
    - 或 describe `claimed_profiles` 在该 profile entry 上携带 `notes` /
      `unsupported_extensions[]` 显式声明 critical extension 不可用
13. 不接受 "静默接受 + reducer 依赖未实现 extension" 的混合状态

### Phase D — development mode `verified_profiles=[]`

14. 复用 Phase A 的 soland describe response
15. 断言顶层 `development_mode === true`(cotest harness 默认)
16. 断言顶层 `verified_profiles` 严格等于 `[]`(Array.isArray + length === 0,**不接受**
    `null` / `undefined` / 占位 stub)
17. coauth 在线时,对 `coauthBaseUrl()/_cokret/describe` 重复 15-16

### Phase E — profile catalog integrity

18. **harness** 读 `conformance-profiles.json`,计算
    `catalog_known = implementation_profiles ∪ profile_tiers.v1_profile_catalog ∪
    profile_tiers.extension_profile_implementation`(并集 — `mimi_interop` 属 extension
    tier,不在 stable catalog 但在 `implementation_profiles` 中)
19. 断言 `claimed_profiles[].profile_id` ⊆ `catalog_known`(零容忍 typo,例如
    `ck.profile.principal-server.v1`)
20. **不**把 `unsupported_profiles[]`(如 `ck.profile.soland_limited_server.v1`)纳入
    检查 — 这类是 limitation descriptor,不是 conformance claim,也不必出现在 catalog

## Observable assertions

- Phase A:数组形态 + `claim_kind` 枚举 + 两者 profile_id 不相交
- Phase B:unsupported kind submit → HTTP 4xx + 规定错误码 + frontier 不动
- Phase C:critical extension fail-closed(submit reject 或 describe 显式声明)
- Phase D:`development_mode=true` 强制 `verified_profiles=[]`(严格等 `[]`)
- Phase E:`claimed_profiles[].profile_id` ⊆ catalog(含 stable + extension tier)

## Edge cases / sub-tests

- **E1 coauth 分区独立**:coauth 当前 `claimed_profiles=[]`、`verified_profiles=[]`
  (T6.3) — 子测试断言两个数组都为 `[]`,确保 coauth 没有 silent claim
  `ck.profile.identity_registry.v1`(对应 G3.C3 跟踪项)
- **E2 verified_profiles entry shape**:一旦 cotest verifier 写入 `verified_profiles`,
  每条 entry MUST 携带 `cotest_run_id` / `artifact_digest` / `artifact_ref` /
  `cotest_issuer_did` / `signature` / `timestamp`;Phase A 的 entry-shape 断言提前钉住未来形态
- **E3 `unsupported_profiles` 不参与 claim**:Phase E 验证
  `ck.profile.soland_limited_server.v1` 等 limitation descriptor **不**在
  `claimed_profiles` 中,且**不**要求出现在 catalog 中
- **E4 catalog 自洽性**:`v1_profile_catalog ⊆ implementation_profiles`,作为 lint;
  不是 server 断言

E1 单独写成 coauth-specific fixme 子测试(coauth 上线后 live 化)。E2 / E4 先注释钉住。

## Implementation notes

- **soland 现状**:`apply_claim_level_partition` 已经实现 T6.1 partition;
  `claimed_profiles` 4 条 `ck.profile.{core_event_store, principal_server,
  principal_server_events_api, mimi_interop}.v1`(最后一条带 `notes`),
  `verified_profiles` dev mode 下 `Vec::new()` 由 `validate` 硬性约束 — Phase A /
  D / E 可立即 live
- **soland 缺口**:event submit handler 对超出声明 profile 范围的 kind 还没有
  `unsupported_event_kind` 出口,Phase B / C fail-closed 路径先 fixme
- **coauth 现状**:describe handler `claimed_profiles=Vec::new()` +
  `verified_profiles=Vec::new()`,inline test (`describe_v2_artifacts.rs::claim_kind_partition`)
  已钉住 self_claimed invariant;本场景在 cotest 层重复该 wire-level 断言
- **catalog loader**:`fs.readFileSync` 同步读(<3000 行,只用一次);ESM 下用
  `fileURLToPath(import.meta.url)` 构造 `__dirname`(参考
- **no new helper**:不要新增 `helpers/conformance.ts` / `helpers/profile-catalog.ts`,
  catalog 集合构造与读文件逻辑放在 spec 文件顶部
- **与 G1.T2 边界**:G1.T2 (`service-surface-contract`) 盯通用 wire 形状
  (`implemented_features` / standard error envelope / pagination / idempotency);本
  场景**只**盯 profile 声明真实性。共享 `solandBaseUrl()` helper,但不共享 fixture
  装载

## 总耗时预估

单次跑约 3-8s(纯 HTTP `/server/describe` 1-2 次 + 同步本地 JSON 读 ~80 KiB + 集合差
比对,无 browser context)。
