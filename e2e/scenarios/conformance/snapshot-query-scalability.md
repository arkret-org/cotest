# Conformance — Snapshot / Query / Scalability Vectors

## 目标

通过 soland 公开的 conformance 端点,执行 spec `conformance/snapshot-schema.md`、`conformance/query-schema.md` 与 `conformance/scalability-constraints.md` 对应的 conformance vector,逐项验证 snapshot manifest 的 chunk/hash/signature 形状、query 的 filter/sort/pagination 行为以及 scale/limit 的 fail-closed 阈值,确保 soland 的实现与 spec fixture 在 byte/digest/枚举值/HTTP 状态码层面完全一致。

不验证:encoding & crypto / redaction(见 `conformance/encoding-vectors`)、registry drift(见 `conformance/registry-drift`)、profile claim 真实性(见 `conformance/profile-gates`)、state resolution(见 `sync/state-resolution-vectors`)、capability 向量(见 `authz/capability-vectors`)、sync pagination 通用向量(见 `sync/sync-vectors`)。本 scenario 与 `conformance/encoding-vectors` 是兄弟关系:同一组 vector loader 模式、同一 HTTP-over-fixture 思路,但覆盖的是 snapshot / query / scalability 三个分支。

## Spec 锚点

- `arkret-spec/spec/v1/zh/conformance/snapshot-schema.md`
  - §2 — Snapshot manifest 字段集(id / realm_id / reducer_profile / frontier / event_set_commitment / state_digest / chunks[] / verification_hints / signature;`snapshot_ref` 仅用于外部引用位)
  - §3 — Chunk descriptor 与 chunk payload canonical shape;`items` 按 `(kind, id)` byte order 排序
  - §4 — `state_digest` = canonical reducer 输出之上的 Merkle root;leaf = `sha256(kind || ":" || id || ":" || sha256(canonical_json(object)))`
  - §5 — Snapshot signature 必须覆盖 manifest payload(去掉 `signature` 自身)的 canonical 编码;签名 DID 必须属于 Realm owner / admin / trusted issuer / witness quorum / policy-approved issuer
  - §6 — Event-set commitment 与 inclusion challenge 的能力边界(本 scenario 只断言 manifest digest 与 chunk hash,inclusion challenge 主流程在 `conformance/snapshot-inclusion-challenge` 单独覆盖)
- `arkret-spec/spec/v1/zh/conformance/query-schema.md`
  - §2 — Query 对象顶层字段集(realm_ids / object_kinds / morph_kinds / facets / filters / relation / order_by / projection / cursor / limit / consistency)
  - §3 — Filter `{ field, op, value }`,op 在 `{eq, neq, in, not_in, lt, lte, gt, gte, contains, exists, prefix, full_text}`
  - §4 — Boolean filter (`and` / `or` / `not`),嵌套深度可受限
  - §6 — Sort `{ field, direction in {asc,desc}, nulls in {first,last} }`
  - §7 — Projection 只减少返回字段,不提升权限
  - §8 — Response `{ items[], next_cursor, has_more, frontier{ barrier_cursor, max_hlc } }`
  - §9 — Schema validation、authorization filtering、unsupported facet / 字段路径 MUST reject
- `arkret-spec/spec/v1/zh/conformance/scalability-constraints.md`
  - §2 — 通用 wire 上限(envelope 1 MiB / 批量 1,000 / sync page 1,000 / prev_refs 128 / refs 128 / authorized_by 64 / fields 256 KiB / relation depth 32 / HLC logical 65,536)
  - §3 — Capability / authz 上限(delegation chain 4 / grant expansion 1,024 / constraint 64 / selector AST 16)
  - §4 — Move / Anchor / Lattice 上限
  - §5 — Space / Relation / View 上限
  - §6 — E2EE 与设备上限
  - §7 — Retention / snapshot pruning / tombstone 上限
  - §8 — 错误语义(MUST reject vs SHOULD soft_fail / quarantine,不得静默截断)
- `arkret-spec/spec/v1/zh/conformance/conformance-vectors.md` — vector loader pattern(同一目录 `spec/v1/artifacts/fixtures/<vector_id>.json`,`expected_*` 字段命名约定,失败时报告 actual / expected diff)
- 关联 artifact: `arkret-spec/spec/v1/artifacts/fixtures/ak.vector.snapshot.*.json`、`ak.vector.query.*.json`、`ak.vector.scalability.*.json`(目前尚未提交,见 Implementation notes 的 fixture absence fallback)
- 关联实现:soland snapshot/query 模块、`/_arkret/_conformance/{snapshot,query}` 端点(目前未实现,见 Implementation notes)

## 拓扑

- 1 × soland (Station) — `solandBaseUrl()`,暴露(将暴露)`/_arkret/_conformance/snapshot`、`/_arkret/_conformance/query` 端点
- 1 × coauth (private authentication process) — 仅用来给 alice 颁发 dev session,使 Phase B 验证 snapshot signature 的签名者 DID 时可以拉到真实 actor signing key
- 1 × conformance harness (Playwright `request` fixture + node `fs`) — 在测试 setup 阶段从 `arkret-spec/spec/v1/artifacts/fixtures/` glob `ak.vector.{snapshot,query,scalability}.*.json`,逐项 POST 到 soland,断言响应与 `expected_*` 字段一致

(都是 cotest 现有 harness 直接提供的,不需要改 `scripts/run-joint-e2e.ps1`;但 `/_arkret/_conformance/{snapshot,query}` 端点目前未实现,见 Implementation notes。)

## Actors

| 名字 | DID | 在 conformance/snapshot-query-scalability 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-sqs-<uuid>.example` | 单 actor;Phase B 用她的 dev key 验证 snapshot signature 验证流的 actor 上下文(实际签名者 DID 由 vector 提供);Phase C 用她的 session 调 query 端点确保 authz filter 走 actor 路径 | 测试开始前 |
| harness | n/a (Playwright `request` + node `fs`) | Vector loader / assertion driver;glob fixture 目录 → 调端点 → diff actual vs expected | n/a |

## Pre-conditions

- `alice` 通过 `POST /_soland/self/account/register` 注册过 (`ensureRegistered`)
- `alice` 持有有效 dev session token (`POST /_soland/gate/auth/dev-login`)
- harness 可访问 `arkret-spec/spec/v1/artifacts/fixtures/` 目录(从 spec test 文件位置 `cotest/e2e/tests/conformance/*.spec.ts` 解析为 `../../../../arkret-spec/spec/v1/artifacts/fixtures`,见 Implementation notes)
- soland 暴露以下 conformance 端点 (gap,见 Implementation notes):
  - `POST /_arkret/_conformance/snapshot` — body `{ vector_id, manifest, chunks }` → `{ manifest_digest, chunk_hashes[], signature_valid, signer_did }`
  - `POST /_arkret/_conformance/query` — body `{ vector_id, query }` → `{ items[], next_cursor, has_more, frontier{...} }` (按 spec §8)

## Steps

### Phase A — Snapshot manifest integrity (snapshot-schema §2 / §3 / §4)

1. **harness** 加载 `ak.vector.snapshot.manifest_integrity.v1` (若存在);vector 形如:
   ```json
   {
     "vector_id": "ak.vector.snapshot.manifest_integrity.v1",
     "protocol_version": "1.0",
     "input": { "manifest": { ... }, "chunks": [ { "chunk_ref": ..., "payload": { ... } } ] },
     "expected_manifest_digest": "sha256:...",
     "expected_chunk_count": 4,
     "expected_chunk_hashes": ["sha256:...", "sha256:...", "sha256:...", "sha256:..."],
     "expected_state_digest": "sha256:..."
   }
   ```
2. `POST /_arkret/_conformance/snapshot` with `{ vector_id, manifest, chunks }`
3. 断言:
   - `response.manifest_digest === expected_manifest_digest`(`sha256:<lowercase_hex>`)
   - `response.chunk_hashes.length === expected_chunk_count`
   - `response.chunk_hashes` 与 `expected_chunk_hashes` 顺序一致、字节相等
   - 若 vector 提供 `expected_state_digest`,断言 `response.state_digest === expected_state_digest`(覆盖 §4 reducer-output Merkle root)
4. 故意篡改一条 chunk payload(改一个 byte)再 POST → 端点 MUST 返回 4xx 与 `error.code === "snapshot_chunk_digest_mismatch"`,不静默接受

### Phase B — Snapshot signature binding (snapshot-schema §5)

5. **harness** 加载 `ak.vector.snapshot.signature_ed25519.v1`(deterministic Ed25519 vector)
6. `POST /_arkret/_conformance/snapshot` with `{ vector_id, manifest, chunks }`(manifest 内含 `signature` 字段)
7. 断言:
   - `response.signature_valid === true`
   - `response.signer_did === vector.expected_signer_did`(spec §5 列出的 5 类签名者之一:Realm owner / creator / admin / trusted snapshot issuer / witness quorum)
   - 签名 transcript 覆盖范围(id / realm_id / reducer_profile / schema_profile_refs / state_digest / frontier / event_set_commitment / chunks descriptor / verification_hints / created_by / created_at)与 vector 声明一致 — 端点应返回 `signed_transcript_fields[]` 或等价信号,断言它与 spec §5 列表逐项相等
8. 同一 manifest 再 POST 一次:`response.signature` 字段(若回显)对 Ed25519 vector MUST 完全相等(deterministic);ECDSA vector 若存在则 `r/s` 可不同但 `signature_valid` 仍为 true
9. 把 vector `signer_did` 替换为已撤销的 DID(vector `expected_signer_did_revoked` 字段) → 端点 MUST 返回 4xx 与 `error.code === "snapshot_issuer_revoked"`(snapshot-schema §5 最大接受窗口规则)

### Phase C — Query filters / sort / pagination (query-schema §2 / §3 / §6 / §8)

10. **harness** 加载 `ak.vector.query.filter_sort_paginate.v1`;vector 形如:
    ```json
    {
      "vector_id": "ak.vector.query.filter_sort_paginate.v1",
      "input": {
        "query": {
          "realm_ids": ["ak:realm:..."],
          "object_kinds": ["strand"],
          "filters": [{ "field": "fields.status", "op": "eq", "value": "todo" }],
          "order_by": [{ "field": "rank", "direction": "asc", "nulls": "last" }],
          "limit": 2
        },
        "seed_objects": [ { ... }, { ... }, { ... }, { ... } ]
      },
      "expected_rows_page_1": ["ak:strand:a", "ak:strand:b"],
      "expected_rows_page_2": ["ak:strand:c"],
      "expected_has_more_page_1": true,
      "expected_has_more_page_2": false
    }
    ```
11. POST `/_arkret/_conformance/query` with `{ vector_id, query }` → cursor_A 返回 page 1
12. 断言:
    - `response.items.map(o => o.id)` 与 `expected_rows_page_1` **顺序相等**(filter + sort 必须按 vector 声明执行)
    - `response.has_more === expected_has_more_page_1`
    - `response.next_cursor` 是非空字符串
    - `response.frontier.barrier_cursor` 存在且非空(§8)
13. 用 `next_cursor` 再 POST query → page 2
14. 断言:
    - `response.items` 与 `expected_rows_page_2` 顺序相等
    - `response.has_more === false`
15. **Pagination 稳定性**:用相同 `next_cursor` 再 POST 一次同一个 query → 返回结果 MUST 与上一次 page 2 byte-equal(cursor 在同一查询下是稳定的、不绑定时钟)
16. **Cursor opacity**:`Buffer.from(next_cursor, "base64url").toString("utf8")` 不应包含任何 expected_rows 子串(cursor 对客户端不暴露 row id;参考 encoding §1.11 cursor opaqueness)

### Phase D — Query schema fail-closed (query-schema §3 / §9)

17. **harness** 加载 `ak.vector.query.unknown_filter_key.v1`(filter 用了 spec §3 op 之外的字符串,例如 `"op": "bogus"`)
18. `POST /_arkret/_conformance/query` → MUST HTTP 4xx + `error.code === "query_schema_violation"`(或 spec 允许的等价 `schema_violation`),响应体 MUST NOT 包含 `items` / `next_cursor`(silent-empty 是失败模式)
19. **harness** 加载 `ak.vector.query.conflicting_sort.v1`(同一 `field` 出现两次,direction 一次 asc 一次 desc)
20. `POST .../query` → MUST 4xx + `error.code === "query_schema_violation"`,不能默认拿第一个 sort
21. **harness** 加载 `ak.vector.query.unauthorized_field.v1`(projection 包含调用方未授权字段) → MUST reject 而不是 silent-strip(query-schema §9 "实现 MUST 拒绝访问未授权字段")

### Phase E — Scalability constraints fail-closed (scalability-constraints §2 / §3 / §5 / §8)

22. **harness** 加载 `ak.vector.scalability.page_size_over_max.v1`(query `limit` = 1,001,超过 §2 单次 sync / projection page 1,000 上限)
23. `POST /_arkret/_conformance/query` → MUST HTTP 4xx + `error.code === "scalability_limit_exceeded"`(或等价 `payload_too_large` / `quota_exceeded`,见 §8),响应 MUST NOT 截断到 1,000 后静默接受
24. **harness** 加载 `ak.vector.scalability.batch_item_count_over_max.v1`(snapshot chunk 数 > 1,000,或 events[] > 1,000)
25. `POST /_arkret/_conformance/snapshot` → MUST 4xx + `error.code ∈ {scalability_limit_exceeded, payload_too_large}`
26. **harness** 加载 `ak.vector.scalability.relation_depth_over_max.v1`(query.relation.depth = 33,超过 §2 关系展开深度 32)
27. `POST /_arkret/_conformance/query` → MUST 4xx + `error.code === "scalability_limit_exceeded"`
28. **harness** 加载 `ak.vector.scalability.envelope_over_1mib.v1`(单个 manifest canonical 编码 > 1 MiB)
29. `POST /_arkret/_conformance/snapshot` → MUST 4xx + `error.code === "payload_too_large"`(§2 envelope 1 MiB 规则)
30. 对每条 reject vector 额外断言:响应 envelope 符合 spec §8 错误语义(`retry_after_ms` 出现仅在 `soft_fail` / `temporarily_unavailable` 路径;reject 路径不应携带 retry 提示)

### Phase F — Vector loader smoke (harness-only,no soland call)

31. **harness** 解析自身位置(`fileURLToPath(import.meta.url)` → `dirname(...)`)拼出 fixtures dir 绝对路径 `<repo>/arkret-spec/spec/v1/artifacts/fixtures`
32. `readdirSync(fixturesDir)`,过滤 `ak.vector.{snapshot,query,scalability}.*.json`,得到 candidate id 列表
33. 对每个 candidate:`JSON.parse(readFileSync(...))` MUST 不抛错(即使内容是空对象)
34. 测试通过 `console.log` / `testInfo.attach` 输出 candidate count + id 清单,便于人工 audit;不强制 candidate count > 0(fixture 可能尚未提交,此时 count === 0 也是合法的 — assertion 用 `expect(count).toBeGreaterThanOrEqual(0)`)
35. 这一步 **不触发任何 soland HTTP 请求**;它的目的只是让 fixture 缺失这件事在 CI 日志里立刻可见

### Phase G — Surface probe (optional, encouraged)

36. `GET ${solandBaseUrl()}/_arkret/describe`(无认证)
37. 断言响应是 JSON,且内部一致:
    - **不应** 同时存在 "claim 了 `ak.profile.conformance_harness.v1` profile" 与 "`/_arkret/_conformance/snapshot` 端点返回 404/501" 这对矛盾状态
    - 具体表达:若 `claimed_profiles` 数组里有任意 entry 的 `profile_id === "ak.profile.conformance_harness.v1"`,则对 `/_arkret/_conformance/snapshot` 发一个 minimal POST,响应 status 必须不是 404(允许 200 / 400 / 401 / 405 / 501;但 404 = 端点根本不存在,与 profile claim 矛盾)
    - 若 `claimed_profiles` 不含该 profile,则任何状态码(包括 404)都可以接受 — 这是 "surface 内部一致" 而非 "端点已实现" 的断言

## Observable assertions (合并清单)

- Phase A:`manifest_digest` 字符串相等、`chunk_hashes` 顺序与字节相等、可选 `state_digest` 相等;篡改 chunk 后 4xx + `snapshot_chunk_digest_mismatch`
- Phase B:`signature_valid === true`、`signer_did` 在 §5 五类合法签名者之一、Ed25519 deterministic 再签结果稳定、revoked signer 4xx + `snapshot_issuer_revoked`
- Phase C:filter / sort 后行顺序与 `expected_rows_page_*` 顺序相等;`has_more` 与 expected 相同;`next_cursor` 非空且 opaque;同一 cursor 重发结果 byte-equal
- Phase D:unknown filter op / conflicting sort / unauthorized projection 一律 4xx + `query_schema_violation`,响应不含 `items`
- Phase E:超 page_size / 超 batch / 超 depth / 超 envelope 一律 4xx + `scalability_limit_exceeded` 或 `payload_too_large`,不静默截断
- Phase F:fixtures dir 可读、glob 不抛、命中文件 JSON.parse 不抛、count >= 0
- Phase G:`/server/describe` 与 `/conformance/snapshot` 状态在 profile-claim 与 endpoint-existence 之间没有自相矛盾

## Edge cases / sub-tests

- **E1 unknown vector_id** / **E2 vector version skew**:`ak.vector.snapshot.bogus.v1` 与 `protocol_version="0.9"` 的旧 vector → MUST 4xx + `unknown_vector_id` / `unsupported_vector_version`,不静默走默认 canonicalizer
- **E3 cursor cross-query reuse**:把 Phase C 的 cursor_A 放到不同 query body 再 POST → MUST 4xx + `cursor_query_mismatch`(cursor 绑定到具体 query 形状)
- **E4 snapshot 跨服务器一致性**(dual-soland only):同一 snapshot vector POST 给 alpha 与 beta,两边 `manifest_digest` / `chunk_hashes` MUST byte-equal;`hasDualSoland()` 为 false 时 skip
- **E5 large snapshot streaming**:chunk 总和 > 100 MiB 时端点必须分段验证不 OOM — 建议拆为 `conformance/snapshot-query-scalability.large-payload` 独立 spec,保持主 scenario 紧凑

## Implementation notes

- **soland 缺口**:`/_arkret/_conformance/{snapshot,query}` 端点目前**未实现**。当前 snapshot manifest 与 query schema 的 conformance 只跑在 Rust 侧内部测试(`soland/src/snapshot/*`、reducer 集成测试),不走 HTTP。本 scenario 的价值是把同一组 vector 通过 HTTP 暴露,捕获 reducer 与 HTTP layer 之间的 serializer drift。Phase A–E 在端点落地前以 `test.fixme(...)` 钉住 spec 合约;G3.S7 着陆后可逐项 live 化。
- **fixture 缺失 fallback**:目前 `arkret-spec/spec/v1/artifacts/fixtures/` 中**没有任何** `ak.vector.{snapshot,query,scalability}.*` 文件。Phase F 的 loader smoke 必须优雅降级:`readdirSync` 后命中数可以是 0,assertion 写成 `expect(count).toBeGreaterThanOrEqual(0)`(always-pass);candidate 清单与 count 用 `console.log` + `testInfo.attach` 输出,使得 (1) fixture 尚未提交时测试不红;(2) fixture 提交后日志里立刻能看到 vector 总数变化;(3) spec 作者新增 vector 时不需要改 harness。
- **fixture loader 实现**:用 `fileURLToPath(import.meta.url)` + `dirname` + `path.resolve(..., "..", "..", "..", "..", "arkret-spec", "spec", "v1", "artifacts", "fixtures")` 从 spec 文件位置走到 fixtures 目录。**不**新增 `helpers/conformance-fixtures.ts`;loader 写在 spec 文件顶部(与 encoding-vectors 风格一致)。
- **signing key 注入**:Phase B 验证 signature 时 vector 自带 `signer_did` + `public_key_jwk`,不依赖 alice 的 dev key — snapshot 签名者通常是服务自己或 trusted issuer,不是 actor。Phase C 的 query authz filter 才用 alice 的 session token。
- **vector id 命名**(参考 encoding-vectors §1.2):`ak.vector.snapshot.<scenario>.v1` / `ak.vector.query.<scenario>.v1` / `ak.vector.scalability.<scenario>.v1`,具体 scenario 名见各 Phase 步骤。
- **error codes**:`snapshot_chunk_digest_mismatch`、`snapshot_issuer_revoked`、`query_schema_violation`、`scalability_limit_exceeded`、`payload_too_large`、`unknown_vector_id`、`unsupported_vector_version`、`cursor_query_mismatch` — 在 `arkret-spec/spec/v1/artifacts/registry/error-code-registry.json` 中应有对应条目(缺失属于 spec/registry 缺口,不属于 cotest 缺口)。
- **no new helper**:用现有 `request` fixture + `ensureRegistered` / `issueDevSession`;所有 loader / assertion 写在 spec 文件局部。

## 总耗时预估

单次跑约 30-60s(纯 HTTP 调用 + 一次 fs.readdir,无 browser context;snapshot / query / scalability vector 总数预计 ≤ 20 条,每条 < 300ms;loader smoke < 100ms)。当前 fixture 未提交,主流程全部 fixme,只有 Phase F + Phase G live,实际 wall-clock 约 1-3s。
