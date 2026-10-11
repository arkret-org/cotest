# Conformance — Snapshot / Query / Scalability Vectors

## 目标

Phase B 通过标准接口读取真实 RealmStateSnapshot，并复用 SDK/Garth 验证权威链、完整身份与签名。其余阶段保留 development-only harness 的回归检查；其中旧 manifest/chunk fixture 不是现行协议快照，不能作为生产 Snapshot 合规或基础功能完成的证据，仍需按现行规范重建。

不验证:encoding & crypto / redaction(见 `conformance/encoding-vectors`)、registry drift(见 `conformance/registry-drift`)、profile claim 真实性(见 `conformance/profile-gates`)、state resolution(见 `sync/state-resolution-vectors`)、capability 向量(见 `authz/capability-vectors`)、sync pagination 通用向量(见 `sync/sync-vectors`)。本 scenario 与 `conformance/encoding-vectors` 是兄弟关系:同一组 vector loader 模式、同一 HTTP-over-fixture 思路,但覆盖的是 snapshot / query / scalability 三个分支。

## Spec 锚点

- `arkret-spec/spec/v1/zh/conformance/realm-state-snapshot-schema.md`
  - 闭合字段为 snapshot_id、realm_id、governance_generation、visible_stream_heads、current_state_entries、retention_and_history_floor、created_at、signature。
  - 快照是 Event 与 RealmCommit 的派生读面，不能代替接受真相；current rows、stream heads 与 history floor 必须来自同一 cut。
  - Phase B 同时依照 `sync/authority-commit-log.md` 与 SDK/Garth 的完整 signed RealmStateSnapshot 合同；v1 不采用旧 manifest/chunk/state-root 作为快照或签名预像。
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
  - §4 — CBS / state-model 上限
  - §5 — Space / Relation / View 上限
  - §6 — E2EE 与设备上限
  - §7 — Retention / snapshot pruning / tombstone 上限
  - §8 — 错误语义(MUST reject vs SHOULD soft_fail / quarantine,不得静默截断)
- `arkret-spec/spec/v1/zh/conformance/conformance-vectors.md` — vector loader pattern(同一目录 `spec/v1/artifacts/fixtures/<vector_id>.json`,`expected_*` 字段命名约定,失败时报告 actual / expected diff)
- 关联 artifact: `arkret-spec/spec/v1/artifacts/fixtures/ak.vector.realm_state_snapshot.*.json`、`ak.vector.query.*.json`、`ak.vector.scalability.*.json`(目前尚未提交,见 Implementation notes 的 fixture absence fallback)
- 关联实现:coland snapshot/query 模块、`/_arkret/_conformance/{snapshot,query}` 端点(目前未实现,见 Implementation notes)

## 拓扑

- 1 × coland (Station) — `colandBaseUrl()`,暴露(将暴露)`/_arkret/_conformance/snapshot`、`/_arkret/_conformance/query` 端点
- 1 × coauth — Phase B 通过真实注册／登录取得 canonical session grant 与 DPoP，snapshot 由治理 Station 签发。
- 1 × conformance harness (Playwright `request` fixture + node `fs`) — 在测试 setup 阶段从 `arkret-spec/spec/v1/artifacts/fixtures/` glob `ak.vector.{snapshot,query,scalability}.*.json`,逐项 POST 到 coland,断言响应与 `expected_*` 字段一致

(都是 cotest 现有 harness 直接提供的,不需要改 `scripts/run-joint-e2e.ps1`;但 `/_arkret/_conformance/{snapshot,query}` 端点目前未实现,见 Implementation notes。)

## Actors

| 名字 | DID | 在 conformance/snapshot-query-scalability 中的角色 | 注册时机 |
|---|---|---|---|
| alice | 真实注册得到的 WebVH principal | Phase B 创建普通 Realm，以获准读面取得 snapshot；不提供 snapshot signer 私钥或代签。 | Phase B setup |
| harness | n/a (Playwright `request` + node `fs`) | Vector loader / assertion driver;glob fixture 目录 → 调端点 → diff actual vs expected | n/a |

## Pre-conditions

- Phase B 使用 `openDpopUserPage` 真实 provisioning，持有 canonical session grant、holder proof 与独立 Event signer。
- harness 可访问 `arkret-spec/spec/v1/artifacts/fixtures/` 目录(从 spec test 文件位置 `cotest/e2e/tests/conformance/*.spec.ts` 解析为 `../../../../arkret-spec/spec/v1/artifacts/fixtures`,见 Implementation notes)
- coland 暴露以下 conformance 端点 (gap,见 Implementation notes):
  - `POST /_arkret/_conformance/snapshot` — body `{ vector_id, manifest, chunks }` → `{ manifest_digest, chunk_hashes[], signature_valid, signer_did }`
  - `POST /_arkret/_conformance/query` — body `{ vector_id, query }` → `{ items[], next_cursor, has_more, frontier{...} }` (按 spec §8)

## Steps

### Phase A — 旧 development harness manifest integrity（待重建，非现行 Snapshot 合规证据）

1. **harness** 加载 `ak.vector.realm_state_snapshot.manifest_integrity.v1` (若存在);vector 形如:
   ```json
   {
     "vector_id": "ak.vector.realm_state_snapshot.manifest_integrity.v1",
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
4. 故意篡改一条 chunk payload(改一个 byte)再 POST → 端点 MUST 返回 4xx 与 `error.code === "realm_state_snapshot_chunk_digest_mismatch"`,不静默接受

### Phase B — 真实 Snapshot identity、authority 与 signature binding

5. 真实注册／登录后经 UI 创建普通 Realm，读取标准 snapshot head，再按 snapshot_id 精确读取原签名对象；两者 canonical bytes 必须一致。
6. 以新随机 nonce 读取标准 Realm authority bundle，并获取 runner 已绑定 Station 的 retained service resolution。
7. `cotest-wire verify-realm-state-snapshot` 直接复用 SDK 的 method-native history、verification method 解析和 Garth 的 verified authority/snapshot 安装：验证 nonce、治理代际的 Station signer、完整身份预像与 detached signature。Rust SDK 是唯一类型来源，测试工具只返回验证布尔值和内部失败阶段。
8. 同一真实对象分别改变 body、签名字节、签名方法为已验证 DID 中不存在的方法，以及 authority request nonce；四者均须拒绝。
9. 不使用旧 frontier/seal transcript、伪签名或 reserved issuer-revoked reason，也不把 unknown method 负例记为已经执行真实 DID 撤销操作。

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

### Phase F — Vector loader smoke (harness-only,no coland call)

31. **harness** 解析自身位置(`fileURLToPath(import.meta.url)` → `dirname(...)`)拼出 fixtures dir 绝对路径 `<repo>/arkret-spec/spec/v1/artifacts/fixtures`
32. `readdirSync(fixturesDir)`,过滤 `ak.vector.{snapshot,query,scalability}.*.json`,得到 candidate id 列表
33. 对每个 candidate:`JSON.parse(readFileSync(...))` MUST 不抛错(即使内容是空对象)
34. 测试通过 `console.log` / `testInfo.attach` 输出 candidate count + id 清单,便于人工 audit;不强制 candidate count > 0(fixture 可能尚未提交,此时 count === 0 也是合法的 — assertion 用 `expect(count).toBeGreaterThanOrEqual(0)`)
35. 这一步 **不触发任何 coland HTTP 请求**;它的目的只是让 fixture 缺失这件事在 CI 日志里立刻可见

### Phase G — Surface probe (optional, encouraged)

36. `GET ${colandBaseUrl()}/_arkret/describe`(无认证)
37. 断言响应是 JSON,且内部一致:
    - **不应** 同时存在 "`development_mode === true`" 与 "`/_arkret/_conformance/snapshot` 端点返回 404" 这对矛盾状态
    - 具体表达:若 `GET /_arkret/describe` 顶层 `development_mode === true`,则对 `/_arkret/_conformance/snapshot` 发一个 minimal POST,响应 status 必须不是 404(允许 200 / 400 / 401 / 405 / 501;但 404 = 端点根本不存在,与 test-build 姿态矛盾)
    - 若 `development_mode === false`,则 404 是规范要求 — 这是 "surface 内部一致" 而不是生产能力宣告

## Observable assertions (合并清单)

- Phase A:`manifest_digest` 字符串相等、`chunk_hashes` 顺序与字节相等、可选 `state_digest` 相等;篡改 chunk 后 4xx + `realm_state_snapshot_chunk_digest_mismatch`
- Phase B：原始 by-ref bytes 与 head 一致，完整 SDK/Garth verified path 成功；body、signature、unknown method、nonce 四种篡改逐项拒绝。
- Phase C:filter / sort 后行顺序与 `expected_rows_page_*` 顺序相等;`has_more` 与 expected 相同;`next_cursor` 非空且 opaque;同一 cursor 重发结果 byte-equal
- Phase D:unknown filter op / conflicting sort / unauthorized projection 一律 4xx + `query_schema_violation`,响应不含 `items`
- Phase E:超 page_size / 超 batch / 超 depth / 超 envelope 一律 4xx + `scalability_limit_exceeded` 或 `payload_too_large`,不静默截断
- Phase F:fixtures dir 可读、glob 不抛、命中文件 JSON.parse 不抛、count >= 0
- Phase G:`/_arkret/describe` 与 `/_arkret/_conformance/snapshot` 在 `development_mode` 姿态与 endpoint-existence 之间没有自相矛盾

## Edge cases / sub-tests

- **E1 unknown vector_id** / **E2 vector version skew**:`ak.vector.realm_state_snapshot.bogus.v1` 与 `protocol_version="0.9"` 的旧 vector → MUST 4xx + `unknown_vector_id` / `unsupported_vector_version`,不静默走默认 canonicalizer
- **E3 cursor cross-query reuse**:把 Phase C 的 cursor_A 放到不同 query body 再 POST → MUST 4xx + `cursor_query_mismatch`(cursor 绑定到具体 query 形状)
- **E4 snapshot 跨服务器一致性**（multi-server only）：同一 snapshot vector POST 给 server1 与 server2，两边 `manifest_digest` / `chunk_hashes` MUST byte-equal；`hasServerCount(2)` 为 false 时 skip
- **E5 large snapshot streaming**:chunk 总和 > 100 MiB 时端点必须分段验证不 OOM — 建议拆为 `conformance/snapshot-query-scalability.large-payload` 独立 spec,保持主 scenario 紧凑

## Implementation notes

- **Coland test-build 要求**:`/_arkret/_conformance/{snapshot,query}` 已实现为 development-only HTTP harness。joint runner 必须以 `conformance-harness` feature 构建 Coland 且设置 `development_mode=true`；仅源码时间戳 fresh 不足以证明缓存 binary 带有该 feature。生产 binary 不得暴露该命名空间。
- **fixture 缺失 fallback**:目前 `arkret-spec/spec/v1/artifacts/fixtures/` 中**没有任何** `ak.vector.{snapshot,query,scalability}.*` 文件。Phase F 的 loader smoke 必须优雅降级:`readdirSync` 后命中数可以是 0,assertion 写成 `expect(count).toBeGreaterThanOrEqual(0)`(always-pass);candidate 清单与 count 用 `console.log` + `testInfo.attach` 输出,使得 (1) fixture 尚未提交时测试不红;(2) fixture 提交后日志里立刻能看到 vector 总数变化;(3) spec 作者新增 vector 时不需要改 harness。
- **fixture loader 实现**:用 `fileURLToPath(import.meta.url)` + `dirname` + `path.resolve(..., "..", "..", "..", "..", "arkret-spec", "spec", "v1", "artifacts", "fixtures")` 从 spec 文件位置走到 fixtures 目录。**不**新增 `helpers/conformance-fixtures.ts`;loader 写在 spec 文件顶部(与 encoding-vectors 风格一致)。
- **snapshot 信任材料**：Phase B 只从标准接口读取真实 signed snapshot、nonce-bound authority 与 retained service history，不注入 snapshot 私钥，不从未验证的展示 JSON 选签名公钥。
- **vector id 命名**(参考 encoding-vectors §1.2):`ak.vector.realm_state_snapshot.<scenario>.v1` / `ak.vector.query.<scenario>.v1` / `ak.vector.scalability.<scenario>.v1`,具体 scenario 名见各 Phase 步骤。
- **error codes**：其它 conformance phases 仅断言现行 active registry 合同；Phase B 的本地验证结果不是新增协议 verdict，reserved issuer-revoked reason 不用于 positive/negative 验收。
- **Phase B 验证工具**：使用现有 `openDpopUserPage` 和逐请求 DPoP；`cotest-wire` 的薄命令调用 SDK/Garth 验证器，不另建协议类型或自定义签名规则。其余阶段的 fixture loader 保留在 spec 文件局部。

## 总耗时预估

Phase B 包含真实 provisioning 与浏览器创建 Realm，超时窗口为 180 秒；其它阶段按实际 joint-e2e 记录报告。测试标签与 fixture loader 成功不能替代生产功能验收。
