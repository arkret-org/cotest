# Conformance — Encoding & Crypto / Redaction Vectors

## 目标

通过 soland 公开的 conformance 端点,执行 spec `conformance/conformance-vectors.md` §1 (Encoding & crypto) 与 §3 (Redaction) 中的 conformance vector,逐项验证 canonical JSON、event digest、signature binding、HLC ordering、sync cursor 稳定性、encrypted envelope digest 与 redaction 投影,确保 soland 的实现与 spec fixture 在 byte/digest/order 层面完全一致。

不验证:state resolution (§2,见 sync/state-resolution-vectors)、capability vectors (§4,见 authz/capability-vectors)、sync pagination vectors (§5,见 sync/sync-vectors)、handle vectors (§8,见 identity/handle-vectors)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/conformance/conformance-vectors.md` §1 — Encoding & Crypto Vectors
  - §1.3–§1.5.1 — Canonical JSON (basic / nested / reject non-canonical / reject malformed)
  - §1.6 — Event digest
  - §1.7 — Event batch receipt digest
  - §1.8 — Signature binding payload
  - §1.9–§1.10 — HLC order / logical overflow
  - §1.11 — Cursor opaqueness
  - §1.12 — Encrypted envelope digest
  - §1.13 — 覆盖矩阵
- `arkret-spec/spec/v1/zh/conformance/conformance-vectors.md` §3 — Redaction Vectors
  - §3.2 — 字段保留规则
  - §3.2.1 — Space target redaction payload schema
  - §3.3 — Redaction 与 policy scope
  - §3.4 — Hard erasure receipt
  - §3.5 — Snapshot pruning retains verification stub
- `arkret-spec/spec/v1/zh/encoding.md` — canonical JSON / digest 实现 profile
- `arkret-spec/spec/v1/zh/models/event-and-attestation.md` — signature binding payload
- 关联 artifact: `arkret-spec/spec/v1/artifacts/fixtures/` (canonical vector JSON 入口,本 scenario 通过 harness 装载并下发到 soland)
- 关联实现:`cotest/src/conformance/encoding.rs`, `cotest/src/conformance/redaction.rs`, `cotest/src/conformance/envelope.rs` (Rust 侧已有 fixture-driven 单元测试;本 e2e 任务把同一组 vector 通过 HTTP 端点驱动)

## 拓扑

- 1 × soland (Station) — 假设监听 `http://127.0.0.1:<soland_port>`,暴露 `/_arkret/_conformance/*` 端点
- 1 × coauth (private authentication process) — 仅用来给 alice 颁发 dev session,使签名向量阶段可以拿到一个真实的 actor signing key
- 1 × conformance harness (Playwright `request` fixture) — 加载 `arkret-spec/spec/v1/artifacts/fixtures/*.json` vector,逐项 POST 到 soland,断言响应字段与 `expected_*` 字段相等

(都是 cotest 现有 harness 直接提供的,不需要改 scripts/run-joint-e2e.ps1;但 §1 的 endpoint 目前未实现,见 Implementation notes。)

## Actors

| 名字 | DID | 在 conformance/encoding-vectors 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-conf-<uuid>.example` | 单 actor;在 §1.8 signature binding 阶段用她的 dev key 签 event,在 §3 redaction 阶段做 redaction 发起者 | 测试开始前 |
| guest | `did:webvh:z6mkfixture:guest-conf-<uuid>.example` | 仅用于 §3 redaction visibility matrix 中的 "未授权读者" 投影 (不实际加入任何 space,只是它的 DID 作为 visibility filter 的输入) | 测试开始前 |
| conformance harness | n/a (Playwright `request`) | Vector loader / assertion driver;加载 fixture → 调端点 → diff actual vs expected | n/a |

## Pre-conditions

- `alice` 和 `guest` 都通过 `POST /_soland/self/account/register` 注册过 (`ensureRegistered`)
- `alice` 持有有效 dev session token (`POST /_soland/gate/auth/dev-login`)
- harness 已加载 spec fixture JSON,数据结构形如:
  ```json
  {
    "vector_id": "ak.vector.encoding.canonical_json.basic.v1",
    "protocol_version": "1.0",
    "input": { "b": 2, "a": 1 },
    "expected_canonical_json": "{\"a\":1,\"b\":2}",
    "expected_digest": "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
  }
  ```
- soland 暴露以下 conformance 端点 (gap,见 Implementation notes):
  - `POST /_arkret/_conformance/encode` — body `{ vector_id, input }` → `{ canonical_json, digest }`
  - `POST /_arkret/_conformance/sign` — body `{ vector_id, event, signing_key_ref }` → `{ canonical_bytes, digest, signature }`
  - `POST /_arkret/_conformance/hlc-merge` — body `{ vector_id, clocks: [{actor, hlc, payload_hint}] }` → `{ ordered: [...] }`
  - `POST /_arkret/_conformance/cursor` — body `{ vector_id, events, reduce_round }` → `{ cursor }`
  - `POST /_arkret/_conformance/envelope` — body `{ vector_id, envelope }` → `{ canonical_bytes, digest }`
  - `POST /_arkret/_conformance/redact` — body `{ vector_id, event, redaction, viewer_did }` → `{ projected_event }`

## Steps

### Phase A — Canonical JSON encoding (§1.3 / §1.4 / §1.5 / §1.5.1)

1. **harness** 加载 `ak.vector.encoding.canonical_json.basic.v1`、`...nested.v1`
2. 对每个 vector,`POST /_arkret/_conformance/encode` with `{ vector_id, input }`
3. 断言:
   - `response.canonical_json` 与 `expected_canonical_json` 完全字节相等 (含字段排序、无空白)
   - `response.digest === expected_digest`(`sha256:<lowercase_hex>` 格式,大小写敏感)
4. **harness** 加载 §1.5 `reject_noncanonical_numbers.v1` 与 §1.5.1 `reject_malformed_json.v1`
5. 对每个 reject vector,`POST .../encode` 应返回 HTTP 4xx,`error.code ∈ {schema_violation, invalid_canonical_json, invalid_encoding}`
6. 断言:reject 路径**不会**返回部分 canonical bytes / digest(必须在 canonicalization 阶段失败,不能进入 hash)

### Phase B — Event digest + Signature binding (§1.6 / §1.7 / §1.8)

7. **harness** 加载 `ak.vector.encoding.event_digest.v1`
8. `POST /_arkret/_conformance/encode` with §1.6 输入事件
9. 断言:`canonical_json` / `digest` 与 spec §1.6 期望值一致
10. **harness** 加载 `ak.vector.encoding.batch_receipt_digest.v1` (§1.7)
11. `POST .../encode` 输入 batch receipt → 断言 receipt 的 canonical bytes / digest 一致
12. **harness** 加载 `ak.vector.encoding.signature_binding.v1` (§1.8)
13. `POST /_arkret/_conformance/sign` with `{ event, signing_key_ref: alice.dev_key }`
14. 断言:
    - `canonical_bytes` 与 vector `expected_canonical_bytes` 一致
    - `signature` 在 `(canonical_bytes, alice.public_key)` 下 verify 通过
    - 同一输入连发两次,签名值若是 deterministic scheme (Ed25519) 必须完全相等;若是 randomized (ECDSA),verify 仍通过且 `r/s` 不同

### Phase C — HLC timestamp ordering (§1.9 / §1.10)

15. **harness** 加载 `ak.vector.encoding.hlc_order.v1`,内含一组并发 logical clocks
16. `POST /_arkret/_conformance/hlc-merge` with `{ clocks: [...] }`
17. 断言:`response.ordered` 序列与 vector `expected_order` 完全相同 (包括 tie-break 时 actor_id 字典序)
18. **harness** 加载 `ak.vector.encoding.hlc_logical_overflow.v1` (§1.10)
19. 断言:logical counter 溢出时端点返回明确错误码 (`hlc_logical_overflow`),不静默 wrap

### Phase D — Cursor stability across re-reduce (§1.11)

20. **harness** 加载 `ak.vector.encoding.cursor_opaqueness.v1`,内含同一组 events 的两次 reduce 序列 (顺序不同,最终态相同)
21. `POST /_arkret/_conformance/cursor` with `{ events, reduce_round: 1 }` → cursor_A
22. `POST .../cursor` with `{ events_shuffled, reduce_round: 2 }` → cursor_B
23. 断言:
    - `cursor_A === cursor_B` (cursor 对内部 reduce 顺序不可见)
    - cursor 字节是 opaque base64url / base32,不含明文 event_id (反向验证 `Buffer.from(cursor, "base64url").toString()` 不包含任何 event_id 子串)

### Phase E — Encrypted envelope round-trip (§1.12)

24. **harness** 加载 `ak.vector.encoding.encrypted_envelope_digest.v1`
25. `POST /_arkret/_conformance/envelope` with `{ envelope: { mls_ciphertext, header, ... } }`
26. 断言:
    - `response.canonical_bytes` 与 vector 一致 (header 字段排序后)
    - `response.digest === expected_digest`
    - 用同一 envelope 再算一次 digest,结果稳定 (no randomness in canonical form)

### Phase F — Redaction visibility matrix (§3.2 / §3.3 / §3.4 / §3.5)

27. **harness** 加载 `ak.vector.redaction.field_retention.v1` (§3.2),内含一对 `(original_event, redaction_event)`
28. `POST /_arkret/_conformance/redact` with `{ event, redaction, viewer_did: alice.did }`
29. 断言:`projected_event` 中保留字段集 = vector `expected_retained_fields_owner`,被剥离字段不出现(不是 set null,是 key 缺失)
30. 再次 `POST .../redact` with `{ ..., viewer_did: guest.did }` (未授权读者)
31. 断言:`projected_event` 是 vector `expected_retained_fields_guest` 的精确投影(典型情况:guest 看不到 `payload.content`,但看得到 `event_id` / `redacted_because` / tombstone marker)
32. **harness** 加载 §3.2.1 (space target redaction schema)、§3.3 (policy scope)、§3.4 (hard erasure receipt)、§3.5 (snapshot pruning)
33. 对每条 vector,断言投影/receipt/snapshot stub 与 spec 完全一致

### Phase G — 覆盖矩阵 (§1.13)

34. **harness** 跑完所有 §1 vector 后,POST 一份 `coverage_report` 到 soland 的 `/_arkret/_conformance/coverage` (或直接在 harness 侧产 artifact)
35. 断言:每个 spec §1.13 矩阵条目至少有一个 vector 报告 `pass`;没有任何条目报告 `not_executed`

## Observable assertions (合并清单)

- Phase A:`canonical_json` 字节相等、`digest` 字符串相等 (大小写、前缀 `sha256:`)
- Phase A reject 子步:HTTP 4xx + `error.code` 在 spec 允许集合内
- Phase B:`canonical_bytes` 与 `signature` 双重一致;同 input deterministic schemes 签名稳定
- Phase C:`ordered` 序列与 vector `expected_order` 完全相同
- Phase D:cursor 在不同 reduce 顺序下相同;cursor 内容 opaque
- Phase E:envelope `canonical_bytes` 稳定,`digest` 与 vector 一致
- Phase F:redaction 投影对 owner / guest 字段集精确匹配 vector 期望值
- Phase G:§1.13 覆盖矩阵无 `not_executed`

## Edge cases / sub-tests

- **E9.1 vector version skew**:harness 加载一个 `protocol_version = "0.9"` 的旧 vector,POST `.../encode` → soland 端点必须拒绝 (`unsupported_vector_version`),不能用 v1 canonicalizer 默认处理
- **E9.2 unknown vector_id 优雅降级**:harness POST `{ vector_id: "ak.vector.encoding.bogus.v1", input: {...} }` → soland 端点返回 `unknown_vector_id` (HTTP 4xx),不应静默执行默认 canonicalizer 然后假装 pass
- **E9.3 vector mismatch 时输出 diff**:在 spec §1.6 vector 输入里故意改一个字段值,断言 harness 报告中 `actual.digest !== expected.digest`,并把 `actual_canonical_json` 与 `expected_canonical_json` 同时写到 step screenshot / artifact,便于人工 diff
- **E9.4 redaction 跨服务器一致**:把 §3 vector 同时 POST 给 soland-alpha 与 soland-beta (若 `hasDualSoland()` 为 true),两边投影必须 byte-equal — 这条只在 dual-soland topology 下跑,否则 skip
- **E9.5 large vector 流式**:`ak.vector.encoding.event_digest.v1` 的输入 payload 超过 1MB 时,canonicalizer 也必须产出稳定 digest (避免 streaming buffer 边界 bug)

后两条建议拆成独立的小 spec(`conformance/encoding-vectors.federation`、`conformance/encoding-vectors.large-payload`),保持主 scenario 紧凑。

## Implementation notes

- **soland 缺口**:`/_arkret/_conformance/{encode,sign,hlc-merge,cursor,envelope,redact}` 端点目前**未实现**。当前 conformance 只跑在 Rust 侧 (`cotest/src/conformance/encoding.rs`、`...redaction.rs`、`...envelope.rs`) 的 integration tests,直接调内部 trait,不走 HTTP。本 e2e scenario 的价值正是要把同一组 vector 通过 HTTP 暴露出来,确保 wire-level 一致(避免内部 canonicalizer 与 HTTP layer 之间的 serializer drift)
- **fixture loader**:spec fixture 落在 `arkret-spec/spec/v1/artifacts/fixtures/<vector_id>.json`;harness 可在测试 setup 阶段一次性读入,挂在 `test.use({ vectors: ... })` 或顶层 `beforeAll` 里。Rust 侧已有 `cotest/tests/fixtures/*.json` 的 loader 范式可参考,但 e2e 侧要重写为 TS
- **signing key 注入**:Phase B 用的是 alice 的 dev session signing key,通过 `issueDevSession` 拿到 token 后,从 coauth 拉 actor 的 public key (`GET /_arkret/self/account/keys`) 用来本地 verify
- **cursor opacity 断言**:不要 hardcode cursor 字节格式;只断言 (a) 同输入稳定 (b) 不含明文 event_id 子串 (c) base64url decode 不报错
- **redaction visibility 投影**:vector 里的 `expected_retained_fields_*` 是 key path 列表,断言用 `lodash.pick` / 手写 walker 把 actual / expected 都裁到同一 key 集合后 diff
- **no new helper**:用现有 `request` fixture + `ensureRegistered` / `issueDevSession`;不要新增 `helpers/conformance.ts`,vector loader 放在 spec 文件顶部即可

## 总耗时预估

单次跑约 30-50s(纯 HTTP 调用,无 browser context,§1+§3 vector 总数约 20-30 条,每条 < 200ms)。
