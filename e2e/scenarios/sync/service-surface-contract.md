# Sync — Service Surface Contract (describe / errors / pagination / idempotency)

## 目标

通过 HTTP/JSON binding 直接打 soland 和 coauth 暴露的 `/_cokret/describe` 与相关写/读 endpoint,验证 spec `sync/service-surface.md` §3 与 §3.0 所要求的 **canonical `ServiceDescribe` shape + claim-level partition**,以及 `sync/api-conventions.md` §5 / §6 / §7 / §11 中的 **standard error envelope、幂等键、opaque cursor 分页、unsupported feature fail-closed**。本 scenario 是 v1 core service surface 的 wire-level conformance 闭环:它不验证业务语义(Realm/Event/Capability 在别处),只验证“服务面把自己说清楚、把错误说清楚、把分页/幂等/不支持说清楚”。

不验证:profile claim 的真实性(见 `conformance/profile-gates`)、encoding/redaction vector(见 `conformance/encoding-vectors`)、federation transport(见 `sync/transport-negotiation`)、registry drift(见 `conformance/registry-drift`)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/sync/service-surface.md` §2.3 — 接口必须天然支持幂等重试
- `arkret-spec/spec/v1/zh/sync/service-surface.md` §2.4 — 服务必须公布自己的实现 profile
- `arkret-spec/spec/v1/zh/sync/service-surface.md` §3 — `GET /_cokret/describe` canonical shape
- `arkret-spec/spec/v1/zh/sync/service-surface.md` §3.0 — Describe response claim levels(`supported_operations` / `implemented_features` / `claimed_profiles` / `verified_profiles` / `experimental_features` / `compat_surfaces` / `development_mode`)
- `arkret-spec/spec/v1/zh/sync/service-surface.md` §17 — 线级互操作要求(describe 必填字段、`verified_profiles` 与 `development_mode` 约束、claim-level partition)
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` §4 — 标准成功响应 envelope
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` §5 — 标准错误响应(`ok=false`、`error.code`、`message`、`retry_after_ms`、`details`、`request_id`)
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` §5.1 — 标准错误码与 `unsupported_feature` / `unsupported_event_kind` 区分
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` §5.2 — 未知路径 `404 unrecognized_endpoint` / 错误方法 `405 method_not_allowed`,MUST 使用统一错误响应
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` §6 — 幂等(`Idempotency-Key` / `event_id` / `request_id`、`duplicate_conflict` 语义)
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` §7 — Cursor opaque token、`ck:cursor:<base64url>`、`invalid_param` / `cursor_expired`、TTL 上限
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` §7.1 — 列表分页响应形状(`items` / `next_cursor` / `has_more`)
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` §11 — 版本与 feature discovery
- `arkret-spec/spec/v1/zh/sync/service-api-schema.mdx` §2 — 统一约定 canonical `ServiceDescribe` shape 必填字段集
- `arkret-spec/spec/v1/zh/sync/service-api-schema.mdx` §2.1 — `operation_id` 分组(`ck.server.*` / `ck.events.*` / `ck.sync.*` 等)
- `arkret-spec/spec/v1/artifacts/schemas/service-describe.schema.json` — `ck.schema.service_describe.v1` wire schema
- `arkret-spec/spec/v1/artifacts/registry/error-code-registry.json` — `unrecognized_endpoint` / `method_not_allowed` / `unsupported_feature` / `duplicate_conflict` / `invalid_param` / `cursor_expired` canonical 定义
- 相关实现:`soland/src/routing/system/describe.rs`(soland describe handler)、`coauth/crates/backend/src/handlers/arkret.rs`(coauth `server_describe`)、`soland/src/wire.rs`(claim-level partition)

## 拓扑

- 1 × soland (principal server) — `solandBaseUrl()`;暴露 `/_cokret/describe`、`/_cokret/self/account/*`、`/_cokret/self/snapshot/*` 与 `/_cokret/self/events/*` namespace
- 1 × coauth (auth server) — `coauthBaseUrl()`;同样暴露 canonical `/_cokret/describe`,但 `service_type=auth_server`,不 claim `principal_server` profile
- 1 × harness — Playwright `request` fixture,纯 HTTP;无 browser context

`coauthBaseUrl()` 在某些 run profile 下返回 `undefined`(即未配置 `COTEST_COAUTH_BASE_URL`)。本 scenario 中所有 coauth 子断言 MUST 在该值缺失时通过 `test.skip(!coauthBaseUrl(), ...)` 跳过,不得让 suite 在单服务器 profile 上 fail。

## Actors

| 名字 | DID | 在 service-surface-contract 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-ssc-<uuid>.example` | 写操作发起者;Phase D 用她的 dev token 重复提交带 `Idempotency-Key` 的写请求;Phase C 用她的可见性范围列分页 | 测试开始前 |
| harness | n/a (Playwright `request`) | 直接拼 HTTP request、断言响应 envelope、解码 cursor base64url | n/a |

不需要第二个 actor:本 scenario 不涉及跨用户授权;`unsupported_feature` 路径只需要 alice 的 token + 一个声明不支持的 feature。

## Pre-conditions

- `alice` 已通过 `ensureRegistered` 在 soland 注册
- `alice` 通过 `issueDevSession` 拿到 soland dev session token(coauth bearer 通常不必,因为 describe 是无认证 GET;但写路径需要 alice 的 soland token)
- soland 的 `claimed_profiles` 至少含 `ck.profile.core_event_store.v1`(由 `soland/src/wire.rs` 默认写入)
- coauth 的 `claimed_profiles` 至少含 `ck.profile.auth_server.v1` 或等价 auth-server profile;**MUST NOT** claim canonical identity registry / principal server profile(见 G3.C3)
- `development_mode=true` 时,两个服务的 `verified_profiles` MUST 为空数组(spec §3.0 第 2 条)

## Steps

### Phase A — `server/describe` happy path on soland + coauth(§3 / §3.0 / §17)

1. `GET ${solandBaseUrl()}/_cokret/describe`(无认证)
2. 断言:
   - HTTP 200,`Content-Type: application/json`
   - body 含 spec §3 必填字段:`service_did`、`trust_domain`、`service_type`、`protocol_version`、`supported_profiles`、`supported_operations`、`supported_bindings`(数组,不是单数 `binding`)、`supported_features`、`auth_metadata`、`limits`、`plaintext_visibility`、`development_mode`
   - `service_type === "principal_server"`(soland 是 principal server,见 `service-surface.md` §2.5)
   - `protocol_version === "1.0"`
   - `supported_bindings[0].kind === "http_json"`、`supported_bindings[0].base_url` 是 `${solandBaseUrl()}/_cokret` 或等价
   - **§3.0 claim-level partition**:`implemented_features` / `claimed_profiles` / `verified_profiles` / `experimental_features` / `compat_surfaces` 全部存在且是数组
   - `claimed_profiles[*].claim_kind === "self_claimed"`(self-claim 不得直接写 `cotest_verified`)
   - 若 `development_mode === true`,则 `verified_profiles.length === 0`(spec §3.0 第 2 条 dev fail-closed)
   - `supported_operations` 至少含 `ck.server.query.describe` 与 `ck.self.events.command.submit`(spec §4.2 + service-api-schema §2.1 `/events POST`)
3. `GET ${coauthBaseUrl()}/_cokret/describe`(仅当 `coauthBaseUrl()` 已配置)
4. 断言:
   - HTTP 200,JSON
   - `service_type === "auth_server"`(spec §3 服务类型命名规则)
   - `claimed_profiles` 是数组,且没有任何 entry 的 `profile_id` 等于 `ck.profile.identity_registry.v1`(coauth MUST NOT 假 claim identity registry — G3.C3)
   - `auth_metadata.account_authority.gate_account_base` 是绝对 URL,且 `auth_metadata.methods[]` 非空(coauth 是 Account Authority)
   - 同样 §3.0 六个 claim-level 字段都存在
5. **Cross-server invariant**:两边的 `protocol_version` 必须一致(`"1.0"`)且 `trust_domain` 命名空间满足 `ck:trust_domain:` 前缀

### Phase B — Standard error envelope(§5 / §5.2)

6. `GET ${solandBaseUrl()}/_cokret/self/__definitely_does_not_exist__/probe`(故意打不存在的 endpoint)
7. 断言:
   - HTTP 404
   - body 形如 `{ ok: false, error: { code, message, ... }, request_id? }`
   - `error.code === "unrecognized_endpoint"`(spec §5.2)
   - response **MUST NOT** 是 HTML、纯文本框架错误或栈信息
   - `error.message` 非空字符串(供开发者诊断,但客户端不依赖)
8. `POST ${solandBaseUrl()}/_cokret/describe`(已知路径 + 错误 method)
9. 断言:
   - HTTP 405
   - `error.code === "method_not_allowed"`
   - response header **SHOULD** 含 `Allow: GET` 或类似
10. 同样对 coauth 重复 step 6–9(`test.skip(!coauthBaseUrl(), ...)` 守门)
11. **Cross-cutting invariant**:两个错误响应都符合 `api-conventions.md` §5 的 envelope schema —— `ok=false`、`error.code` 是已注册标准 code、不泄露内部栈/路径细节

### Phase C — Opaque pagination cursor(§7 / §7.1)

12. `harness` 通过 alice token 在 soland 上播种 ≥5 条可被 list 的 event(用 `POST /_cokret/self/events` 写最小事件,或调一个已存在的 list endpoint 比如 `/_cokret/self/authz/invites`)
13. `GET ${solandBaseUrl()}/_cokret/self/events?limit=2`(或等价 list endpoint;`limit` 故意小于总数以强制分页)
14. 断言响应形状(api-conventions §7.1):
    - `items` 是数组,长度 ≤ 2
    - `next_cursor` 是字符串,匹配 `^ck:cursor:[A-Za-z0-9_-]+$`(opaque base64url,见 §7)
    - `has_more === true`(因为播种了 ≥5 条)
15. 用 `next_cursor` 取第二页:`GET .../events?limit=2&after=${next_cursor_1}`
16. 用第二页的 `next_cursor` 取第三页
17. 断言:
    - 三页 `items` 的 ID 集合两两不相交(no overlap)
    - 三页 union 至少覆盖 step 12 播种的全部 ID(no gap)
    - 任意页的 cursor `base64url_decode(cursor.slice("ak:cursor:".length))` 不抛错,且 decoded 字节中**不含**任何 event_id / item id 的明文子串(opacity:客户端不得据此推断排序/权限)
18. **Cursor expiry 子断言**:把 step 14 的 `next_cursor` 篡改一个字符(保持 base64url 合法),POST 给 list endpoint
19. 断言:`error.code ∈ { "invalid_param", "cursor_expired" }` 且 HTTP 4xx;**不得** 静默从头返回 page 1

### Phase D0 — Event ID replay(§6)

20. 构造最小 `POST /_cokret/self/events` envelope，记录 `event_id`
21. 用完全相同的 envelope 重放一次
22. 断言:
    - 第二次返回 duplicate/no-op 语义，`event_id` 与首次一致
    - 事件列表中该 `event_id` 只出现一次
23. 用同一个 `event_id` 但修改 canonical body 的 envelope 再提交一次
24. 断言:
    - HTTP 409
    - `error.code === "duplicate_conflict"`
    - drift body 没有落入可见事件列表

### Phase D — Idempotency key(§6)

25. 构造写请求 body B1(可以是最小 `POST /_cokret/self/events` envelope,或一个不需要复杂 prerequisite 的 op)
26. `POST ... ` with `Idempotency-Key: ssc-${uuid}` + body B1 → response R1(HTTP 2xx,带 `event_id` 或 `request_id`)
27. **同样的** `Idempotency-Key` + **同样的** canonical body B1 → response R2
28. 断言:
    - R2 与 R1 在 `event_id` / `request_id` / accepted 状态等关键字段上一致(spec §6:相同幂等键 + 相同 body → 与首次语义等价)
    - 服务端**没有**因第二次提交产生新事件(可以通过 list endpoint 或 frontier 旁路验证)
29. **不同 body 同键** 反例:同样的 `Idempotency-Key` + 修改一个字段的 body B2 → response R3
30. 断言:
    - `error.code === "duplicate_conflict"`(spec §6 第 2 条)
    - HTTP 409

### Phase E — Unsupported feature fail-closed(§5.1)

31. 从 Phase A 的 describe 响应里取 `supported_features` 与 `implemented_features`,选一个**两者都不在**的 feature 标识(例如 `ck.feature.mimi_room_passthrough.v1` 在普通 dev soland 上不出现)
32. 构造一个 `POST /_cokret/self/events` 请求,在 envelope 的 `requirements.features[]` 字段里声明依赖该 feature
33. 断言:
    - HTTP 4xx
    - `error.code === "unsupported_feature"`(spec §5.1:该 code 专门用于 `Event.requirements.features[]` 命中实现未声明 feature)
    - **MUST NOT** 是 `unsupported_event_kind`(spec §5.1 第 4 条:二者不得互相替代)
    - **MUST NOT** 是普通 `schema_violation`(实现不得用泛 code 掩盖 fail-closed)
    - 服务端没有把 event 写入(用 frontier 或 list 反向验证)

## Observable assertions(合并清单)

- Phase A:两个 service 的 `/server/describe` 返回 spec §3 + §3.0 全部必填字段;`service_type` 正确;`claim_kind === "self_claimed"`;dev mode `verified_profiles` 为空;coauth 不 claim identity registry
- Phase B:未知路径 → 404 `unrecognized_endpoint`;错误 method → 405 `method_not_allowed`;两者都符合 §5 错误 envelope,不返回 HTML/栈信息
- Phase C:list 响应符合 §7.1 形状;`cursor` 是 `ck:cursor:<base64url>`;多页无 overlap / 无 gap;cursor 不可解析出明文 ID;篡改 cursor → `invalid_param` / `cursor_expired`
- Phase D0:`event_id` 同 envelope 重放 → duplicate/no-op;同 `event_id` 不同 body → `duplicate_conflict` / 409;事件只投影一次
- Phase D:同键同 body → 与首次等价;同键不同 body → `duplicate_conflict` / 409;副作用只发生一次
- Phase E:`requirements.features[]` 引用未实现 feature → `unsupported_feature` / 4xx;event 未落库;不被泛 code 替代

## Edge cases / sub-tests

- **E1 profile partition leak**:claim_kind 不混淆 — `claimed_profiles[*].claim_kind` MUST 全部是 `"self_claimed"`;任何 `cotest_verified` 条目 MUST 只出现在 `verified_profiles` 数组中(spec §3.0 第 2 + 4 条);当前已 live,并在 `verified_profiles` 非空时校验 cotest artifact 元数据与 profile_id 分区
- **E2 dev_mode invariant**:`development_mode === true` + 非空 `verified_profiles` 是 invalid describe(SDK / conformance tooling 必须 fail);harness 不能模拟服务端违规,所以以 fixme 钉住 spec 合约,等 production-mode CI 落地后做 live 反例测试
- **E3 cursor TTL 上限**:stream cursor TTL MUST ≤ 7 天(api-conventions §7 TTL 硬上限);本测试无法在 e2e 内等 7 天,但可以 fixme 钉住 spec,后续在 cotest fixture 里塞一个 8 天前签发的 cursor 验证 `cursor_expired`
- **E4 idempotency cross-actor 隔离**:同一 `Idempotency-Key` 由 bob 重复提交 MUST NOT 命中 alice 的缓存项(否则可被用作 oracle);fixme 钉住,等 G3.S0 / multi-user soland scaffold 稳定后 live
- **E5 unsupported critical extension**:与 `unsupported_feature` 平行,`requirements.critical_extensions[]` 引用未实现且 `fail_closed=true` 的 extension MUST 也用 `unsupported_feature` code(spec §5.1 同一条);当前已由 Phase E2 live 覆盖

## Implementation notes

- **soland describe 已实现**:`soland/src/routing/system/describe.rs` + `soland/src/wire.rs` 已经写入 `claimed_profiles` / `verified_profiles` / `implemented_features` 等字段;Phase A 在 soland 侧可以**直接 live**
- **coauth describe 已实现**:`coauth/crates/backend/src/handlers/arkret.rs::server_describe` 同样按 canonical shape 返回;Phase A 在 coauth 侧也可以 live(但需 `test.skip(!coauthBaseUrl(), ...)`)
- **Phase C list endpoint 已 live**:当前用 `/_cokret/self/events?after=...` 覆盖 §7.1 pagination shape、opaque cursor、tamper reject、gap-free / non-overlap 分页;`/sync/operations` 不存在不再阻塞本场景
- **event_id 幂等已 live**:soland 当前依赖 `event_id` 幂等(spec §4.2);同 envelope replay 与同 `event_id` drift conflict 已由 Phase D0 覆盖
- **Idempotency-Key header 已在 events write live**:Phase D 覆盖 `POST /_cokret/self/events` 的同键同 body replay 与同键不同 body `duplicate_conflict`;其它 write endpoint 的一致性可另开场景
- **`unsupported_feature` 触发条件已 live**:Phase E 通过 `Event.requirements.features[]` 注入未声明 feature,Phase E2 通过 `requirements.critical_extensions[]` 注入 fail-closed extension,断言 soland 在 envelope validation 阶段返回 `unsupported_feature`
- **no new helper**:用现有 `request` fixture + `ensureRegistered` / `issueDevSession` + `solandBaseUrl()` / `coauthBaseUrl()`;不要新增 helper

## 总耗时预估

单次跑约 30–60s:当前 Phase A/B/C/D/E/E2 均已 live,会启动 soland 并执行 describe、error envelope、pagination、idempotency 与 fail-closed 写入验证。E2 dev-mode 反例、E3 cursor TTL 过期、E4 cross-actor Idempotency-Key 隔离仍是后续边界。
