# Harness — Mock Services Self-Test

> **harness / smoke-only**:本 scenario **不验证 soland / inkson / coauth 业务流程**,只验证 cotest 自带 mock 中 8 类共享基础契约。是 harness 自检层,跑在任何业务 scenario 之前；claim issuer / challenge provider 的业务约束由 `spaces/knock-auto-resolve` 覆盖。

## 目标

通过直接 HTTP 调用这 8 类 mock service,逐条验证它们 `cotest/e2e/mocks/_shared/*.mjs` 文档化的契约形状(端点、状态码、JWT 结构、签名 kid、错误码、`/inspect` 调试 surface);每个 mock 未启动时对应测试通过 `test.skip(!baseUrl, "...")` 自动跳过,而不是失败。本套件的存在意义是:任一业务 scenario 在引用对应 `mockXxxBaseUrl()` 时,都能假设 mock 的协议层契约仍未漂移 — 否则错误源会从"业务 scenario fail"变成"harness 自检 fail",定位成本大幅降低。

不验证:任何 soland / inkson / coauth 业务流程、任何跨 mock 的协作(那是业务 scenario 的事)、mock 与真实第三方服务的兼容性(mock 只追 spec 契约,不追真实 IdP 行为)。

## Spec 锚点

本 scenario 没有直接的 `arkret-spec/` § 锚点;它锚定的是 cotest 自己定义的 mock 协议层,与各业务 scenario 对应:

| Mock | 文件 | 业务 scenario 锚点(被本 mock 解锁的 cotest scenarios) |
|---|---|---|
| OIDC IdP | [`mocks/mock-idp.mjs`](../../mocks/mock-idp.mjs) | identity/onboarding, identity/account-device-auth |
| Email 3PID | [`mocks/mock-email.mjs`](../../mocks/mock-email.mjs) | invites/third-party, identity/onboarding |
| WebVH witness | [`mocks/mock-witness.mjs`](../../mocks/mock-witness.mjs) | harness/mocks-selftest |
| Push gateway | [`mocks/mock-push-gateway.mjs`](../../mocks/mock-push-gateway.mjs) | discovery/notifications |
| Applet registry | [`mocks/mock-applet-registry.mjs`](../../mocks/mock-applet-registry.mjs) | extensions/applet-bridge |
| MIMI facade | [`mocks/mock-mimi-facade.mjs`](../../mocks/mock-mimi-facade.mjs) | extensions/mimi-federation |

本 scenario 覆盖的 7 类 mock 共享 `mocks/_shared/inspect.mjs`(`/inspect` debug surface 风格统一);需要签名的 mock 还共享 `mocks/_shared/keypairs.mjs`(RS256 / Ed25519 keypair 生成与缓存)。

实现锚点:[`tests/harness/mocks-selftest.spec.ts`](../../tests/harness/mocks-selftest.spec.ts) 是本 scenario 的唯一 spec 文件。

## 拓扑

- 0 × soland / coauth / inkson — 本 scenario 完全不依赖业务服务
- 0..8 类本 scenario 覆盖的 mock service — 由 `run-joint-e2e.ps1` 的 `-StartMockXxx` 或 `-StartMocks` 决定启动哪些;未启动的对应测试跳过
- 1 × Playwright `request` fixture — 直接打 mock 的 HTTP 端点,不开 browser context

`scripts/run-joint-e2e.ps1` 的 `-StartMocks` 会启动全部 11 个 mock,而本 scenario 覆盖的 helper `mockXxxBaseUrl()` 在未启动时返回 `undefined`,测试在 setup 阶段就 skip。

## Actors

| 名字 | 角色 | 注册时机 |
|---|---|---|
| Playwright `request` | 唯一调用方;模拟"业务 spec 在 setup 阶段访问 mock 时的 HTTP 行为" | n/a |

本 scenario 没有真实 DID actor:每个测试用一次性 `selftest-${Date.now()}` 标识符,跑完不留状态(mock 自身的 `/inspect` 是只读 debug surface,跨测试无影响)。

## Pre-conditions

- `run-joint-e2e.ps1` 带 `-StartMocks`(或子集 `-StartMockIdp` / `-StartMockEmail` / …),把要测的 mock 拉起并把 `MOCK_<NAME>_BASE_URL` 写到 Playwright 进程的环境变量里
- `helpers/env.ts` 的 `mockXxxBaseUrl()` 在 mock 未启动时返回 `undefined`,测试用 `test.skip(!baseUrl, "<mock> not started for this run")` 优雅跳过
- 不需要 soland、coauth、inkson 任何一项;本套件可以单独跑(`-Grep "harness/mocks-selftest"`)做 mock 冒烟

## Steps

每个 mock 一个独立 `test(...)`,失败互不影响。

1. **mock-idp**:`POST /scenarios` 注入一对 (login_hint, sub, email) → PKCE 走 `GET /authorize` → `POST /token` → 断言 `id_token.sub/email` 与注入值一致;再注入 `force_error: "unauthorized_client"` 走错误路径 → `POST /token` 必须返回 4xx + `error="unauthorized_client"`;最后 `GET /inspect` 至少有两条 scenarios 行。
2. **mock-email**:`POST /mock/email/verification/send` 写一个 TTL=1s 的过期 token → 等 1.5s → `POST /mock/email/verification/claim` 必须返回 410 + `error="token_expired"`;再发一个 TTL=600s 的好 token,`claim` 必须返回 200 + `binding_proof` + `token_commitment.startsWith("sha256:")`;`/inspect` 必有一条 `consumed=true`。
3. **mock-witness**:`POST /mock/witness/sign` 连发 (h1, n=1, fresh `entry_timestamp`) 与 (h2, n=2, prev=h1, fresh `entry_timestamp`) → 200;再发 (h3, n=3, prev=WRONG) → 409 + `error="prev_entry_hash_mismatch"`;skip n=4 直接发 n=5 → 409 + `error="non_monotonic_entry_number"`;发一个 `entry_timestamp` 过旧的 → 422 + `error="entry_timestamp_stale"`;`/inspect` 中该 scid 的 `last_entry_number === 2`。
   另有一条独立 live test 遍历配置的 witness quorum，确认每个实例都暴露与配置 DID 一致的健康 policy。
4. **mock-push-gateway**:`DELETE /scenarios` 清空 → `POST /_arkret/edge/push/register-device` 注册 pusher → `POST /_arkret/edge/push/notify` 收到 `delivered=true` + `delivery_receipt` 是 3 段 JWT;再 `notify` 一条 `blind_wake: true` 且 payload 含明文 body → 必须返回 4xx/422(blind-wake 模式禁明文键);`/mock/push/inbox` 至少有一条历史;`/jwks` kid 为 `mock-push-gateway-key-1`。
5. **mock-applet-registry**:`POST /sign-package` 生成 controller-signed `ak.schema.applet_package.v1` → 返回 `package_digest`、`applet_package.bot_actor_id`、`proof.payload_digest` 与可提交到 soland identity store 的 `service_id_document`;`GET /identity` 返回 registry 自身 DID。ghost 生成通过 soland 的 typed applet ingress 在 applet-bridge e2e 中覆盖。
6. **mock-mimi-facade**:`DELETE /scenarios` 清空 → `POST /mock/mimi/join-requests` 预置 `bob_mimi` join → `POST /mock/mimi/approve` 返回 realm-scoped `did:pairwise:`;`POST /mock/mimi/outbound` happy path 返回 `delivered`;设置 `unavailable=true` 后 outbound 返回 503 + `status="deferred"`;`POST /mock/mimi/inbound` 对未知 `content_kind=m.location.share.live` 返回 202 + `status="quarantined"` + `unknown_content_kind`;`/inspect` 至少记录 join、approval、outbound、inbound、quarantine。

## Observable assertions(合并清单)

- 每个测试在对应 mock 未启动时 `skipped`,不污染整体 pass rate
- 8 条 live tests / 7 类契约 invariant(详见上面 Steps，witness 单实例与 quorum 各占一条 test):
  - mock-idp 的 PKCE happy path + force_error matrix
  - mock-email 的 TTL 过期 → 410 / happy path → binding_proof + `sha256:` 前缀的 `token_commitment`
  - mock-witness 的 chain 链头单调、prev hash 一致、stale timestamp 拒绝
  - mock-push-gateway 的 register/notify/blind-wake 拒明文/inbox 可读 / jwks
  - mock-applet-registry 的 bot DID `did:web:applet.` 命名 / ghost DID `did:web:ghost.` 命名 / accountability 回指 bot
  - mock-mimi-facade 的 bob_mimi join / pairwise DID / fallback deferred / unknown content quarantine

## Implementation notes

- **不要把 harness 自检放进任何业务 scenario 的 setup**:本套件只在 `tests/harness/mocks-selftest.spec.ts` 跑,业务 scenario 直接信任 helper 的返回值;否则一个 mock 漂移会让 N 个业务 scenario 同时 fail,排查反而更难
- **`test.skip(!baseUrl, ...)` 必须在 `test(...)` 体内第一行**,不要挪到 `beforeAll` — Playwright 会把 `test.skip` 标记为 skipped 而非 failed,只有写在 test 体内才生效
- **mock 实现升级时同步更新本 spec**:任何 mock 加端点、改状态码、改错误码、改 kid,必须同步改 `mocks-selftest.spec.ts`,这是 "spec drift 拦截器" 的核心价值
- **`/scenarios` reset 顺序**:某些 mock 的注入是累积的(例如 push-gateway),测试开头必须 `DELETE /scenarios` 清空,否则前一次 run 残留会影响断言
- **selftest stamp 用 `Date.now()`**:避免跨 run 撞 scid / pusher_id / namespace;同一 run 内多个 mock 之间也用同一个 stamp 没问题,因为他们的命名空间互不重叠

## 总耗时预估

单次跑 9 条测试约 5-12s(全部纯 HTTP,无 browser context,中间有一次 mock-email 强制 sleep 1.5s 等 TTL 过期);如果只启动部分 mock,跳过的测试 < 100ms 各计。
