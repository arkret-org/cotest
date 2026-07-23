# Joint E2E Scenarios

按 spec 的功能域组织的 e2e scenario 套件。文件名直接描述内容,**没有顺序号前缀**。

```
e2e/
  scenarios/      # 设计契约(actor / step / 断言 / spec ref)
    authz/        calls/        conformance/  discovery/
    encryption/   extensions/   federation/
    governance/   harness/      identity/     invites/
    joint/        kanban/       messaging/    models/
    spaces/       sync/         workflows/
  tests/          # 同结构,playwright 实现
    authz/        calls/        conformance/  discovery/
    ...           (19 个 domain,一一对应)
  mocks/          # 10 个 mock service,Node.js 单文件
    mock-idp.mjs        mock-email.mjs      mock-witness.mjs
    mock-policy-server.mjs mock-push-gateway.mjs
    mock-applet-registry.mjs mock-tsp-endpoint.mjs mock-mimi-facade.mjs
    mock-claim-issuer.mjs mock-challenge-provider.mjs
    _shared/keypairs.mjs _shared/inspect.mjs
```

每个 scenario 名(如 `kanban/end-to-end`)同时是 doc 路径、test 路径、与跨引用 token。完整对照见 [catalog.md](catalog.md)。

## 总览

- **72 条 scenarios**(19 个领域),其中
  - **70** 条业务 scenario 与 spec 一一对应(`scenarios/<domain>/<name>.md` ↔ `tests/<domain>/<name>.spec.ts`)
  - **2** 条 harness/probe 专属:[`harness/mocks-selftest`](harness/mocks-selftest.md)、[`spaces/admin-section-route`](spaces/admin-section-route.md)
  - `workflows/incident-response`、dual-soland federation、history visibility、MIMI facade harness 等新增 coverage 均已登记到 catalog
- **88 个 playwright spec 文件**
- **398 live test / 42 fixme / 148 条件 skip**(条件 skip 出现在 live test 体内或 `describe` 头部,基于运行时的 mock / topology / transport / claim_kind 状态决定是否执行)
- **10 个 mock service**:OIDC IdP / Email 3PID / WebVH witness / Policy server / Push gateway / Applet registry / TSP endpoint / MIMI facade / Claim issuer / Challenge provider

## 19 个 domain

| Domain | scenario doc 数 | spec 文件数 | verified | promised | fixme | skip |
|---|---:|---:|---:|---:|---:|---:|
| authz | 2 | 2 | 9 | 10 | 1 | 3 |
| calls | 7 | 7 | 18 | 18 | 0 | 0 |
| conformance | 4 | 6 | 36 | 36 | 0 | 3 |
| discovery | 3 | 3 | 7 | 10 | 3 | 11 |
| encryption | 6 | 6 | 27 | 32 | 5 | 15 |
| events | 1 | 1 | 1 | 1 | 0 | 0 |
| extensions | 2 | 3 | 12 | 15 | 3 | 2 |
| federation | 2 | 3 | 18 | 18 | 0 | 5 |
| governance | 5 | 5 | 23 | 30 | 7 | 3 |
| harness | 1 | 1 | 9 | 9 | 0 | 9 |
| identity | 9 | 15 | 80 | 97 | 17 | 50 |
| invites | 1 | 2 | 8 | 8 | 0 | 1 |
| joint | 1 | 5 | 5 | 5 | 0 | 3 |
| kanban | 3 | 3 | 19 | 19 | 0 | 7 |
| messaging | 4 | 4 | 39 | 39 | 0 | 6 |
| models | 4 | 4 | 18 | 21 | 3 | 1 |
| spaces | 6 | 6 | 26 | 26 | 0 | 6 |
| sync | 5 | 6 | 26 | 29 | 3 | 7 |
| workflows | 6 | 6 | 17 | 17 | 0 | 16 |
| **合计** | **72** | **88** | **398** | **440** | **42** | **148** |

## 设计原则

1. **Spec-contract first** — 每条 fixme 都标了 scenario 引用 + 当前 owner gap。删除 `.fixme` 前必须走 [`docs/fixme-promotion-checklist.md`](../../docs/fixme-promotion-checklist.md)。
2. **UI 层 + 业务流程** — 每个 scenario 模拟真实多用户业务,不是单页 smoke。例外是 `harness/mocks-selftest`(纯 harness 自检)与 `spaces/admin-section-route`(inkson routing probe),两条都显式标注为 harness/probe-only。
3. **Spec-mirrored 目录** — 按 arkret-spec 的域划分(`identity/`、`encryption/`、`sync/` 等),scenario 路径直接对应 spec 路径,导航零成本。
4. **Mock services 解锁外部依赖** — 10 个 mock 把已登记协议的外部依赖(OIDC、email、witness、policy server、push gateway、applet registry、TSP endpoint、MIMI facade、claim issuer、challenge provider)mock 化,默认不启动,通过 `-StartMocks` 一次拉起。Audit Applet 不在已登记跨服务 transport 前提下伪造 identity / invite / inbox 路由。

## Mock services

| 服务 | 文件 | 触发 | helper API |
|---|---|---|---|
| OIDC IdP | [mocks/mock-idp.mjs](../mocks/mock-idp.mjs) | `-StartMockIdp` | `mockIdpBaseUrl()` |
| Email + 3PID | [mocks/mock-email.mjs](../mocks/mock-email.mjs) | `-StartMockEmail` | `mockEmailBaseUrl()` |
| WebVH witness | [mocks/mock-witness.mjs](../mocks/mock-witness.mjs) | `-StartMockWitness` | `mockWitnessBaseUrl()` + `mockWitnessDid()` |
| Policy server | [mocks/mock-policy-server.mjs](../mocks/mock-policy-server.mjs) | `-StartMockPolicyServer` | `mockPolicyServerBaseUrl()` + `mockPolicyServerDid()` |
| Push gateway | [mocks/mock-push-gateway.mjs](../mocks/mock-push-gateway.mjs) | `-StartMockPushGateway` | `mockPushGatewayBaseUrl()` |
| Applet registry | [mocks/mock-applet-registry.mjs](../mocks/mock-applet-registry.mjs) | `-StartMockAppletRegistry` | `mockAppletRegistryBaseUrl()` + `mockAppletRegistryDid()` |
| TSP endpoint | [mocks/mock-tsp-endpoint.mjs](../mocks/mock-tsp-endpoint.mjs) | `-StartMockTspEndpoint` | `mockTspEndpointBaseUrl()` + `mockTspEndpointVid()` |
| MIMI facade | [mocks/mock-mimi-facade.mjs](../mocks/mock-mimi-facade.mjs) | `-StartMockMimiFacade` | `mockMimiFacadeBaseUrl()` + `mockMimiFacadeDid()` / `createMimiFacadeClient()` |
| Claim issuer | [mocks/mock-claim-issuer.mjs](../mocks/mock-claim-issuer.mjs) | `-StartMockClaimIssuer` | `mockClaimIssuerBaseUrl()` + `mockClaimIssuerDid()` |
| Challenge provider | [mocks/mock-challenge-provider.mjs](../mocks/mock-challenge-provider.mjs) | `-StartMockChallengeProvider` | `mockChallengeProviderBaseUrl()` + `mockChallengeProviderDid()` |

`-StartMocks` 一次启动全部 10 个。每个 mock 都是 Node.js 单文件,需要签名的 mock 使用 RS256 / Ed25519 真签名 JWT,全部共享 `mocks/_shared/inspect.mjs` 的 debug surface。harness 自检 spec [`harness/mocks-selftest`](harness/mocks-selftest.md) 锁住其中 8 类共享基础契约；claim issuer / challenge provider 的业务约束由 `spaces/knock-auto-resolve` 覆盖。

## 编排约定

- 一个 scenario 一个 `*.spec.ts`,路径 `tests/<domain>/<name>.spec.ts`,doc 对应 `scenarios/<domain>/<name>.md`
- 唯二例外是 `tests/harness/mocks-selftest.spec.ts` 与 `tests/spaces/admin-section-route.spec.ts`,两条都有同名 scenario doc 并显式标注为 harness/probe-only
- `test.describe.configure({ mode: "serial" })` — actor 之间有时序依赖
- `uniqueUser("<domain>-<short>")` 避免跨 scenario 状态污染
- 关键 phase 末尾 `stepShot()` 留证据
- 暂跑不通的 spec 契约用 `test.fixme()`,正文留 `@blocking-on`、`@user-promise`、`@expected-live-by`
- mock 依赖型 live test 用 `test.skip(!mockXxxBaseUrl(), "...")` 在 setup 阶段优雅跳过
- 跨 scenario 引用按路径,如 `(见 identity/multi-device)`,不用 S# 顺序号

## 运行

```pwsh
# 单服务器、无 mocks
& "D:\Works\arkret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -RunProfile joint-full

# 单服务器 + 全部 mocks
& "D:\Works\arkret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -StartMocks -RunProfile joint-full

# 双服务器 + 全部 mocks(最大覆盖)
& "D:\Works\arkret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -DualSoland -StartMocks -RunProfile joint-full

# cotest 本地 dual-soland profile(只跑 federation matrix)
& "D:\Works\arkret\cotest\scripts\run-cotest.ps1" -Profile dual-soland

# 单个领域
& "..." -StartCoauth -Grep "encryption/"

# 单个 scenario
& "..." -StartCoauth -Grep "messaging/triad-collaboration"

# 跑 harness 自检(只在 -StartMocks 下有可执行内容)
& "..." -StartCoauth -StartMocks -Grep "harness/mocks-selftest"

# 只验证 MIMI facade mock/helper
& "..." -StartMockMimiFacade -Grep "mock-mimi-facade"
```

## 产物

`artifacts/runs/<ts>/joint-e2e/`:
- `summary.md` / `scenarios.md` — 整体 + scenario 维度
- `junit.xml` — CI 友好结构化结果
- `playwright-report/` — HTML(含 trace/video/failure screenshot)
- `services/` — soland / coauth / inkson / mock-* 进程日志
- `screenshots/` / `diagnostics/`(console + network HAR)
