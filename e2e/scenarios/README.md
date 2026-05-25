# Joint E2E Scenarios

按 spec 的功能域组织的 e2e scenario 套件。文件名直接描述内容,**没有顺序号前缀**。

```
e2e/
  scenarios/      # 设计契约(actor / step / 断言 / spec ref)
    authz/        calls/        conformance/  discovery/
    documents/    encryption/   extensions/   federation/
    governance/   harness/      identity/     invites/
    kanban/       messaging/    models/       spaces/
    sync/         workflows/
  tests/          # 同结构,playwright 实现
    authz/        calls/        conformance/  discovery/
    ...           (17 个 domain,一一对应)
  mocks/          # 8 个 mock service,Node.js 单文件
    mock-idp.mjs        mock-email.mjs      mock-witness.mjs
    mock-audit-agent.mjs mock-policy-server.mjs mock-push-gateway.mjs
    mock-applet-registry.mjs mock-tsp-endpoint.mjs
    _shared/keypairs.mjs _shared/inspect.mjs
```

每个 scenario 名(如 `kanban/end-to-end`)同时是 doc 路径、test 路径、与跨引用 token。完整对照见 [catalog.md](catalog.md)。

## 总览

- **57 条 scenarios**(18 个领域),其中
  - **55** 条业务 scenario 与 spec 一一对应(`scenarios/<domain>/<name>.md` ↔ `tests/<domain>/<name>.spec.ts`)
  - **2** 条 harness/probe 专属:[`harness/mocks-selftest`](harness/mocks-selftest.md)、[`spaces/admin-section-route`](spaces/admin-section-route.md)
  - Wave A (G1.T1–T7) 新增的 7 条 scenario(extensions/agent-protocol-interop、sync/service-surface-contract、conformance/{profile-gates,registry-drift,snapshot-query-scalability}、models/{core-object-invariants,morph-schema-migration})均已附带 spec
- **57 个 playwright spec 文件**
- **83 live test / 248 fixme / 15 条件 skip**(条件 skip 出现在 live test 体内或 `describe` 头部,基于运行时的 mock / topology / transport / claim_kind 状态决定是否执行)
- **8 个 mock service**:OIDC IdP / Email 3PID / WebVH witness / Audit agent / Policy server / Push gateway / Applet registry / TSP endpoint
- 数字由 [`scripts/summarize-e2e-coverage.mjs`](../scripts/summarize-e2e-coverage.mjs) 从文件树重算;`--check` 在出现 orphan 或 catalog drift 时返回非零,可挂 CI

## 18 个 domain

| Domain | scenario doc 数 | spec 文件数 |
|---|---:|---:|
| authz | 2 | 2 |
| calls | 1 | 1 |
| conformance | 4 | 4 |
| discovery | 2 | 2 |
| documents | 1 | 1 |
| encryption | 4 | 4 |
| extensions | 3 | 3 |
| federation | 1 | 1 |
| governance | 3 | 3 |
| harness | 1 | 1 |
| identity | 9 | 9 |
| invites | 1 | 1 |
| kanban | 2 | 2 |
| messaging | 4 | 4 |
| models | 4 | 4 |
| spaces | 5 | 5 |
| sync | 4 | 4 |
| workflows | 6 | 6 |
| **合计** | **57** | **57** |

## 设计原则

1. **Spec-contract first** — 每条 fixme 都标了 spec § 引用 + 当前 soland gap。soland 哪天补齐 endpoint,把 `test.fixme` 删掉一个字就激活。
2. **UI 层 + 业务流程** — 每个 scenario 模拟真实多用户业务,不是单页 smoke。例外是 `harness/mocks-selftest`(纯 harness 自检)与 `spaces/admin-section-route`(yougen routing probe),两条都显式标注为 harness/probe-only。
3. **Spec-mirrored 目录** — 按 contrix-spec 的域划分(`identity/`、`encryption/`、`sync/` 等),scenario 路径直接对应 spec 路径,导航零成本。
4. **Mock services 解锁外部依赖** — 8 个 mock 把所有外部依赖(OIDC、email、witness、audit agent、policy server、push gateway、applet registry、TSP endpoint)mock 化,默认不启动,通过 `-StartMocks` 一次拉起。

## Mock services

| 服务 | 文件 | 触发 | helper API |
|---|---|---|---|
| OIDC IdP | [mocks/mock-idp.mjs](../mocks/mock-idp.mjs) | `-StartMockIdp` | `mockIdpBaseUrl()` |
| Email + 3PID | [mocks/mock-email.mjs](../mocks/mock-email.mjs) | `-StartMockEmail` | `mockEmailBaseUrl()` |
| WebVH witness | [mocks/mock-witness.mjs](../mocks/mock-witness.mjs) | `-StartMockWitness` | `mockWitnessBaseUrl()` + `mockWitnessDid()` |
| Audit agent | [mocks/mock-audit-agent.mjs](../mocks/mock-audit-agent.mjs) | `-StartMockAuditAgent` | `mockAuditAgentBaseUrl()` + `mockAuditAgentDid()` |
| Policy server | [mocks/mock-policy-server.mjs](../mocks/mock-policy-server.mjs) | `-StartMockPolicyServer` | `mockPolicyServerBaseUrl()` + `mockPolicyServerDid()` |
| Push gateway | [mocks/mock-push-gateway.mjs](../mocks/mock-push-gateway.mjs) | `-StartMockPushGateway` | `mockPushGatewayBaseUrl()` |
| Applet registry | [mocks/mock-applet-registry.mjs](../mocks/mock-applet-registry.mjs) | `-StartMockAppletRegistry` | `mockAppletRegistryBaseUrl()` + `mockAppletRegistryDid()` |
| TSP endpoint | [mocks/mock-tsp-endpoint.mjs](../mocks/mock-tsp-endpoint.mjs) | `-StartMockTspEndpoint` | `mockTspEndpointBaseUrl()` + `mockTspEndpointVid()` |

`-StartMocks` 一次启动全部 8 个。每个 mock 都是 Node.js 单文件,RS256 / Ed25519 签真 JWT,共享 `mocks/_shared/keypairs.mjs` 与 `mocks/_shared/inspect.mjs`。harness 自检 spec [`harness/mocks-selftest`](harness/mocks-selftest.md) 锁住每个 mock 的契约,任一 mock 实现漂移都会被立刻发现。

## 编排约定

- 一个 scenario 一个 `*.spec.ts`,路径 `tests/<domain>/<name>.spec.ts`,doc 对应 `scenarios/<domain>/<name>.md`
- 唯二例外是 `tests/harness/mocks-selftest.spec.ts` 与 `tests/spaces/admin-section-route.spec.ts`,两条都有同名 scenario doc 并显式标注为 harness/probe-only
- `test.describe.configure({ mode: "serial" })` — actor 之间有时序依赖
- `uniqueUser("<domain>-<short>")` 避免跨 scenario 状态污染
- 关键 phase 末尾 `stepShot()` 留证据
- 暂跑不通的 spec 契约用 `test.fixme()`,正文留 spec § + soland gap 说明
- mock 依赖型 live test 用 `test.skip(!mockXxxBaseUrl(), "...")` 在 setup 阶段优雅跳过
- 跨 scenario 引用按路径,如 `(见 identity/multi-device)`,不用 S# 顺序号

## 运行

```pwsh
# 单服务器、无 mocks
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -RunProfile joint-full

# 单服务器 + 全部 mocks
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -StartMocks -RunProfile joint-full

# 双服务器 + 全部 mocks(最大覆盖)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -DualSoland -StartMocks -RunProfile joint-full

# cotest 本地 dual-soland profile(只跑 federation matrix)
& "D:\Works\contrix-dev\cotest\scripts\run-cotest.ps1" -Profile dual-soland

# 单个领域
& "..." -StartCoauth -Grep "encryption/"

# 单个 scenario
& "..." -StartCoauth -Grep "messaging/triad-collaboration"

# 跑 harness 自检(只在 -StartMocks 下有可执行内容)
& "..." -StartCoauth -StartMocks -Grep "harness/mocks-selftest"
```

## 产物

`artifacts/runs/<ts>/joint-e2e/`:
- `summary.md` / `scenarios.md` — 整体 + scenario 维度
- `junit.xml` — CI 友好结构化结果
- `playwright-report/` — HTML(含 trace/video/failure screenshot)
- `services/` — soland / coauth / yougen / mock-* 进程日志
- `screenshots/` / `diagnostics/`(console + network HAR)
