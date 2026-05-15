# Joint E2E Scenarios

按 spec 的功能域组织的 e2e scenario 套件。文件名直接描述内容,**没有顺序号前缀**。

```
e2e/
  scenarios/      # 设计契约(actor / step / 断言 / spec ref)
    identity/    encryption/    messaging/    spaces/
    kanban/      documents/     calls/        federation/
    authz/       discovery/     governance/   sync/
    invites/
  tests/          # 同结构,playwright 实现
    identity/    encryption/    ...
```

每个 scenario 名(如 `kanban/end-to-end`)同时是 doc 路径、test 路径、与跨引用 token。完整目录见 [catalog.md](catalog.md)。

## 总览

- **31 条 scenarios**(13 个领域)
- **206 个 playwright tests**(~30 live + ~176 fixme)
- **3 个 mock service**:OIDC IdP / email + 3PID / WebVH witness

## 设计原则

1. **Spec-contract first** — 每条 fixme 都标了 spec § 引用 + 当前 soland 缺口。soland 哪天补齐 endpoint,把 `test.fixme` 删掉一个字就激活。
2. **UI 层 + 业务流程** — 每个 scenario 模拟真实多用户业务,不是单页 smoke。
3. **Spec-mirrored 目录** — 按 contrix-spec 的域划分(`identity/`、`crypto-media/`、`sync/` 等),scenario 路径直接对应 spec 路径,导航零成本。
4. **Mock services 解锁外部依赖** — OIDC / email / witness 服务 mock 化。

## Mock services

| 服务 | 文件 | 触发 | helper API |
|---|---|---|---|
| OIDC IdP | [mocks/mock-idp.mjs](../mocks/mock-idp.mjs) | `-StartMockIdp` | `mockIdpBaseUrl()` |
| Email + 3PID | [mocks/mock-email.mjs](../mocks/mock-email.mjs) | `-StartMockEmail` | `mockEmailBaseUrl()` |
| WebVH witness | [mocks/mock-witness.mjs](../mocks/mock-witness.mjs) | `-StartMockWitness` | `mockWitnessBaseUrl()` + `mockWitnessDid()` |

`-StartMocks` 一次启动全部三个。每个 mock 都是 ~200 行的 Node.js 单文件,RS256 签真 JWT。

## 编排约定

- 一个 scenario 一个 `*.spec.ts`,路径 `tests/<domain>/<name>.spec.ts`,doc 对应 `scenarios/<domain>/<name>.md`
- `test.describe.configure({ mode: "serial" })` — actor 之间有时序依赖
- `uniqueUser("<domain>-<short>")` 避免跨 scenario 状态污染
- 关键 phase 末尾 `stepShot()` 留证据
- 暂跑不通的 spec 契约用 `test.fixme()`,正文留 spec § + soland gap 说明
- 跨 scenario 引用按路径,如 `(见 identity/multi-device)`,不用 S# 顺序号

## 运行

```pwsh
# 单服务器、无 mocks
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -RunProfile joint-full

# 单服务器 + 全部 mocks
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -StartMocks -RunProfile joint-full

# 双服务器 + 全部 mocks(最大覆盖)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -DualSoland -StartMocks -RunProfile joint-full

# 单个领域
& "..." -StartCoauth -Grep "encryption/"

# 单个 scenario
& "..." -StartCoauth -Grep "messaging/triad-collaboration"
```

## 产物

`artifacts/runs/<ts>/joint-e2e/`:
- `summary.md` / `scenarios.md` — 整体 + scenario 维度
- `junit.xml` — CI 友好结构化结果
- `playwright-report/` — HTML(含 trace/video/failure screenshot)
- `services/` — soland / coauth / yougen / mock-* 进程日志
- `screenshots/` / `diagnostics/`(console + network HAR)
