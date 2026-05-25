# Joint E2E 改造任务清单

生成日期: 2026-05-12

状态说明:

- `[x]` 已完成
- `[>]` 正在处理
- `[ ]` 未开始

## Phase 0: 任务拆分和边界确认

- [x] T0.1 梳理当前 `cotest` 的 API/协议测试能力和 UI E2E 缺口，形成 `_report.md`。
- [x] T0.2 将联合 E2E 改造拆成可执行任务，并保存到 `_todos.md`。
- [x] T0.3 在每个阶段完成后更新本文件状态，避免后续工作失焦。

## Phase 1: live soland + yougen UI smoke 骨架

- [x] T1.1 新增 `scripts/run-joint-e2e.ps1`，负责编排 soland、yougen、可选 coauth，创建运行目录并收集产物。
- [x] T1.2 新增 `e2e/package.json` 和 `e2e/playwright.config.ts`，把 Playwright 输出固定到 `artifacts/runs/<timestamp>/joint-e2e/`。
- [x] T1.3 新增 E2E helper，统一读取 `COTEST_*` 环境变量、创建多用户 browser context、保存步骤截图。
- [x] T1.4 新增 live smoke tests: 环境健康、错误 server URL、Alice/Bob 独立 dev-login、Alice 创建 Space 并持久化消息。
- [x] T1.5 运行静态/配置级验证，确保新增脚本和 TypeScript 配置可解析。
- [x] T1.6 在 `docs/test-strategy.md` 补充 UI E2E 与现有 API conformance 的边界。
- [x] T1.7 修复 live smoke 暴露的本地服务编排问题: 隔离 `DATABASE_URL`/`.env`，并递归清理 soland/yougen 子进程。
- [x] T1.8 修复 live smoke 暴露的跨项目兼容问题: soland CORS 放行 yougen 写事件头，yougen 只对 `sx:` sync token 发送 `X-Contrix-Wait-For`。

## Phase 2: coauth live 接入

- [x] T2.1 扩展 `run-joint-e2e.ps1` 的 coauth 启动参数，支持 live `CoauthBaseUrl` 和本地 `CoauthCommand`。
- [x] T2.2 复用或增强 `coauth_bootstrap`，生成测试用 coauth 配置和 ephemeral PostgreSQL。
- [x] T2.3 明确 soland 与 coauth 的测试配置映射: audience、endpoint、service DID、introspection URL、bearer。
- [x] T2.4 新增 coauth discovery/topology smoke: `/health`、OIDC discovery、`/api/v1/server/describe`、principal server 配置。
- [x] T2.5 新增 coauth 登录失败和 session grant 失败 UI 流程。

## Phase 3: 多用户真实流程矩阵

- [x] T3.1 新增 Alice/Bob/Admin/Guest page objects，隔离 localStorage、token、device id。
- [x] T3.2 新增注册用户流程: 生成/绑定 DID、填写 handle/display name/device、提交注册、截图归档。
- [x] T3.3 新增联系人流程: Alice 搜索 Bob、请求、Bob 接受、重复请求冲突。
- [x] T3.4 新增 Space 管理流程: 创建 private Space、邀请/添加成员、修改元数据/策略、移除成员、删除。
- [x] T3.5 新增双向消息流程: Alice 发送、Bob 同步、Bob 回复、编辑、redaction/tombstone。
- [x] T3.6 新增权限流程: Guest/非成员/非 owner 的 UI 禁用和 API 403/401 校验。
- [x] T3.7 新增会话流程: refresh/logout/revoked token。
- [x] T3.8 新增移动端核心路径: 登录、导航、timeline、发送消息、Space admin 截图。

## Phase 4: 报告、CI 和视觉稳定化

- [x] T4.1 将 joint E2E summary 链接到 `artifacts/latest/`，并输出截图索引。
- [x] T4.2 增加 `joint-smoke` 与 `joint-full` 运行 profile 或独立脚本参数。
- [x] T4.3 引入 trace/video/HAR/console/network 失败归档。
- [x] T4.4 对登录页、Space admin、timeline、权限错误页建立可控视觉 baseline。
- [x] T4.5 为 CI 准备 Node、Playwright browser、Dioxus CLI、Docker/PostgreSQL 前置检查。
- [x] T4.6 将稳定后的 joint smoke 纳入 release-gate 前置检查。

## Phase 5: spec 覆盖补齐 (规划日期 2026-05-14)

差距分析: Phase 1-4 已经覆盖了健康检查、错误登录、注册、联系人、Space lifecycle、消息发送/编辑/redaction、权限矩阵、会话刷新/登出/失效、移动端核心路径、视觉 baseline。但相对 contrix-spec/v1 的产品面，下列 UI 流程仍未在 Playwright 层覆盖。Phase 5 把这些缺口补齐，全部基于 yougen 中实际存在的 `data-testid`，不依赖未实现的 UI surface。

- [x] T5.1 新增 `e2e/tests/onboarding.spec.ts`: 通过 `/onboarding` 走 DID method → Handle → Device → Recovery 四步，校验 `onboarding-progress` 切换、各步面板可见、Recovery 三选项切换 (`recovery-vault` / `recovery-social` / `recovery-key`)、`onboarding-finish` 链接落到 Dashboard。
- [x] T5.2 新增 `e2e/tests/directory-tabs.spec.ts`: 覆盖 `tab-objects` / `tab-spaces` / `tab-organizations` / `tab-actors` / `tab-handles` 五个 tab 切换、`directory-three-axes-banner` 可见、`directory-contact-tools` 表单可见。
- [x] T5.3 新增 `e2e/tests/consent-flow.spec.ts`: 在 `/settings/privacy` 渲染 `consent-grant-demo`，填空校验、Space ID 校验、提交 `consent-grant-submit` 后 `consent-grant-status` 渲染 Move 结果或 reason；`consent-revoke-submit` 走相同路径。
- [x] T5.4 新增 `e2e/tests/quarantine-smoke.spec.ts`: `/quarantine` 渲染 `quarantine-panel` + `quarantine-header`，点击 `quarantine-refresh-button` 后 `quarantine-status` 或 `quarantine-empty` 至少出现一项。
- [x] T5.5 新增 `e2e/tests/chat-interactions.spec.ts`: Alice/Bob 进入 `/chat/<space>`，发送消息，Bob 通过 `chat-react-button` 打开 `chat-reaction-picker` 选择 emoji，Alice 看到 `chat-reactions`；Bob 点 `chat-reply-button`，Alice 看到 `chat-reply-indicator`/`chat-reply-banner` 行为。
- [x] T5.6 新增 `e2e/tests/failure-paths.spec.ts`: 通过 Playwright route mock 把 `POST /api/v1/events` 临时返回 500，Alice 在 chat 发送消息后看到 `chat-message-error` + `chat-retry-button`；清掉 mock 后点击 retry 让消息进入 timeline。
- [x] T5.7 新增 `e2e/tests/notifications-smoke.spec.ts`: `/notifications` 渲染 `notifications-panel`、`mark-all-read` 按钮可点击、空/筛选状态出现 `notifications-muted-empty` 或 `notification-item`。
- [x] T5.8 扩展 `mobile-core.spec.ts` (`@mobile`): 新增 mobile login error 截图、`mobile-directory-nav-button` → 进入 directory、`mobile-settings-nav-button` → 进入 settings、`mobile-topbar-notifications-button` → 进入 notifications。
- [x] T5.9 扩展 `visual-baseline.spec.ts` (`@visual`): 为 `dashboard-panel`、`directory-panel`、`settings-panel`、`notifications-panel` 增加 baseline，移动端给 `mobile-shellbar` + `mobile-nav-drawer` 增加 390x844 baseline。
- [x] T5.10 更新 `docs/test-strategy.md` Joint UI E2E 段落, 描述 Phase 5 新增的 spec 与 testids 覆盖关系。
- [x] T5.11 对所有新增 spec 跑 `npx tsc --noEmit` 通过类型检查。

## Phase 6: 反向填充 cotest fixme(2026-05-17)

joint-e2e 当前 **29 passed / 0 failed / 194 skipped** —— skip 中除去 `describe.fixme` 容器自带的 2 行,其余 192 个全部是单测 `test.fixme(...)` 占位。这些占位需要等服务端 / 客户端实现到位才能转实测。

服务端 / 客户端 gap 已经写进各项目 `_todos.md`:
- `../soland/_todos.md` "E2E gap backlog" 表 — 125 行 ID,覆盖 ~142 fixme(server / reducer / projection / federation / MLS / WebRTC / 备份 / WebVH)
- `../yougen/_todos.md` E 段 "cotest joint-e2e fixme 反推的 yougen 侧 gap" — 30 行 ID,覆盖 ~50 fixme(UI / 视图 / 向导 / outbox / testid)

下面是 cotest 端配套需要做的 harness 改造,不是 yougen / soland 业务:

### 6.A harness 缺失的 mock 服务

| ID | 主题 | 用途 | acceptance |
|---|---|---|---|
| **H-MOCK-IDP-1** | mock OIDC IdP | `tests/identity/onboarding.spec.ts` "bob registers via OIDC bridge" 与 `account-device-auth.spec.ts` 都需要 | `e2e/mocks/mock-idp.mjs` 起 HTTP server,实现 `/discovery`、`/authorize`、`/token` 三端点 + 测试用静态 ID Token;`run-joint-e2e.ps1 -StartMockIdp` 已有占位,但 mock-idp.mjs 仅是骨架 — 补齐到能让 coauth 真正完成 OIDC token exchange |
| **H-MOCK-EMAIL-1** | mock email verification service | `onboarding.spec.ts` "carol registers via email-only" + `invites/third-party.spec.ts` "mock verification service receives invite token" | `e2e/mocks/mock-email.mjs` 起 HTTP server,记录所有"发出"的邮件 + token 内嵌的 verification link;暴露 `/inbox/{email}` 给测试取最近的 token;coauth / soland 把 SMTP 调用替换为 HTTP POST 到 mock |
| **H-MOCK-AUDIT-AGENT-1** | mock audit-agent | `encryption/audited-e2ee.spec.ts` "report triggers audit_disclosure_policy.trigger; audit-agent is invited" | mock audit-agent 服务持有自己的 DID + signing key + KeyPackage(if E2EE);被邀请进 space 后能 acknowledge invite,生成 `cx.audit.accessed` 事件;`/inspect` 端点给测试看它收到的 `cx.moderation.franking_proof` 列表 |
| **H-MOCK-WITNESS-1** | mock did:webvh witness | `identity/webvh-rotation.spec.ts` 多个用例 + onboarding 的 did:webvh genesis | 现有 `e2e/mocks/mock-witness.mjs` 是骨架,需要扩到能:接受 entry rotation co-sign 请求、按测试场景模拟 offline(>24h timestamp)、提供 `/inspect` 看签发历史 |

#### Per-mock 实现状态 (CT-15, 2026-05-19 更新)

文件实际情况:`e2e/mocks/` 下现在有 4 个 mjs (`mock-idp.mjs` / `mock-email.mjs` / `mock-witness.mjs` / `mock-audit-agent.mjs`),并新增 `e2e/mocks/_shared/{inspect.mjs,keypairs.mjs}` 公共模块。所有四个 mock 都已经实现 `/inspect` 端点(支持 `GET` 查询、`DELETE` 重置)。

##### H-MOCK-IDP-1 implementation status

源文件:`cotest/e2e/mocks/mock-idp.mjs` (146 行,RS256 静态 keypair)

- [x] `/.well-known/openid-configuration` (discovery) 端点
- [x] `/jwks` 端点 (公钥)
- [x] `/authorize` 端点 — 接 `login_hint` / `redirect_uri` / `state` / `client_id`,302 redirect 回 RP 带 `code`+`state`
- [x] `/token` 端点 — form-encoded `code` → 返 `{access_token, token_type, id_token, expires_in}`
- [x] 静态 ID Token 返 (RS256 签名,`iss`/`sub`/`aud`/`email`/`email_verified` claims)
- [x] `/inspect` 端点 — 暴露 authorize / tokens / scenarios 三条日志 (2026-05-19)
- [x] 测试场景化的 sub/email 注入 — `POST /scenarios {login_hint, sub?, email?, force_error?}` (2026-05-19)
- [x] PKCE 校验 (S256 / plain) — `/authorize` 接收 `code_challenge`+`code_challenge_method`, `/token` 校验 `code_verifier`,不匹配返 `invalid_grant` (2026-05-19)
- [x] error 响应矩阵 — 通过 scenario 的 `force_error` 可强制 `invalid_grant` / `invalid_client` / `unauthorized_client` 等任意 OIDC 错误 (2026-05-19)

##### H-MOCK-EMAIL-1 implementation status

源文件:`cotest/e2e/mocks/mock-email.mjs` (161 行,RS256 keypair + in-memory inbox/token 表)

- [x] `/jwks` 端点
- [x] `/api/v1/verification/send` — 记录 `{to, token, subject, body}` 到 inbox
- [x] `/api/v1/verification/inbox?to=email` — 列出该地址收到的所有邮件
- [x] `/api/v1/verification/claim` — token+did → 签 `binding_proof` JWT (RS256,`purpose=third_party_invite_binding`,`token_commitment` 用 sha256:hex 编码)
- [x] token 双重消费检测 (`409 token_already_consumed`)
- [x] `/inspect` 端点 — 全局 dump (sent 日志 + claims 日志 + 所有 token 状态) (2026-05-19)
- [ ] coauth/soland 把 SMTP 调用替换为 HTTP POST 到本 mock (服务端侧改动,**不在 harness 范围**;需要 `../coauth/_todos.md` 配套 task) — **跨项目, 不在 cotest 内**
- [x] HTML / multipart body 渲染断言 — `send` 接收 `body_html`,inbox 存储并通过 `/inspect` 暴露 (2026-05-19)
- [x] 过期 token 验证 — inbox token 现在带 `expires_at` (`MOCK_EMAIL_TOKEN_TTL_SECONDS` 控制 TTL,默认 15 分钟),过期返 `410 token_expired` (2026-05-19)

##### H-MOCK-WITNESS-1 implementation status

源文件:`cotest/e2e/mocks/mock-witness.mjs` (132 行,RS256 keypair,默认 `did:web:witness.joint-e2e.local`)

- [x] `/jwks` 端点
- [x] `/api/v1/witness/policy` — 返 `{witness_did, health}`
- [x] `/api/v1/witness/sign` — entry_hash → 签 witness JWT (claims:`iss`/`sub=scid`/`entry_hash`/`entry_number`/`exp=now+24h`)
- [x] `/api/v1/witness/health` 测试钩子 — `POST {state:"healthy"|"down"}` 翻状态;`down` 时 `/sign` 返 503
- [x] offline 模拟 (通过 health=down 实现 `>24h degraded window` 的关键路径)
- [x] `/inspect` 端点 — 暴露 signed 日志 + 每个 scid 的链头 (last_entry_number, last_entry_hash) (2026-05-19)
- [x] 真实 prev_entry_hash 链校验 — `/sign` 现在校验 `entry_number` 单调递增和 `prev_entry_hash` 与上一条一致,不匹配返 `409 prev_entry_hash_mismatch` / `non_monotonic_entry_number` / `unknown_chain_with_prev` (2026-05-19)
- [x] backdated/forged timestamp 拒绝 — `entry_timestamp` 比 `MOCK_WITNESS_STALE_SECONDS`(默认 24h)旧返 `422 entry_timestamp_stale` (2026-05-19)
- [~] 多 witness 仲裁 (`quorum > 1` 场景) — mock 单实例本身支持任意 DID,但 `run-joint-e2e.ps1` 当前只起一个 witness 进程;quorum 场景需要 harness 循环起 N 个进程(对应 `-MockWitnessExtraDids`)。**暂缓**,等第一个 quorum spec 落地再做 — 见 H-HARNESS-MULTIWIT-1

##### H-MOCK-AUDIT-AGENT-1 implementation status

源文件:`cotest/e2e/mocks/mock-audit-agent.mjs` (2026-05-19 创建,Ed25519 keypair + 自动生成 DID + MLS KeyPackage 桩)

- [x] 创建 `e2e/mocks/mock-audit-agent.mjs` 文件 (2026-05-19)
- [x] audit-agent 自身的 DID + Ed25519 signing key 自动生成 — 默认 `did:web:audit-agent.joint-e2e.local#<rand>`,可通过 `MOCK_AUDIT_AGENT_DID` 固定 (2026-05-19)
- [x] KeyPackage 发布 — `GET /api/v1/audit-agent/identity` 返 `key_package` 占位 blob (E2EE invite 时由 soland 转发到组) (2026-05-19)
- [x] `/api/v1/audit-agent/events` + `/api/v1/audit-agent/inbox` 端点 — 接收并列出 `cx.moderation.franking_proof` / `cx.audit.report` 事件 (2026-05-19)
- [x] 自动 acknowledge invite — `POST /api/v1/audit-agent/invite` 收到 invite 后生成并记录一条 `cx.audit.accessed` envelope (2026-05-19)
- [x] 自动生成 audit binding signed proof — Ed25519 签名嵌入 `cx.audit.accessed.binding_proof`,可通过 `/jwks` 验证 (2026-05-19)
- [x] `/inspect` 端点 — dump inbox / invites / accessed 三个 log,以及 agent_did 和 public_jwk (2026-05-19)
- [x] `run-joint-e2e.ps1` 增加 `-StartMockAuditAgent` 开关(`-StartMocks` 自动开启);新增 `-MockAuditAgentDid` 参数允许固定 DID;summary.json/.md 输出 `mock_audit_agent_base_url` (2026-05-19)
- [ ] coauth/soland 配置侧把 `cx.audit_disclosure_policy.audit_agent_did` 指向 mock 自动生成的 DID — **跨项目,服务端 todo**;cotest 已经通过 `COTEST_MOCK_AUDIT_AGENT_BASE_URL` / `COTEST_MOCK_AUDIT_AGENT_DID` 把 mock 信息 export 给 spec,服务端配置生成需在 `../soland/_todos.md` / `../coauth/_todos.md` 跟进

#### 实际文件布局 (2026-05-19 落地)

```
cotest/e2e/mocks/
  mock-idp.mjs           ← /inspect + PKCE + scenarios + force_error ✅
  mock-email.mjs         ← /inspect + body_html + token expiry (TTL) ✅
  mock-witness.mjs       ← /inspect + prev_entry_hash 链校验 + stale 拒签 ✅
  mock-audit-agent.mjs   ← 新建 ✅
  _shared/
    inspect.mjs          ← 统一的 /inspect 中间件(GET dump + DELETE 重置)✅
    keypairs.mjs         ← 统一的 Ed25519/RS256 keypair helper ✅
```

### 6.B harness 反向工程 fixme → 实测的流水

- [x] **H-SHIM-1** fixme → test 自动重写脚本 — `scripts/promote-fixme.ps1 -SpecPath <file>:<line> -NewBody '...'` 把指定 fixme 整段替换成实测;先验证当前位置仍是 `test.fixme(...)`(防止 race),通过 bracket-counter 找到匹配的 `)` 即使 body 跨多行;支持 `-DryRun` 预览。Smoke tested 2026-05-19 (2026-05-19 ✅)
- [x] **H-SHIM-2** per-feature 选择性跳过 — `run-joint-e2e.ps1 -RunProfile joint-smoke` 现在自动加 `--grep @fully-implemented`,只跑测试名带该 tag 的实测;显式 `-Grep` 仍可覆盖。fixme 占位不再阻塞 smoke CI (2026-05-19 ✅)
- [x] **H-SHIM-3** service-log gap 报告 — `run-joint-e2e.ps1` 结束阶段扫所有 service stderr (`Select-String` 正则 `(WARN|ERROR).*(denied|FORBIDDEN|capability_denied|policy_reject|reject|unauthorized)`),分服务列出最多 50 行匹配,写入 `service-gaps.md`,并把路径加入 `summary.json/.md` (2026-05-19 ✅)

### 6.D 后续 follow-up (deferred)

- [x] **H-HARNESS-MULTIWIT-1** multi-witness quorum 编排 — `mock-witness.mjs` 单实例已经能用任意 DID 启动,`run-joint-e2e.ps1 -MockWitnessExtraDids` 现在会循环 spawn 额外 witness,并通过 `COTEST_MOCK_WITNESS_QUORUM_BASE_URLS` / `COTEST_MOCK_WITNESS_QUORUM_DIDS` export 给 spec。
- [x] **H-SHIM-4** promote-fixme 反向 demotion — `scripts/demote-test.ps1` 已落地,当回归测试失败但功能未回退到 fixme 时,可临时把 test 转 `test.fixme` 并附 reason 注释。

### 6.C 当前已落地

| 项 | 落地 | 说明 |
|---|---|---|
| 192 fixme 全部分类归入各项目 _todos.md | ✅ 2026-05-17 | soland 125 行 + yougen 30 行 + harness ~10 行,每行 stable ID |
| kanban `/kanban` → `/kanban/${space_id}` 修复 | ✅ 2026-05-17 | `e2e/tests/kanban/end-to-end.spec.ts:42` + `workflows/kanban-week.spec.ts:49`;创建新 space 后必须带 space_id 路由,否则 selected_space 回退到 demo space → 403/capability_denied → 卡片乐观 UI 回滚 |
| agent_workspace Rust e2e | ✅ 2026-05-17 | `tests/agent_workspace_e2e.rs` 真实跑通,401 + 401 + openapi operationId 三条全过 |
| event_idempotency_replay Rust scenario | ✅ 2026-05-18 | `tests/event_idempotency_replay.rs` + `src/scenarios/event_idempotency_replay.rs`,验证同一 event_id 二次 POST 返 `status=duplicate,idempotent=true` 且 projection 只发生一次 |
| H-MOCK-IDP-1 / EMAIL-1 / WITNESS-1 全部子项 | ✅ 2026-05-19 | 见 §6.A 各 implementation status |
| H-MOCK-AUDIT-AGENT-1 (harness 侧) | ✅ 2026-05-19 | `mock-audit-agent.mjs` 全功能,run-joint-e2e `-StartMockAuditAgent` 开关到位;遗留服务端配置项已转 soland/coauth 项目 todo |
| H-SHIM-1/2/3 | ✅ 2026-05-19 | `promote-fixme.ps1`、joint-smoke `--grep @fully-implemented` 自动启用、`service-gaps.md` 报告 |

## Phase 7: 持续维护和扩展 (2026-05-19 起)

Phase 6 把 harness 侧的 mock 服务全部补齐之后,joint-e2e 主体上可以承接服务端 / 客户端 feature 落地,逐步把 192 个 fixme 占位转为实测。下面是 cotest 仓自身的持续维护项,不是反推到 soland/yougen 的服务端任务。

### 7.A 自动化覆盖

- [x] T7.1 新增 `e2e/tests/harness/mocks-selftest.spec.ts` (2026-05-19),直接 hit 各 mock 的端点 + `/inspect` 验证行为契约:
  - idp: `POST /scenarios` → PKCE-S256 `/authorize`+`/token` happy path 验证 sub/email/audience;`force_error=unauthorized_client` 路径返 400 + 正确 OIDC `error` 字段
  - email: `ttl_seconds=1` → wait 1.5s → claim 返 `410 token_expired`;另起 longer-ttl token 走 happy path 拿到 binding_proof 和 token_commitment
  - witness: scid 顺序签 entry 1/2,prev_entry_hash mismatch 返 `409 prev_entry_hash_mismatch`,skip-number 返 `409 non_monotonic_entry_number`,stale timestamp (2024-01-01) 返 `422 entry_timestamp_stale`
  - audit-agent: `/identity` 拿 did + key_package,`/invite` 自动 emit `cx.audit.accessed` 含 binding_proof,`/accessed` 列出 emitted envelope,`/jwks` 暴露 Ed25519 公钥
  - 全部 4 个 case 已在 4 个 mock 同时运行的环境跑过,2026-05-19 4 passed
- [x] T7.2 mocks-selftest 标记 `@fully-implemented` (`test.describe("harness mocks selftest @fully-implemented", ...)`),`joint-smoke` 自动 grep 该 tag 后这套 selftest 会跟着跑,任何 mock 行为漂移会被立即拦截 (2026-05-19)

### 7.B Rust scenario 反向覆盖

- [ ] T7.3 review `src/scenarios/event_idempotency_replay.rs` (2026-05-18 新增) 是否需要在 `_report.md` 的 spec 覆盖矩阵里登记;现在 `tests/event_idempotency_replay.rs` 用 `serial_test::serial` 串行运行,确认 `TestServerGroup` 隔离仍然成立。
- [ ] T7.4 把同类的事件流幂等 / replay 场景扩展到 redaction、tombstone、edit chain (cx.message.update / cx.message.redact);currently only `cx.message.create` 被覆盖。

### 7.C harness 文档同步

- [x] T7.5 `docs/test-strategy.md` "Joint UI E2E" 段新增 "Mock services" 子节,列 4 个 mock 的 spec section + 关键端点表;同时记录 `joint-smoke` 现在默认 `--grep @fully-implemented` 的行为 (2026-05-19)
- [x] T7.6 `_report.md` 新增 §9.5 "Harness mock 服务",指向各 mock 文件、列对应 spec section、说明 `_shared` 公共模块、引出 `mocks-selftest.spec.ts` 契约固定点 (2026-05-19)
