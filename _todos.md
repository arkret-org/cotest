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
| **H-MOCK-AUDIT-AGENT-1** | mock audit-agent | `encryption/audited-e2ee.spec.ts` "report triggers audit_disclosure_policy.trigger; audit-agent is invited" | mock audit-agent 服务持有自己的 DID + signing key + KeyPackage(if E2EE);被邀请进 space 后能 acknowledge invite,生成 `cx.audit.accessed` 事件;`/inspect` 端点给测试看它收到的 `cx.moderation.frank` 列表 |
| **H-MOCK-WITNESS-1** | mock did:webvh witness | `identity/webvh-rotation.spec.ts` 多个用例 + onboarding 的 did:webvh genesis | 现有 `e2e/mocks/mock-witness.mjs` 是骨架,需要扩到能:接受 entry rotation co-sign 请求、按测试场景模拟 offline(>24h timestamp)、提供 `/inspect` 看签发历史 |

### 6.B harness 反向工程 fixme → 实测的流水

| ID | 主题 | 描述 |
|---|---|---|
| **H-SHIM-1** | fixme → test 自动重写脚本 | `scripts/promote-fixme.ps1 -SpecPath <file>:<line> -NewBody '...'` 把指定 fixme 整段替换成实测;先验证当前 test 在该位置仍是 fixme(防止 race);用于服务端 feature 落地后批量切换 |
| **H-SHIM-2** | per-feature 选择性跳过 | 让 `run-joint-e2e.ps1 -Profile joint-smoke` 通过 grep 标签(测试名带 `@fully-implemented`)只跑已落地的;avoid CI noise during incremental rollout |
| **H-SHIM-3** | service-log gap 报告 | run-joint-e2e 结束后扫所有 service stderr 找 `WARN.*denied|FORBIDDEN|reject` 行写进 summary.md,让失败原因更直接(参见 2026-05-17 kanban 修复就是靠这条 WARN) |

### 6.C 当前已落地

| 项 | 落地 | 说明 |
|---|---|---|
| 192 fixme 全部分类归入各项目 _todos.md | ✅ 2026-05-17 | soland 125 行 + yougen 30 行 + harness ~10 行,每行 stable ID |
| kanban `/kanban` → `/kanban/${space_id}` 修复 | ✅ 2026-05-17 | `e2e/tests/kanban/end-to-end.spec.ts:42` + `workflows/kanban-week.spec.ts:49`;创建新 space 后必须带 space_id 路由,否则 selected_space 回退到 demo space → 403/capability_denied → 卡片乐观 UI 回滚 |
| agent_workspace Rust e2e | ✅ 2026-05-17 | `tests/agent_workspace_e2e.rs` 真实跑通,401 + 401 + openapi operationId 三条全过 |
