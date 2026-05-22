# cotest 当前测试能力与三方联合 E2E 测试方案

生成日期: 2026-05-12

## 1. 当前项目如何测试

当前 `cotest` 不是普通单元测试项目，而是一个面向 Contrix/soland 的黑盒合规测试套件。它的核心定位是:

- 启动真实的 `soland` 服务进程或 Docker 容器。
- 只通过公开 HTTP API 驱动服务。
- 在必要位置使用 `contrix-rust-sdk` 做 typed protocol smoke 测试。
- 把请求响应转录、服务日志、测试摘要、覆盖矩阵、JUnit、HTML 报告等统一保存到 `artifacts/`。

主要入口:

- `cargo test --tests -- --nocapture`: 直接运行所有 Rust integration tests。
- `scripts/run-cotest.ps1 -Runtime process`: 默认本地进程模式，启动相邻目录 `../soland/Cargo.toml`。
- `scripts/run-cotest.ps1 -Runtime docker`: 使用 `cotest-soland:latest` 容器运行 SUT。
- `scripts/run-cotest.ps1 -Profile fast-smoke|compose|release-gate|full-nightly`: 按配置选择测试子集。
- `scripts/run-compose.ps1`: process 模式下运行 compose profile，并允许接入 `COAUTH_BASE_URL`、`FLORIA_BASE_URL`、`SODMIN_BASE_URL`、`YOUGEN_BASE_URL` 或对应启动命令。

核心代码组织:

- `src/harness.rs`: 服务生命周期、端口分配、HTTP 断言、测试 actor、transcript 记录、Docker 网络。
- `src/scenarios/*.rs`: 实际业务/协议测试流程。
- `tests/*.rs`: 很薄的 integration wrapper，调用 `src/scenarios`。
- `src/conformance/*.rs` 与 `tests/fixtures/*.json`: 离线规范 fixture 和语义验证。
- `config/ci-profiles.json`: 定义 `all`、`fast-smoke`、`compose`、`release-gate`、`full-nightly` 的测试筛选。
- `scripts/run-cotest.ps1`: 负责运行测试并产出报告。

运行产物:

- `artifacts/runs/<timestamp>/raw.log`
- `artifacts/runs/<timestamp>/transcript.ndjson`
- `artifacts/runs/<timestamp>/summary.md`
- `artifacts/runs/<timestamp>/summary.html`
- `artifacts/runs/<timestamp>/junit.xml`
- `artifacts/runs/<timestamp>/coverage-matrix.*`
- `artifacts/runs/<timestamp>/coverage-gate.*`
- `artifacts/runs/<timestamp>/release-gate.*`
- `artifacts/runs/<timestamp>/secret-scan.*`
- `artifacts/runs/<timestamp>/services/*.log`
- `artifacts/latest/` 会复制最近一次运行结果。

最近一次可见的 `artifacts/latest/summary.md` 显示: 2026-05-07 的 `release-gate`、`process` 运行成功，17 个测试通过，0 失败。它验证的是 API/协议/fixture 层，不是浏览器 UI 层。

## 2. 当前具体测试了什么

### 2.1 单服务 API 和业务流程

当前 `cotest` 已经覆盖了不少你提到的后端流程:

- 服务发现与健康检查: `/health`、`/api/v1/server/describe`、`/api/v1/integration/describe`、sync/directory/index describe。
- 认证与账号: 无效 JSON、标准错误 envelope、账号注册、重复注册、dev-login、logout、logout 后 token 失效。
- 联系人: 发送联系人请求、接受联系人请求、重复请求、请求自己、请求不存在用户。
- 协作流程: Alice/Bob 账号启动、创建 Space、添加成员、发送消息、Bob sync 看到消息、snapshot head、移除成员、删除 Space、生命周期事件查询。
- Space 权限: 未认证创建失败、空 title 失败、非法 invitee 失败、非 owner 添加成员失败、owner 不能移除自己、非 owner 删除 Space 失败。
- 私有可见性: 匿名搜索私有 Space 为空、非成员发送消息失败、成员发送成功、删除后再发送失败。
- 交互模型: 消息修改/删除、reaction、read marker、subscription、entity/relation/view projection。
- schema/policy/realtime: schema registry、policy document、typing ephemeral、push rules、WebRTC signaling。
- delivery/media: device key upload/query/claim、to-device 消息、blob 上传下载、Range/hash、反枚举、query-string auth 拒绝。
- identity/directory: DID resolve/document/log/receipt、directory discoverability/privacy、export/audit/notification/inbox。
- authz/presence/push: grant lifecycle、policy check、presence、push device registration、ICE config。

### 2.2 多服务/多节点

已有多节点 API 层测试:

- `federation_readiness`: 两个 soland 实例隔离、service DID 不同、基础 discovery 可用。
- `federation_contract`: federation transaction/push/pull/verify-actor、replay/idempotency、invalid input、redaction/snapshot。
- `federation_collaboration`: Alice 在 server A，Bob 在 server B，跨服务邀请/消息推送/拉取/sync 可见、Bob 回复、device message、blob、push、moderation。

### 2.3 Bridge/compose

`compose` profile 当前更接近桥接契约验证，而不是完整三方产品流:

- `principal_bridge_contracts_are_discoverable`: 检查 soland 暴露的 auth bridge、push outbound bridge、integration manifest。
- `session_grant_exchange_uses_configured_coauth_introspection`: 使用本地 mock coauth introspection server，验证 soland 的 session grant exchange 和 push register 会调用 introspection。
- `starid_optional_resolver_profile_is_discoverable`: 可选 resolver profile。
- `scripts/run-compose.ps1` 能接入 live coauth/floria/sodmin/yougen URL 或命令，但当前测试内容仍主要是 contract/discovery scaffold。

### 2.4 离线 conformance fixture

当前大量 `tests/fixtures/*.json` 验证规范语义:

- Event Envelope、encoding、redaction、capability、sync、federation、privacy/security。
- Move/Anchor/Lattice、state resolution、consent、read receipt policy、MLS/E2EE、device verification、key backup、history visibility、multi-space federation 等。

这些测试价值很高，但它们不是用户真实 UI 操作。

## 3. 当前缺口

对你提出的需求来说，当前项目的主要缺口是:

1. 没有在 `cotest` 内运行浏览器 UI 自动化。现有测试主要是 Rust + HTTP API。
2. 没有“每个流程步骤保存截图”的稳定产物规范。`yougen` 自己有 Playwright 测试，但默认使用 mock Contrix API，视觉 smoke 只检查截图 buffer 大小，不是三方 live 流程截图归档。
3. `yougen + soland + coauth` 还没有形成真实联合启动、登录、注册、授权、业务操作、UI 断言的一体化流程。
4. coauth 在当前 `cotest` 的主要使用方式是 mock introspection 或可选外部服务，不是完整 OIDC/账号/注册 UI 流。
5. 现有 API 流程虽然覆盖注册、联系人、消息、Space、权限，但没有用多个浏览器上下文模拟多个真实用户。
6. 没有针对 UI 显示正确性的断言体系，例如 locator 可见性、错误提示、按钮禁用、移动端布局、截图对比、trace/video/HAR 归档。

## 4. 难度评估

整体难度: 中高到高。

如果只要求“yougen 连接 live soland，使用 dev-login，跑多用户浏览器流程并保存截图”，难度是中高。现有 `yougen` 已经有 Playwright、`data-testid`、Dioxus web 启动脚本，现有 `cotest` 已经能启动 soland。

如果要求“真实 coauth 注册/登录/OIDC/session grant，然后 yougen 用真实 token 调 soland”，难度是高。原因是要同时解决 coauth 数据库、配置、密钥、测试用户、回调 URL、CORS、HTTPS/local.host、token introspection、浏览器跳转和会话隔离。

| 模块 | 难度 | 原因 |
| --- | --- | --- |
| soland API 启动和隔离 | 低到中 | `cotest` 已有 process/docker harness，in-memory 模式可快速跑。 |
| coauth 启动 | 中到高 | 需要 PostgreSQL、配置文件、principal server 配置、密钥/issuer、health listener。已有 bootstrap helper，但还不是完整 UI 登录流。 |
| yougen web 启动 | 中 | 已有 `dx serve --platform web` 和 Playwright 配置，但构建慢，依赖 dx/Node/browser。 |
| 多用户浏览器模拟 | 中到高 | 需要多个 browser context、独立 local storage、token/session、并发/串行边界。 |
| 真实 coauth OIDC/注册 | 高 | 涉及 redirect、callback、cookie、CSRF/state、测试密码策略、邮件/验证码/验证码绕过或测试模式。 |
| UI 正确性验证 | 中 | 有 `data-testid` 基础，需补 page object、截图命名、关键页面断言。 |
| 截图稳定归档 | 中 | 保存截图容易，稳定可复现和 CI 结合较难。 |
| CI 稳定性 | 高 | 三服务启动、端口、TLS、浏览器、数据库、超时都会带来 flake。 |

## 5. 推荐技术方案

推荐把方案拆成两层:

1. `cotest` 继续做三方服务编排、环境隔离、产物汇总和 release profile。
2. 浏览器真实用户流程用 Playwright 实现。UI 流程不建议写在 Rust integration test 里。

### 5.1 新增联合 E2E 入口

建议新增脚本:

- `scripts/run-joint-e2e.ps1`

职责:

1. 创建本次运行目录: `artifacts/runs/<timestamp>/joint-e2e/`。
2. 启动或接入 coauth。
3. 启动 soland，并注入:
   - `SOLAND_DEVELOPMENT_MODE=true` 或测试专用 production-like 配置。
   - `SOLAND_PUBLIC_BASE_URL=<浏览器可访问 URL>`。
   - `SOLAND_CORS_ALLOW_ORIGIN=<yougen web origin>`。
   - `SOLAND_OAUTH_INTROSPECTION_URL` 或 `SOLAND_SESSION_GRANT_INTROSPECTION_URL`。
   - `SOLAND_OAUTH_INTROSPECTION_BEARER` 或 `SOLAND_SESSION_GRANT_INTROSPECTION_BEARER`。
4. 启动 yougen web:
   - `dx serve --platform web --addr 127.0.0.1 --port <port> --open false --hot-reload false --watch false`
   - 注入 `YOUGEN_SERVER_URL=<soland public URL>`。
   - 如支持，注入 `YOUGEN_COAUTH_URL=<coauth public URL>`。
5. 等待三个服务 `/health` 或等价 ready endpoint。
6. 运行 Playwright live specs。
7. 收集:
   - Playwright report
   - screenshots
   - traces
   - videos
   - browser console/network logs
   - soland/coauth/yougen stdout/stderr
   - JUnit XML
8. 把结果复制到 `artifacts/latest/joint-e2e/`，并在 `summary.md` 链接截图目录。

### 5.2 Playwright 代码位置

有两个可选方案:

方案 A: specs 放在 `../yougen/tests/e2e-live/`。

- 优点: UI selector、page object、mock/live 测试都跟 yougen 放一起。
- 缺点: 三方编排逻辑分散到 yougen，不符合 cotest 的“跨项目测试”定位。

方案 B: specs 放在 `cotest/e2e/`。

- 优点: cotest 统一负责跨服务场景和报告。
- 缺点: cotest 需要引入 Node/Playwright package，维护成本上升。

我的建议: 编排脚本和报告汇总放在 `cotest`，Playwright live specs 可以先放 `cotest/e2e/`。如果后续 yougen 团队希望把 UI 流程自持，再迁移 page object 到 yougen。

### 5.3 Playwright 设计

基础配置:

- `workers: 1`: 跨服务流程先串行，降低 flake。
- `trace: "retain-on-failure"` 或 `"on-first-retry"`。
- `video: "retain-on-failure"`。
- `screenshot: "only-on-failure"` 加自定义 step screenshot。因为你的需求是每个关键步骤都保存截图，只靠 Playwright 默认截图不够。
- `outputDir: artifacts/runs/<timestamp>/joint-e2e/playwright-output`。
- `reporter: [["list"], ["junit", { outputFile }], ["html", { outputFolder }]]`。

建议封装:

```ts
async function shot(page, name) {
  const path = pathJoin(process.env.COTEST_UI_SCREENSHOT_DIR, `${test.info().title}-${name}.png`);
  await page.screenshot({ path, fullPage: true });
  await test.info().attach(name, { path, contentType: "image/png" });
}
```

多用户模拟:

- Alice、Bob、Admin、Guest 使用不同 `browser.newContext()`。
- 每个 context 单独登录，单独保存 `storageState`。
- 每个用户页面都使用 `data-testid` 定位，避免文本变化导致脆弱。
- 对实时/同步结果使用 `expect.poll` 或 UI 层刷新按钮，不使用固定 sleep。

断言分两类:

- UI 断言: 页面可见、状态文案、错误提示、按钮禁用、列表项出现/消失、消息内容显示、权限入口隐藏。
- API 断言: 通过 soland HTTP API 查状态，确认 UI 操作真的落库或被正确拒绝。

截图策略:

- 每个流程开始、关键成功步骤、关键失败步骤都截图。
- 命名建议: `<flow>/<step>-<user>-<viewport>.png`。
- 首期只做截图归档和非空检查，不做严格像素 diff。
- 对登录页、Space 管理页、聊天页、权限错误页、移动端布局，可以后续追加 `toHaveScreenshot` baseline。

## 6. 建议测试流程矩阵

### Flow 0: 环境健康和发现

目标: 确认三方服务真的连起来。

步骤:

1. soland `/health` 成功。
2. coauth `/health` 或 internal health 成功。
3. yougen 首页可加载。
4. yougen 配置的 server URL 指向 soland。
5. soland `server/describe` 暴露 principal server 能力。
6. coauth discovery 暴露 principal server 配置。

截图:

- yougen 初始页
- 连接成功后的 dashboard

### Flow 1: 错误账号/错误登录

目标: 验证失败登录路径和 UI 错误展示。

步骤:

1. 输入非法 server URL，点击连接。
2. 输入不允许的远端 http URL，点击连接。
3. 使用不存在账号登录。
4. 使用错误密码或错误 session grant 登录。
5. 验证没有进入已登录状态，也没有留下可用 token。

断言:

- UI 显示明确错误。
- session panel 不显示在线。
- `/api/v1/account/me` 不可用或返回 unauthorized。

截图:

- invalid-url
- bad-credential
- unauthorized-state

### Flow 2: 注册用户

目标: 从 UI 完成用户注册，并确认 soland/coauth 侧状态一致。

步骤:

1. Alice 打开注册页。
2. 选择生成 DID 或绑定已有 DID。
3. 填写 handle/display name/device label。
4. 生成 proof。
5. 提交注册。
6. 自动或手动登录。
7. 在 soland 查询 `/api/v1/account/me` 或等价接口。

断言:

- UI 显示注册成功。
- coauth 有账号或 session。
- soland 能识别 principal DID/device。

截图:

- registration-form
- proof-step
- registration-success
- logged-in-dashboard

### Flow 3: 两个用户登录和联系人请求

目标: 模拟 Alice 与 Bob 真实用户关系建立。

步骤:

1. Alice 登录。
2. Bob 登录。
3. Alice 搜索 Bob。
4. Alice 发送联系人请求。
5. Bob 在通知/请求列表看到请求。
6. Bob 接受。
7. Alice 再搜索 Bob，Bob 变为可见/可联系。

断言:

- 请求状态从 pending 到 accepted。
- Alice/Bob 两个浏览器 context 中 UI 状态一致。
- 重复请求显示冲突或已存在。

截图:

- alice-search-bob
- alice-request-pending
- bob-request-inbox
- bob-accept
- alice-contact-accepted

### Flow 4: Space 创建、邀请、成员管理

目标: 覆盖 Space 生命周期和管理 UI。

步骤:

1. Alice 创建 private Space。
2. Bob 作为非成员搜索不到该 Space。
3. Alice 邀请 Bob 或 add member。
4. Bob 接受邀请。
5. Bob 能看到 Space。
6. Alice 修改 Space 名称/描述/策略。
7. Alice 移除 Bob。
8. Bob 刷新后失去访问。
9. Alice archive/delete Space。

断言:

- owner 字段正确。
- members 列表正确变化。
- Bob 被移除后 UI 不再显示消息入口，API 发送返回 403。
- 删除后 Space 显示 archived/deleted 或不可访问。

截图:

- create-space
- bob-hidden-before-invite
- member-added
- bob-space-visible
- space-admin-policy
- bob-removed
- space-deleted

### Flow 5: 双向消息和同步

目标: 覆盖真实聊天流。

步骤:

1. Alice 在 Space 发送消息。
2. Bob 页面刷新或自动 sync 后看到 Alice 消息。
3. Bob 回复。
4. Alice 看到 Bob 回复。
5. Alice 编辑消息。
6. Bob 看到 revision。
7. Bob redaction 或 Alice redaction。
8. 另一个用户看到 tombstone。

断言:

- timeline 顺序正确。
- event id/operation id 存在。
- revision chain 可见。
- redacted tombstone 可见。

截图:

- alice-message-sent
- bob-message-received
- bob-reply
- alice-reply-received
- message-edited
- message-redacted

### Flow 6: 权限和越权

目标: 验证 UI 和 API 都正确阻止越权。

步骤:

1. Guest 未登录访问 Space。
2. Bob 非成员发送消息。
3. Bob 尝试管理成员。
4. Bob 尝试删除 Space。
5. Alice owner 执行相同操作成功。
6. Bob 被移除后再次发送消息。

断言:

- Guest/Bob UI 中管理按钮隐藏或 disabled。
- API 返回 `401`/`403` 和标准 error envelope。
- Alice UI 操作成功。
- 权限错误展示不泄漏私有 Space 详情。

截图:

- guest-denied
- bob-no-admin-controls
- bob-send-forbidden
- alice-admin-controls
- removed-member-denied

### Flow 7: 会话、刷新、登出、过期

目标: 覆盖 coauth/soland 会话边界。

步骤:

1. Alice 登录。
2. 刷新 token 或 session。
3. 打开 `/account/me` 页面或状态面板确认 session。
4. logout。
5. 页面刷新后不再在线。
6. 使用旧 token 调 soland 被拒绝。

截图:

- session-active
- token-refreshed
- logged-out
- revoked-token-denied

### Flow 8: 移动端关键路径

目标: 确认移动端 UI 不遮挡、关键操作可用。

步骤:

1. 使用 390x844 viewport。
2. 登录。
3. 打开导航抽屉。
4. 进入 Space/timeline。
5. 发送一条消息。
6. 进入 Space admin 或权限页，确认布局可用。

截图:

- mobile-dashboard
- mobile-nav
- mobile-timeline
- mobile-send-message
- mobile-space-admin

## 7. 建议落地阶段

### Phase 1: live soland + yougen UI smoke

目标: 先不接真实 coauth，用 soland dev-login 或测试 session，打通浏览器 UI、截图、报告。

工作:

- 新增 `run-joint-e2e.ps1` 基础版。
- 启动 soland in-memory。
- 启动 yougen web。
- Playwright 跑 Flow 0、Flow 1、Flow 4/5 的最小 happy path。
- 截图保存到 `artifacts/runs/<timestamp>/joint-e2e/screenshots`。

预估: 1 到 3 天，取决于本机 dx/Playwright/soland build 是否稳定。

### Phase 2: 接入 live coauth

目标: coauth 作为真实 auth server 参与登录/注册/session grant。

工作:

- 复用或增强 `coauth_bootstrap`，生成测试配置。
- 准备 ephemeral PostgreSQL。
- 配置 principal server:
  - coauth trust soland audience/endpoint/service DID。
  - soland 配置 coauth introspection URL/bearer。
- 明确测试模式:
  - 密码登录是否启用。
  - 邮件/验证码/CAPTCHA 是否关闭或走测试 stub。
  - OIDC callback URL 是否可本地访问。

预估: 3 到 7 天。主要风险在 coauth 配置和 auth redirect/session 细节。

### Phase 3: 多用户完整业务矩阵

目标: 多 context 模拟 Alice/Bob/Admin/Guest，跑注册、请求、消息、Space、权限。

工作:

- 建立 page objects。
- 建立 API setup/teardown helpers。
- 串行 flow 和独立 flow 分开。
- UI 断言和 API 断言成对出现。
- 失败时自动保存 trace/video/HAR/service logs。

预估: 4 到 10 天，取决于真实 UI 已支持多少入口。

### Phase 4: 视觉回归和 CI 稳定化

目标: 从“截图证据”升级为“关键页面视觉回归”。

工作:

- 给核心页面加 `toHaveScreenshot` baseline。
- 固定 viewport、字体、时间、测试数据。
- 标记动态区域或使用 locator screenshot。
- 加 `joint-smoke` 和 `joint-full` profiles。
- 在 CI 中安装 dx、Playwright browser、PostgreSQL/Docker。

预估: 3 到 7 天。

## 8. 需要新增或修改的文件

建议在 `cotest` 内新增:

- `scripts/run-joint-e2e.ps1`: 三方启动、等待、运行、归档。
- `e2e/package.json`: Playwright 依赖和 npm scripts。
- `e2e/playwright.config.ts`: live E2E 配置。
- `e2e/tests/*.spec.ts`: 多流程测试。
- `e2e/helpers/services.ts`: 读取 env、health wait、API helper。
- `e2e/helpers/screenshots.ts`: 统一截图命名和附件。
- `e2e/helpers/users.ts`: Alice/Bob/Admin/Guest context 管理。
- `e2e/page-objects/*.ts`: Login/Register/Dashboard/Space/Chat/Admin 页面对象。

建议修改:

- `scripts/run-cotest.ps1`: 可选地在 summary 中链接 joint E2E 产物，或保持独立脚本。
- `config/ci-profiles.json`: 新增 `joint-smoke`、`joint-full`，或者保留在新脚本参数里。
- `docs/test-strategy.md`: 补充 UI E2E 与当前 API conformance 的边界。

可能需要在 `yougen` 补:

- 更稳定的 `data-testid`。
- 支持通过 env 注入 coauth URL。
- 支持测试模式下预填 server/coauth URL。
- 对注册/登录错误、权限错误暴露稳定状态元素。

可能需要在 `coauth` 补:

- 测试专用配置生成器。
- 测试用户 seed。
- 关闭邮件/CAPTCHA 或使用本地 stub。
- 明确 session grant/OIDC 测试路径。

可能需要在 `soland` 补:

- 更稳定的 CORS 配置。
- test-only reset/seed 或 in-memory 隔离。
- coauth introspection 配置与 dev-login/production-like 模式切换更清晰。

## 9. 风险和注意事项

- 真实浏览器会受 CORS/HTTPS/local.host 影响。yougen README 已说明 web build 必须访问浏览器可达且 CORS 允许的 soland URL。
- coauth 正常运行依赖 PostgreSQL 和完整配置。只靠当前 mock introspection 无法证明真实登录/注册链路。
- 三服务同时编译和启动会慢。建议先使用已构建 binary，避免 `cargo test` 与 `cargo run` 争用 cargo lock。
- UI E2E 必须严格隔离测试数据。推荐每次 run 使用唯一后缀，如 `e2e-<timestamp>`。
- 全量流程不适合每个 PR 都跑。建议 PR 跑 `joint-smoke`，nightly 或 release 跑 `joint-full`。
- 初期截图只作为证据归档，不建议马上做全页面像素回归。动态数据、时间、光标、滚动位置都会导致 flake。
- 多用户消息同步不能依赖固定 sleep，应使用轮询 UI 状态或后端 API 状态。

## 9.5 Harness mock 服务 (2026-05-19 补)

`e2e/mocks/` 下有四个 in-process mock 服务,由 `run-joint-e2e.ps1` 可选启动 (`-StartMocks` 一次全开,或单独 `-StartMockIdp` / `-StartMockEmail` / `-StartMockWitness` / `-StartMockAuditAgent`)。每个 mock 都暴露 `GET /inspect` 用于断言侧的 dump 和 `DELETE /inspect` 用于场景间复位;签名秘钥通过 `GET /jwks` 暴露,可被 spec 用来验证 mock 自己签的 JWT/binding_proof。

| 文件 | 主要负责的 spec section | 关键端点 / 行为 |
|------|------------------------|----------------|
| `e2e/mocks/mock-idp.mjs` | S4/S7 OIDC bridge | `/.well-known/openid-configuration` + `/jwks`;`/authorize` 接 PKCE `code_challenge`/`code_challenge_method`,`/token` 校验 `code_verifier` 不匹配返 `invalid_grant`;`POST /scenarios` 绑定 `login_hint -> {sub,email,force_error}` 让 spec 灵活注入身份或强制 OIDC 错误 |
| `e2e/mocks/mock-email.mjs` | S3 third-party invite, S7 email onboarding | `/api/v1/verification/send` 接 `body_html` + `ttl_seconds`,`/inbox?to=` 返历史邮件,`/claim` 验 token (过期返 `410 token_expired`,已用返 `409 token_already_consumed`,成功返签好的 `binding_proof` JWT) |
| `e2e/mocks/mock-witness.mjs` | S9 did:webvh rotation | `/sign` 校验 `entry_number` 单调和 `prev_entry_hash` 与链头一致 (`409 prev_entry_hash_mismatch` / `non_monotonic_entry_number`),并按 `MOCK_WITNESS_STALE_SECONDS`(默认 24h)拒签 backdated entry (`422 entry_timestamp_stale`);`/health` 是测试钩子,可临时翻 down 触发 503 模拟 24h degraded window |
| `e2e/mocks/mock-audit-agent.mjs` | S25 audited E2EE | 自动生成 Ed25519 keypair + DID (`MOCK_AUDIT_AGENT_DID` 可固定);`/identity` 暴露 DID + MLS KeyPackage 占位;`/invite` 自动 ACK 并签 `cx.audit.accessed` envelope(含 binding_proof),`/accessed` 列出所有 emitted envelope |

共享 helper 在 `e2e/mocks/_shared/`:`keypairs.mjs` 统一封装 Ed25519/RSA 生成 + `b64url`,`inspect.mjs` 提供共用 InspectLog + `/inspect` 中间件。

新增 spec `e2e/tests/harness/mocks-selftest.spec.ts` 是这套 mock 的契约固定点:同时跑 4 个 mock case,任何 mock 行为漂移会被 joint-smoke 立即拦截。Spec 标 `@fully-implemented`,无需服务端配合即可在 `joint-smoke` profile 直接通过。

## 10. 结论

当前 `cotest` 已经是比较完整的 soland/API/协议黑盒测试套件，覆盖了大量后端业务和合规场景，包括注册、联系人、消息、Space、权限和 federation。但它现在不是三方产品级 UI E2E 测试框架。

要满足“联合 yougen、soland、coauth 三方，模拟多个真实用户，多流程验证 UI 正确并保存截图”，需要新增一层 Playwright live E2E，并由 `cotest` 负责编排三方服务和归档产物。建议先以 live soland + yougen dev-login 打通截图和多用户 UI 流程，再接入真实 coauth 注册/登录/session grant，最后扩展到权限矩阵和视觉回归。
