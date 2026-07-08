# Spaces — Admin Section Route (Diagnostic Probe)

> **诊断 / 回归 probe**:这不是业务 scenario,是为了拦截 inkson 一个已知的 routing race 而存在 — 当 URL 是 `/realms/<id>/admin/<section>` 且用户**没有点 tab**(直接 hard navigation)时,`RealmAdminPanel` 必须从 URL 读出 `active_section`,而不是默认回到 `overview`。这个 race 历史上让 `invite-member` / `refresh-members-button` 在某些业务 scenario 里"看不见而 fail",诊断成本很高,所以单独抽出一条 probe。

## 目标

通过 Playwright 直接 `page.goto("/realms/<realmId>/admin/members")`(不点 admin 导航的 tab,也不经任何 in-app 链接跳转),断言:
1. `realm-admin-panel` 在 hard nav 完成后可见
2. `realm-admin-active-section` 这个 testid 反映 URL 路径段(本 probe 期望文本为 `"Members"`)
3. 上述断言在 fresh browser context、fresh login session 下成立 — 也就是说,即使没有任何 client-side state 残留,RealmAdminPanel 也必须从 URL 推出来正确的 active section

不验证:invite-member / refresh-members-button 等具体 admin 操作本身(那是 `messaging/triad-collaboration`、`spaces/knock-application` 等业务 scenario 的事);其他 admin section(`settings` / `roles` / `audit` …)的等价 routing 行为(本 probe 只覆盖 `members`,其他 section 如果有 routing race 应该再加一条对应 probe)。

## Spec 锚点

本 probe 没有 cokret-spec § 锚点 — 它锚定的是 **inkson 自己的 routing 约定**:当 URL 是 `/realms/<id>/admin/<section>` 时,`RealmAdminPanel` 应通过 React Router 把 `section` 解析进 `active_section` 状态,并把人类可读名称(`"Members"`、`"Settings"` 等)渲染到 `data-testid="realm-admin-active-section"` 里。

实现锚点:[`tests/spaces/admin-section-route.spec.ts`](../../tests/spaces/admin-section-route.spec.ts) 是本 probe 的唯一 spec 文件,共 1 个 live test,无 fixme。

## 拓扑

- 1 × soland(提供 Realm 创建)
- 1 × coauth(发 alice 的 dev session)
- 1 × inkson(被测对象;routing 行为)
- 1 × Playwright browser context — 一次性 alice user

不需要 mocks、不需要 DualSoland。

## Actors

| 名字 | DID | 角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-admin-probe-<uuid>.example` | 单 actor;建一个空间然后直接 hard nav 到 `/admin/members` | 测试开始前 |

## Pre-conditions

- `alice` 通过 `ensureRegistered(request, alice)` 注册
- `alice` 通过 `issueDevSession(request, alice)` 拿 token
- `alice` 在 inkson 通过 `openUserPage(browser, alice, { sessionCredential })` 起 browser context(`inkson.config.v1` localStorage 注入)
- `alice` 通过 `JointUserPage.createRealm(...)` 建一个 `discoverability=listed, joinRule=invite` 的 Realm,记录 `realmId`

## Steps

1. **alice** `page.goto("/realms/${realmId}/admin/members", { waitUntil: "domcontentloaded" })` — 关键:hard navigation,不点任何 tab,不经 in-app 链接
2. 等 `realm-admin-panel` 可见(timeout 120s — inkson 初始化和 server claim 可能慢)
3. 等 `realm-admin-active-section` 可见(timeout 30s)
4. 读 `realm-admin-active-section` 的 `textContent().trim()`,日志输出供失败诊断
5. 断言:`text === "Members"`

整个 spec 是一个单 `test(...)`,无 phase 拆分。

## Observable assertions

- `realm-admin-panel` 在 hard nav 后 ≤ 120s 内可见
- `realm-admin-active-section` 在 panel 可见后 ≤ 30s 内出现
- `realm-admin-active-section` 的文本必须是 `"Members"`(精确比较,trim 后);如果是 `"Overview"` 或空字符串,说明 inkson 把 URL `section` 段丢了,routing race 复现

## Implementation notes

- **历史背景**:本 probe 的出现是因为 `messaging/triad-collaboration` Phase C 与 `spaces/knock-application` Phase B 都遇到过 `invite-member` 按钮"渲染不出来"的问题,人工 trace 发现 `RealmAdminPanel` 在 hard nav 时把 `active_section` 误初始化为 `overview`,导致 members section 没渲染。本 probe 把这个 race 单独抽出,fail 时无歧义指向 inkson routing 而不是 invite 逻辑
- **不要混进 invite/role 业务断言**:本 probe 故意只读 `active_section` 文本,不点 invite 按钮、不调 invite API — 任何额外断言都会模糊"是 routing fail 还是 invite fail"的判断
- **120s 超时不是 routing 问题的征兆**:首次加载 inkson 的 React bundle + soland 初始 claim 在 cold start 下可能慢,本 spec 容忍长 timeout,只在 `active_section` 文本错时 fail
- **若以后想覆盖更多 section**:复制本 probe,把 `members` 换成 `settings` / `roles` / `audit`,断言文本换成对应的人类可读名;不要在本 spec 里 loop section,会让失败时定位变难
- **配套 testid 约定**:inkson `RealmAdminPanel` 必须暴露:
  - `data-testid="realm-admin-panel"` — 整个 admin panel 容器
  - `data-testid="realm-admin-active-section"` — 文本节点,显示当前 section 的人类可读名

## 总耗时预估

单次跑约 30-60s(主要是 inkson 冷启动 + soland 注册 + Realm 创建;真正的 routing 断言部分 < 1s)。
