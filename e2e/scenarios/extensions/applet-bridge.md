# Applet 桥接:bot actor + ghost actor + portal realm

## 目标

验证一个外部集成服务以 **applet** 形态接入 contrix 时的完整生命周期:applet 提交 signed manifest 注册 → soland 验证 manifest + 颁发 `bot_actor_did` → bot 加入 space → applet 接到外部 webhook → 为外部用户生成 `ghost_actor_did` → 以 ghost 身份在 portal realm 写消息 → space 成员看到 ghost 消息且能沿 DID Document `accountability` 链回溯到 bot / applet registry → admin 撤销 applet 权限后,后续 ghost 消息被拒。

不验证:applet 间消息编排(后续 `extensions/applet-orchestration`)、applet 跨 server 联邦(后续 `federation/applet-federation`)、portal realm 的 RBAC 细节(后续 `authz/portal-realm-rbac`)、applet 计费 / 配额(spec 还在草案)。

## Spec 锚点

- `contrix-spec/spec/v1/zh/extensions/applet-integration.md` §3 — Applet manifest 结构(`manifest_id`、`namespace`、`capabilities`、`signing_key`)
- `contrix-spec/spec/v1/zh/extensions/applet-integration.md` §4 — 注册流程与 `bot_actor_did` 颁发
- `contrix-spec/spec/v1/zh/extensions/applet-integration.md` §5 — Ghost actor 的 accountability 模型(`actor_id = ghost_actor_did`、DID Document 的 `accountability` 指向 bot + registry)
- `contrix-spec/spec/v1/zh/extensions/applet-schema.md` — Manifest JSON schema、portal realm 路由约定

## 拓扑

- 1 × soland (principal server) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 1 × mock-applet-registry — 由并行任务产出的 mock,监听 `http://127.0.0.1:${MOCK_APPLET_REGISTRY_PORT}`;由它代表"applet developer"完成 manifest 签名与 ghost actor 颁发的对外 surface
- 共享同一 coauth;principal actor 与 bot/ghost actor 的 token 都来自这个 coauth(ghost token 通过 applet manifest 中 `signing_key` 派生,见 spec §5)

## Actors

| 名字 | DID | 在 applet-bridge 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:web:alice-s-applet-<uuid>.example` | principal user / space 创建者 / 可对 applet 行使 revoke 的 admin | 测试开始前 |
| applet_service | `did:web:applet-registry-<uuid>.example` | mock-applet-registry 暴露的开发者身份;签 manifest、为外部用户生成 ghost actor | 测试开始前(由 mock 启动注入) |
| bot_actor | `did:web:bot-<applet_namespace>-<uuid>.example` | applet 注册成功后 soland 颁发的 bot DID;以 member 身份加入 space | Phase A 末由 soland 颁发 |
| ghost_actor | `did:web:ghost-<external_user_x>-<uuid>.example` | 外部用户 X 在 portal realm 内的代理身份;由 applet_service 在 Phase C 现场生成 | Phase C 现场颁发(每次外部事件可能复用同一 ghost) |

> 命名约定:`bot_actor_did` 是稳定的(每个 applet 实例一个);`ghost_actor_did` 与外部用户一一对应,跨事件复用,但其 DID Document 始终把 `accountability` 指向同一个 `bot_actor` + `applet_service`。

## Pre-conditions

- alice 通过 `POST /api/v1/account/register` 注册过(`ensureRegistered`)
- alice 持有有效 dev session token(`POST /api/v1/auth/dev-login`)
- alice 的 browser context 通过 `yougen.config.v1` localStorage 注入 server_url / account_did / device_id / session_token
- `process.env.MOCK_APPLET_REGISTRY_PORT` 存在;mock-applet-registry 已经 ready(健康检查 `GET /healthz` 返回 200)
- mock-applet-registry 内置 `applet_service` 的签名密钥;测试只需要调它的 HTTP API,不直接持有密钥

## Steps

### Phase A — applet 注册 + bot 颁发

1. **applet_service** (通过 mock-applet-registry) 构造 signed manifest:
   - `manifest_id = "applet:bridge:demo-${stamp}"`
   - `namespace = "bridge.demo"`
   - `display_name = "Demo Bridge Applet"`
   - `capabilities = ["realm:portal", "message:write", "actor:provision-ghost"]`
   - `signing_key` 由 mock 内置
2. mock-applet-registry `POST ${MOCK_APPLET_REGISTRY_PORT}/sign-manifest` 返回 `{ manifest, signature, signing_did }`
3. 测试以 alice 的 admin token 调 soland `POST /api/v1/extensions/applets/register`,body = `{ manifest, signature }`
   - 断言:`status = 201`,返回 `{ applet_id, bot_actor_did, portal_realm_id }`
   - 记录 `applet_id`、`bot_actor_did`、`portal_realm_id`
4. **断言**:`bot_actor_did` 形如 `did:web:bot-bridge-demo-...`;`portal_realm_id` 形如 `cx:realm:portal:...`

### Phase B — bot 加入 space

5. **alice** 通过 `/setup` 多步向导建空间 `S`:
   - title = `"extensions/applet-bridge Demo Space ${stamp}"`
   - discoverability = `listed`
   - join_rule = `invite`
   - history_visibility = `joined`
   - seed_members = `[]`(bot 走 admin invite 通道,不走 seed)
6. 断言:`space-lifecycle-flow` 显示 `created cx:space:...`,记录 `spaceId`
7. **alice** 在 `/space/${spaceId}/admin/members` 通过 `invite-member` 邀请 `bot_actor_did`
   - 断言:`space-admin-panel` 状态文本含 `invited ${bot_actor_did}`
8. **applet_service** 替 bot 接受 invite:`POST ${MOCK_APPLET_REGISTRY_PORT}/bot/${applet_id}/accept-invite`,body = `{ space_id: spaceId }`
   - mock 内部会用 bot 的 session token 调 soland `POST /api/v1/spaces/${spaceId}/invite/accept`
   - 断言:返回 `{ status: "joined" }`
9. **alice** 同步 `/space/${spaceId}/admin/members`,断言 members 列表包含 `bot_actor_did`

### Phase C — 外部事件 → ghost actor 转译

10. mock-applet-registry 模拟外部事件:测试调 `POST ${MOCK_APPLET_REGISTRY_PORT}/external-event`,body 形如
    ```json
    {
      "applet_id": "<applet_id>",
      "space_id": "<spaceId>",
      "external_user": { "id": "ext-user-X", "display_name": "External X" },
      "payload": { "kind": "message", "text": "hi from outside ${stamp}" }
    }
    ```
11. mock 内部:
    - 如果该 `external_user.id` 没有对应 ghost,调 soland `POST /api/v1/extensions/applets/${applet_id}/ghosts` 颁发 `ghost_actor_did`(DID Document 的 `accountability` 数组里包含 `bot_actor_did` + `applet_service.did`)
    - 用 ghost session token 在 `portal_realm_id` 内写消息(`POST /api/v1/realms/${portal_realm_id}/messages`,带 `space_id` 路由)
    - 返回 `{ ghost_actor_did, message_id }`
12. 断言:返回的 `ghost_actor_did` 形如 `did:web:ghost-ext-user-x-...`
13. **alice** 进 `/timeline/${spaceId}`,timeline 包含 `"hi from outside ${stamp}"` 文本
14. **alice** 点击该 timeline-event,断言:
    - 消息卡片显示 ghost 标记(`ghost-actor-badge` testid),且文本含 `External X`
    - `actor_id` 字段 = `ghost_actor_did`
15. 调 soland `GET /api/v1/identity/${ghost_actor_did}/did-document`,断言:
    - `accountability` 数组非空
    - 含一个 entry `kind = "bot_actor"`,`did = bot_actor_did`
    - 含一个 entry `kind = "applet_registry"`,`did = applet_service.did`

### Phase D — 链路追溯 UI

16. **alice** 在该消息卡片点 `accountability-trace-button`(yougen UI;若未实现,这一步降级为 fixme + 直接断言 §15 的 HTTP 返回)
    - 断言:面板显示两级链路 — 第一级 bot `bot_actor_did`,第二级 registry `applet_service.did`

### Phase E — Revoke + 后续 ghost 消息被拒

17. **alice** 在 `/space/${spaceId}/admin/access` 或 `/settings/applets`(以 yougen 实际路由为准)对 `applet_id` 执行 revoke:
    - 调 soland `POST /api/v1/extensions/applets/${applet_id}/revoke`,带 alice token
    - 断言:返回 `{ status: "revoked", revoked_at: <ISO> }`
18. 再调 `POST ${MOCK_APPLET_REGISTRY_PORT}/external-event`(同 §10,但 text = `"after revoke ${stamp}"`)
    - 断言:mock 拿到的 soland 写消息响应 status = `403` 或 `409`,error code 含 `applet_revoked`
    - **断言**:alice timeline 不出现 `"after revoke ${stamp}"`
19. 已存在的 bot/ghost 记录保留(historic accountability 不能事后被抹去) — 断言:
    - `GET /api/v1/identity/${bot_actor_did}/did-document` 仍 200
    - `GET /api/v1/identity/${ghost_actor_did}/did-document` 仍 200
    - 两者的 `status` 字段含 `revoked`

## Observable assertions (合并清单)

- 步骤 3-4:applet register 返回 201,`bot_actor_did` / `portal_realm_id` 形式正确
- 步骤 6:`spaceId` 形如 `cx:space:...`
- 步骤 8-9:bot 出现在 space members
- 步骤 11-13:外部事件 30s 内在 alice timeline 出现
- 步骤 14:UI 上 ghost 消息有 ghost badge,actor_id 是 ghost_actor_did
- 步骤 15:DID Document `accountability` 链含 bot + registry
- 步骤 17:revoke 返回 200 + 状态 `revoked`
- 步骤 18:revoke 后再发的 ghost 消息被拒(403/409 + `applet_revoked`),timeline 不出现新文本
- 步骤 19:历史 DID Document 保留,但 `status` 标记为 `revoked`

## Edge cases / sub-tests

- **E4.1 namespace 冲突**:Phase A 之后,mock 再用一个不同的 `manifest_id` 但相同 `namespace = "bridge.demo"` 注册;soland 返回 `409`,error code 含 `applet_namespace_conflict`;首次 applet 不受影响
- **E4.2 capability revoke**:revoke applet 后,bot DID 仍可被 `GET`,但 bot 试图直接 `POST /api/v1/spaces/${spaceId}/messages` 也被拒(403 + `bot_actor_revoked`) — 验证 revoke 是作用在 capability 层而非只挡 ghost 路径
- **E4.3 idempotency**:同一 `manifest_id` 用相同 `Idempotency-Key` 重复 register 两次,第二次返回 200 + 与第一次完全相同的 `{ applet_id, bot_actor_did }`;不同 `Idempotency-Key` 但相同 `manifest_id` 返回 `409 applet_already_registered`

主流程之外的 E4.x 子测试建议放在同一个 `tests/extensions/applet-bridge.spec.ts` 的 `test.describe` 内,各自独立建空间或共用 Phase A,以避免 namespace 状态干扰。

## Implementation notes

- soland 当前 **没有** `/api/v1/extensions/applets/*` 路由(spec 里也是草案);整个主测试以 `test.fixme` 起步,等待 `// soland gap: applet manifest verifier + bot/ghost DID provisioning + portal realm routing 未实现` 这个 gap 关闭
- mock-applet-registry 由并行任务产出;它需要至少这几个 endpoint:
  - `GET /healthz`
  - `POST /sign-manifest` → `{ manifest, signature, signing_did }`
  - `POST /bot/:applet_id/accept-invite` → `{ status }`
  - `POST /external-event` → `{ ghost_actor_did, message_id }` 或错误
- `MOCK_APPLET_REGISTRY_PORT` 由 cotest harness 在启动 mock 时注入(同 `COTEST_MOCK_WITNESS_BASE_URL` 的模式);测试中直接读 `process.env.MOCK_APPLET_REGISTRY_PORT`
- Yougen UI 侧:`ghost-actor-badge`、`accountability-trace-button`、`/settings/applets` 当前都不存在 — 主测试用 HTTP 断言为主,UI 断言挂 fixme
- Portal realm 是 spec §5 引入的"消息归属于 applet 而非 space"的概念;在 timeline 渲染时仍以 space_id 投影,但底层存储路径不同 — 这部分依赖 soland 的 realm 路由,属于上面提到的 soland gap

## 总耗时预估

主流程跑通约 30-45s(单 browser context + 多次 HTTP 直调 mock-applet-registry / soland);E4.1/E4.2/E4.3 各 +5-10s。fixme 阶段实际只跑 §15-§18 的 HTTP 骨架,会更快。
