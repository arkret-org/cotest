# Applet 桥接:bot actor + ghost actor + portal realm

## 目标

验证一个外部集成服务以 **applet** 形态接入 arkret 时的完整生命周期:applet registry 提交 controller-signed `ak.schema.applet_package.v1` → soland 通过 `self/applets/install/preview` 生成安装计划并通过 `self/applets/install` commit → 派生 `ak.applet.registration`、颁发 `bot_actor_id` 与 capability grant → typed applet ingress 为外部用户生成 `ghost_actor_id` 并写 portal 消息 → Realm 成员看到 ghost 消息且能沿 DID Document `accountability` 链回溯到 bot / applet registry → admin 撤销 applet install 后,后续 ingress 被拒。

不验证:applet 间消息编排(后续 `extensions/applet-orchestration`)、applet 跨 server 联邦(后续 `federation/applet-federation`)、portal realm 的 RBAC 细节(后续 `authz/portal-realm-rbac`)、applet 计费 / 配额(spec 还在草案)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/extensions/applet-integration.md` §3–§4b — Applet Package、install preview/commit/revoke 与 `bot_actor_id` 颁发
- `arkret-spec/spec/v1/zh/extensions/applet-integration.md` §5 — Ghost actor 的 accountability 模型(`actor_id = ghost_actor_id`、DID Document 的 `accountability` 指向 bot + registry)
- `arkret-spec/spec/v1/zh/extensions/applet-schema.md` — Manifest JSON schema、portal realm 路由约定

## 拓扑

- 1 × soland (principal server) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 1 × mock-applet-registry — 由 cotest runner 的 `-StartMockAppletRegistry` / `-StartMocks` 启动,通过 `COTEST_MOCK_APPLET_REGISTRY_BASE_URL` 注入;由它代表"applet developer"完成 manifest 签名与外部 webhook 转发
- 共享同一 coauth;principal actor 与 bot/ghost actor 的 token 都来自这个 coauth(ghost token 通过 applet manifest 中 `signing_key` 派生,见 spec §5)

## Actors

| 名字 | DID | 在 applet-bridge 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s-applet-<uuid>.example` | principal user / Realm 创建者 / 可对 applet 行使 revoke 的 admin | 测试开始前 |
| applet_service | `did:webvh:z6mkfixture:applet-registry-<uuid>.example` | mock-applet-registry 暴露的开发者身份;签 manifest、为外部用户生成 ghost actor | 测试开始前(由 mock 启动注入) |
| bot_actor | `did:web:bot-<applet_namespace>-<uuid>.example` | applet 注册成功后 soland 颁发的 bot DID;以 member 身份加入 Realm | Phase A 末由 soland 颁发 |
| ghost_actor | `did:web:ghost-<external_user_x>-<uuid>.example` | 外部用户 X 在 portal realm 内的代理身份;由 applet_service 在 Phase C 现场生成 | Phase C 现场颁发(每次外部事件可能复用同一 ghost) |

> 命名约定:`bot_actor_id` 是稳定的(每个 applet 实例一个);`ghost_actor_id` 与外部用户一一对应,跨事件复用,但其 DID Document 始终把 `accountability` 指向同一个 `bot_actor` + `applet_service`。

## Pre-conditions

- alice 通过 `POST /_soland/self/account/register` 注册过(`ensureRegistered`)
- alice 持有有效 dev session token(`POST /_soland/gate/auth/dev-login`)
- alice 的 browser context 通过 `inkson.config.v1` localStorage 注入 server_url / account_did / device_id / session_credential
- `process.env.COTEST_MOCK_APPLET_REGISTRY_BASE_URL` 存在;mock-applet-registry 已经 ready(健康检查 `GET /healthz` 返回 200)
- mock-applet-registry 内置 `applet_service` 的签名密钥;测试只需要调它的 HTTP API,不直接持有密钥

## Steps

### Phase A — applet package install + bot 颁发

1. **applet_service** (通过 mock-applet-registry) 构造 signed applet package:
   - `applet_id = "ak:applet:<uuidv7>"`
   - `namespace = "bridge.demo"`
   - `display_name = "Demo Bridge Applet"`
   - `requested_scopes = ["ak.message.create", "ak.applet.ghost.provision"]`
   - `proof` 由 mock 内置 controller key 生成
2. mock-applet-registry `POST ${COTEST_MOCK_APPLET_REGISTRY_BASE_URL}/sign-package` 返回 `{ applet_package, package_digest }`
3. 测试以 alice 的 admin token 调 soland `POST /_arkret/self/applets/install/preview`,再用返回的 `plan_digest` 调 `POST /_arkret/self/applets/install`
   - 断言:`status = 201`,返回 `{ applet_id, bot_actor_id, registration_event_ref, effective_status }`
   - 记录 `applet_id`、`bot_actor_id`、`registration_event_ref`
4. **断言**:`bot_actor_id` 形如 `did:web:bot-bridge-demo-...`;projection events 中出现 `ak.applet.registration`

### Phase B — bot 加入 Realm

5. **alice** 通过 `/setup` 多步向导建 Realm `R`:
   - title = `"extensions/applet-bridge Demo Realm ${stamp}"`
   - discoverability = `listed`
   - join_rule = `invite`
   - history_visibility = `joined`
   - seed_members = `[]`(bot 走 admin invite 通道,不走 seed)
6. 断言:`realm-lifecycle-strand` 显示 `created ak:realm:...`,记录 `realmId`
7. **alice** 在 `/realms/${realmId}/admin/members` 通过 `invite-member` 邀请 `bot_actor_id`
   - 断言:`realm-admin-panel` 状态文本含 `invited ${bot_actor_id}`
8. **applet_service** 替 bot 接受 invite:`POST ${COTEST_MOCK_APPLET_REGISTRY_BASE_URL}/bot/${applet_id}/accept-invite`,body = `{ realm_id: realmId }`
   - mock 内部会用 bot 的 session token 调 Realm invite accept API
   - 断言:返回 `{ status: "joined" }`
9. **alice** 同步 `/realms/${realmId}/admin/members`,断言 members 列表包含 `bot_actor_id`

### Phase C — 外部事件 → ghost actor 转译

10. mock-applet-registry 模拟外部事件:测试调 `POST ${COTEST_MOCK_APPLET_REGISTRY_BASE_URL}/external-event`,body 形如
    ```json
    {
      "applet_id": "<applet_id>",
      "realm_id": "<realmId>",
      "external_user": { "id": "ext-user-X", "display_name": "External X" },
      "payload": { "kind": "message", "text": "hi from outside ${stamp}" }
    }
    ```
11. mock 内部:
    - 调 soland typed applet ingress `POST /_soland/self/applets/{applet_id}/ghosts`,path 携带 `applet_id`,body 携带 `realm_id`、`external_user` 和 message payload
    - soland 若该 `external_user.id` 没有对应 ghost,在 install record 下颁发 `ghost_actor_id`(DID Document 的 `accountability` 数组里包含 `bot_actor_id` + `applet_service.did`)
    - 返回 `{ ghost_actor_id, message_id }`
12. 断言:返回的 `ghost_actor_id` 形如 `did:web:ghost-ext-user-x-...`
13. **alice** 进 `/timeline/${realmId}`,timeline 包含 `"hi from outside ${stamp}"` 文本
14. **alice** 点击该 timeline-event,断言:
    - 消息卡片显示 ghost 标记(`ghost-actor-badge` testid),且文本含 `External X`
    - `actor_id` 字段 = `ghost_actor_id`
15. 调 soland `GET /_arkret/root/identity/${ghost_actor_id}/did-document`,断言:
    - `accountability` 数组非空
    - 含一个 entry `kind = "bot_actor"`,`did = bot_actor_id`
    - 含一个 entry `kind = "applet_registry"`,`did = applet_service.did`

### Phase D — 链路追溯 UI

16. **alice** 在该消息卡片点 `accountability-trace-button`(inkson UI;若未实现,这一步降级为直接断言 §15 的 HTTP 返回)
    - 断言:面板显示两级链路 — 第一级 bot `bot_actor_id`,第二级 registry `applet_service.did`

### Phase E — Revoke + 后续 ghost 消息被拒

17. **alice** 在 `/realms/${realmId}/admin/access` 或 `/settings/applets`(以 inkson 实际路由为准)对 `applet_id` 执行 revoke:
    - 调 soland `POST /_arkret/self/applets/${applet_id}/revoke`,带 alice token、`effective_scope`、`reason_code` 和 `revoke_mode`
    - 断言:返回 `{ status: "revoked", revoked_at: <ISO> }`
18. 再调 `POST ${COTEST_MOCK_APPLET_REGISTRY_BASE_URL}/external-event`(同 §10,但 text = `"after revoke ${stamp}"`)
    - 断言:mock 拿到的 soland 写消息响应 status = `403` 或 `409`,error code 含 `applet_revoked`
    - **断言**:alice timeline 不出现 `"after revoke ${stamp}"`
19. 已存在的 bot/ghost 记录保留(historic accountability 不能事后被抹去) — 断言:
    - `GET /_arkret/root/identity/${bot_actor_id}/did-document` 仍 200
    - `GET /_arkret/root/identity/${ghost_actor_id}/did-document` 仍 200
    - 两者的 `status` 字段含 `revoked`

## Observable assertions (合并清单)

- 步骤 3-4:applet install 返回 201,`bot_actor_id` 形式正确,并写入 `ak.applet.registration` projection
- 步骤 6:`realmId` 形如 `ak:realm:...`
- 步骤 8-9:bot 出现在 Realm members
- 步骤 11-13:外部事件 30s 内在 alice timeline 出现
- 步骤 14:UI 上 ghost 消息有 ghost badge,actor_id 是 ghost_actor_id
- 步骤 15:DID Document `accountability` 链含 bot + registry
- 步骤 17:revoke 返回 200 + 状态 `revoked`
- 步骤 18:revoke 后再发的 ghost 消息被拒(403/409 + `applet_revoked`),timeline 不出现新文本
- 步骤 19:历史 DID Document 保留,但 `status` 标记为 `revoked`

## Edge cases / sub-tests

- **E4.1 namespace 冲突**:Phase A 之后,mock 再生成一个不同的 `package_id` 但相同 `namespace = "bridge.demo"` 的 package;soland install preview/commit 返回 `409`,error code 含 `applet_namespace_conflict`;首次 applet 不受影响
- **E4.2 capability revoke**:revoke applet 后,bot DID 仍可被 `GET`,但 bot 试图通过 typed bot message route 继续写消息也被拒(403 + `bot_actor_revoked`) — 验证 revoke 是作用在 capability 层而非只挡 ghost 路径
- **E4.3 idempotency**:同一 install body 用相同 `Idempotency-Key` 重复 commit 两次,第二次返回 200 + 与第一次完全相同的 `{ applet_id, bot_actor_id }`;相同 key 但不同 body 返回 `409 idempotency_key_conflict`

主流程之外的 E4.x 子测试建议放在同一个 `tests/extensions/applet-bridge.spec.ts` 的 `test.describe` 内,各自独立建 Realm 或共用 Phase A,以避免 namespace 状态干扰。

## Implementation notes

- soland 已提供 canonical applet runnable surface:`/_arkret/self/applets/install/preview`、`/_arkret/self/applets/install`、`/_arkret/self/applets/{applet_id}/revoke`、`/_arkret/self/applets/{applet_id}/ghosts/provision`、`/_arkret/edge/applet/transactions`,以及 `GET /_arkret/root/identity/{did}/did-document` accountability 查询。当前 portal realm 写入以 space timeline 投影为主,底层仍是本地参考实现。
- mock-applet-registry 提供这些 endpoint:
  - `GET /healthz`
  - `POST /sign-package` → `{ applet_package, package_digest }`
  - `POST /bot/:applet_id/accept-invite` → `{ status }`
  - `POST /external-event` → `{ ghost_actor_id, message_id }` 或错误
- `COTEST_MOCK_APPLET_REGISTRY_BASE_URL` 由 cotest harness 在启动 mock 时注入;mock 自身仍用 `MOCK_APPLET_REGISTRY_PORT` 绑定本地监听端口
- Inkson UI 侧:`ghost-actor-badge`、`accountability-trace-button`、`/settings/applets` 当前都不存在 — 主测试用 timeline 可见性 + HTTP accountability 断言为主
- Portal realm 是 spec §5 引入的"消息归属于 applet 而非 Space"的概念;当前 soland route 返回 `portal_realm_id` 并在 projection payload / content portal metadata 中保留,同时按 `realm_id` 投影到用户 timeline

## 总耗时预估

主流程跑通约 1-5s(单 browser context + 多次 HTTP 直调 mock-applet-registry / soland);E4.1/E4.2/E4.3 各通常小于 1s。
