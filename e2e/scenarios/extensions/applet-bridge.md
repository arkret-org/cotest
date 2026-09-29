# Applet 桥接:bot actor + ghost actor + portal realm

## 目标

验证一个外部集成服务以 **applet** 形态接入 arkret 时的完整生命周期：install 原子接受 registration/grants、Bot managed-actor provision、Bot PCR genesis、accountability/profile；Ghost provision 原子接受同构的四事件单元；Bot/Ghost runtime current resolution 从各自 authority pair 的 PCR cell 派生；Realm 成员看到 Ghost 消息并能追溯 immutable creation/accountability anchors；admin 撤销后，Applet ingress 与绕过该路由的 actor 自签普通 Event 都被通用门禁拒绝。

不验证:applet 间消息编排(后续 `extensions/applet-orchestration`)、applet 跨 server 联邦(后续 `federation/applet-federation`)、portal realm 的 RBAC 细节(后续 `authz/portal-realm-rbac`)、applet 计费 / 配额(spec 还在草案)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/extensions/applet-integration.md` §3–§4b — Applet Package、install preview/commit/revoke 与 `bot_actor_id` 颁发
- `arkret-spec/spec/v1/zh/extensions/applet-integration.md` §3.4、§9.1 — Ghost actor 初始 Profile 的 `accountable_principal_ids` 只指向签署 accountability grant 的 applet service；controller 关系由 registration/install 表达
- `arkret-spec/spec/v1/zh/extensions/applet-schema.md` — Manifest JSON schema、portal realm 路由约定

## 拓扑

- 1 × soland (Station) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (private authentication process) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 1 × mock-applet-registry — 由 cotest runner 的 `-StartMockAppletRegistry` / `-StartMocks` 启动,通过 `COTEST_MOCK_APPLET_REGISTRY_BASE_URL` 注入;由它代表"applet developer"完成 manifest 签名与外部 webhook 转发
- 共享同一 coauth；只有 principal actor（alice）持有 Account session。applet service 没有 Account session，也不走 Account Station 的 `/_arkret/self/events`（`sync/service-http-binding.md` §2.6）；它的写入只经 `POST /_arkret/edge/applet/transactions`，每次投递带 RFC 9421 来源签名（`applet-integration.md` §7.3.1，覆盖集含 `arkret-operation`），每条 Event 是 closed Event Envelope（`event-envelope.schema.json`），唯一 producer proof 为 `producer_proof`，由 registration epoch 捕获的 service signing key（`webhook_auth.key_ref`）签名

## Actors

| 名字 | DID | 在 applet-bridge 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s-applet-<uuid>.example` | principal user / Realm 创建者 / 可对 applet 行使 revoke 的 admin | 测试开始前 |
| applet_service | `did:webvh:z6mkfixture:applet-registry-<uuid>.example` | mock-applet-registry 暴露的开发者身份;签 manifest、为外部用户生成 ghost actor | 测试开始前(由 mock 启动注入) |
| bot_actor | `ak:did_core:<method>:<core>` | controller-signed package 声明、formal registration 接受后生效的稳定 bot actor id;以 member 身份加入 Realm | Phase A package 签署时声明 |
| ghost_actor | `ak:did_core:<method>:<core>` | 外部用户 X 在 portal realm 内的稳定代理 actor id;由 applet_service 在 Phase C 现场选择并 provision | Phase C 首次遇到该外部用户时 |

> `bot_actor_id` / `ghost_actor_id` 都是不可直接解析的 `did_core_id`，不能靠字符串模板反拼 bare
> `did`。测试必须为每个主体构造并发布独立 did:webvh inception，提交完整 method-history evidence，
> 并验证 `project(initial_resolution.did)==actor_id`。durable record 保存 provision/PCR creation anchors，
> current resolution 只从 `(actor_id, actor_station_id)` PCR cell 取得。

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
3. 测试先构造 caller-signed `registration_event` 与 `capability_grant_events[]` 作为 preview authoring basis；soland 返回 target-PS-signed、短期 `authoring_request`，client 将其原样 relay 到 Applet 标准 `POST /_arkret/edge/applet/managed-actors/author`，取得 Applet service/managed actor 真实签名的四 Event closed bundle，再以 `{applet_package, authoring_request, managed_actor_bundle}` 调 `POST /_arkret/self/applets/install`
   - mock 的 JavaScript 层只负责 HTTP 编排和 exact-replay 持久化；closed carrier、proof、package/registration binding 与四 Event 构造统一委托给 `cotest-wire` 使用的 Rust SDK managed-actor authoring kernel，不维护第二套协议判定器。
   - replay 状态中的 registry/service 私钥使用 run-scoped AES-256-GCM key 加密落盘；保留的 joint artifact 只含密文，key 在服务停止后删除。
   - commit 不发送已删除的 `approved_scopes` 旧字段；soland 只验证、记录和提交 caller-signed Events，不代签或重建 Event
   - 断言:`status = 201`,返回 `{ applet_id, bot_actor_id, registration_event_ref, effective_status }`
   - 记录 `applet_id`、`bot_actor_id`、`registration_event_ref`
4. **断言**：`bot_actor_id` 为从独立 did:webvh SCID 投影的 `ak:did_core:webvh:*`；outcome 返回完整 authority pair、provision ref 与 PCR realm id；六类事实和 record 要么全部可见，要么全部不可见。

### Phase B — bot 加入 Realm

5. **alice** 通过 `/setup` 多步向导建 Realm `R`:
   - title = `"extensions/applet-bridge Demo Realm ${stamp}"`
   - discoverability = `listed`
   - join_rule 由普通 Realm membership policy 决定，本场景不声称执行 invite lifecycle transition
   - history_access = `since_join`
   - seed_members = `[]`（install 不写 membership）
6. 断言:`realm-lifecycle-strand` 显示 `created ak:realm:...`,记录 `realmId`
7. 安装本身不创建 membership，registration Event 也不是 Bot 的授权：以 `authorization_ref=registration_event_ref` 投递的 Bot `ak.member.state{join}` 在 transaction outcome 中 `status="rejected"`，且不入 accepted history（§8、§11）。
8. alice 以 Realm 管理员身份为 Bot 签发一条 install 绑定的 grant（`subject=bot_actor_id`，`authority_control/applet_authority` 绑定 `applet_id`、`executed_by=service_id`、`registration_epoch`；§6、§11），再发 directed `ak.invite.create`；Bot 自己的 `ak.invite.accept` 由 Applet service 执行并签名（`actor_id=bot_actor_id`、`executed_by=service`、`authorization_ref=<Bot grant>`、`applet_id`、`producer_proof`），经 transaction rail 投递（`common-fields.md` §4.5：管理员不代写他人 `member.state{join}`）。
   - 断言:transaction outcome `status="accepted"`，accepted history 含该 `ak.invite.accept`，其 `actor_id`/`executed_by` 如上
9. **alice** 同步 `/realms/${realmId}/admin/members`,断言 members 列表包含 `bot_actor_id`

### Phase C — 外部事件 → ghost actor 转译

10. mock-applet-registry 模拟外部事件:测试调 `POST ${COTEST_MOCK_APPLET_REGISTRY_BASE_URL}/external-event`,body 形如
    ```json
    {
      "soland_base_url": "<soland>",
      "destination_id": "<station service did_core_id>",
      "applet_id": "<applet_id>",
      "realm_id": "<realmId>",
      "strand_id": "<portal strand>",
      "authorization_ref": "<Ghost 自己的 ak.message.create grant>",
      "provision_authorization_ref": "<install 的 ak.applet.ghost.provision grant>",
      "external_user": { "id": "ext-user-X", "display_name": "External X" },
      "ghost_creation": { "authoring_request": "…", "managed_actor_bundle": "…", "ghost_actor_did": "…", "external_ref": "…" },
      "payload": { "kind": "message", "text": "hi from outside ${stamp}" }
    }
    ```
    首次调用 `payload.kind="provision"` 只做 provision；Ghost 随后按 Phase B 同样的 grant + invite/accept 流程入 Realm（§9.1：provision 不隐含 membership），再发 `kind="message"`。
11. mock 内部:
    - 正向 provision 前，测试把同一 `applet_managed_control` PCR genesis 单独投递到普通 `/_arkret/self/events`，必须被拒（只能由固定四事件 formal aggregate 注入）
    - 用 active registration service key 生成 RFC 9421 来源签名（覆盖 `arkret-operation`），调 `POST /_arkret/self/applets/{applet_id}/ghosts/provision`；不得用 bearer session 替代
    - 请求是 exact `{authoring_request, managed_actor_bundle}`；Station 独立验证 DID method evidence 和 DID namespace 后原子提交，不代签、不重建
    - ghost 消息是 closed Event Envelope：`actor_id=ghost_actor_id`、`executed_by={kind:service,service_id}`、`authorization_ref=<Ghost 自己的 message grant>`（provision grant 与其回显不授权后续写入，§9.1）、`applet_id`、顶层 signed `external_ref`、唯一 `producer_proof`；不携带 `proofs[]`/`actor_seq`/`hlc`/`prev_refs`/`auth_context` 等 schema 外成员。`event_id` 与 `producer_proof` 由 `cotest-wire` 的 SDK 命令派生/签名。通过 `POST /_arkret/edge/applet/transactions` 提交
    - Realm 为私有明文时，必须在 `plaintext_visible_services` 中显式授权 applet service 的 `message_content`
    - 返回 `{ ghost_actor_id, message_id }`
12. 断言:返回的 `ghost_actor_id` 是合法 `did_core_id`，且与 provision/profile/message 三处逐字相同
13. **alice** 进 `/timeline/${realmId}`,timeline 包含 `"hi from outside ${stamp}"` 文本
14. **alice** 点击该 timeline-event,断言:
    - 消息卡片显示 ghost 标记(`ghost-actor-badge` testid),且文本含 `External X`
    - `actor_id` 字段 = `ghost_actor_id`
15. 问责闭包断言:
    - accepted 消息：`actor_id=ghost_actor_id`、`executed_by=service`、`applet_id`、`authorization_ref=<Ghost message grant>`、`external_ref.protocol="bridge"`；`producer_proof.kind="detached_jws"`、`verification_method=webhook_auth.key_ref`，不带 `signer_resolution_evidence_ref`
    - Ghost `ak.profile.create` 属于 Ghost 自己的 `applet_managed_control` PCR（`realm_id=principal_control_realm_id`），从提交的四事件单元断言 `payload.object.principal_id = ghost_actor_id`、`actor_kind = "integration"`、`accountable_principal_ids = [applet_service.service_id]`，且其 critical `accountability` semantic ref 指向下述 grant
    - 同一 provisioning aggregate 的 `ak.identity.accountability_grant` 在 portal Realm accepted history 中，由 service 署名、`authorization_ref=<provision grant>`，
      `issuer=applet_service.service_id`、`subject=ghost_actor_id`、`grant_status="active"`
    - provision outcome 的 `authorization_ref` 回显 provision grant，且不等于 Ghost message grant

### Phase D — 链路追溯 UI

16. **alice** 在该消息卡片点 `accountability-trace-button`(inkson UI;若未实现,这一步降级为直接断言 §15 的 accepted Event closure)
    - 断言:面板显示 Ghost Profile → service accountability grant，并可由 registration/install 追溯 controller；不得从实现私有 DID Document `accountability` 字段取代该 closure

### Phase E — Revoke + 后续 ghost 消息被拒

17. **alice** 在 `/realms/${realmId}/admin/access` 或 `/settings/applets`(以 inkson 实际路由为准)对 `applet_id` 执行 revoke:
    - 先调 `POST /_arkret/self/applets/${applet_id}/revoke/preview`（outcome 只含 `revoke_plan`），按 plan 为每个 capability revoke intent 签 `ak.capability.revoke{grant_id, expected_revision, reason}`，为每个 membership removal intent 签 `ak.member.state{leave}`（Bot/Ghost 经 invite accept 入场，属 applet-managed membership）
    - 再调 `POST /_arkret/self/applets/${applet_id}/revoke`，携 caller 自算的 `revoke_plan_digest = sha256(JCS(revoke_plan))`、两类 submission 数组和 `Idempotency-Key`
    - 断言:返回 `{ ok: true, status: "complete", revoked_refs: [...] }`
18. 再调 `POST ${COTEST_MOCK_APPLET_REGISTRY_BASE_URL}/external-event`(同 §10,但 text = `"after revoke ${stamp}"`)
    - 断言:mock 拿到的 soland transaction 响应 status = `403`（无 active effective install），error code = `applet_registration_unauthorized`（§7.3.1 失败码）
    - **断言**:alice timeline 不出现 `"after revoke ${stamp}"`
19. 已接受的 registration、Profile 与 accountability grant 仍保留(historic accountability 不能事后被抹去)，同时 revoke outcome 的 `revoked_refs` 至少包含 bot/ghost actor ids，后续 runtime ingress 继续 fail closed
20. revoke 前由 service 自行构造并签名（绕过 mock registry）的一条合法 Ghost `ak.message.create`，revoke 后直接投递到 `/_arkret/edge/applet/transactions`：断言 `403 applet_registration_unauthorized` 且不入 history。Applet service 没有 Account session，不存在经 `/_arkret/self/events` 冒充 Ghost 的路径
21. Applet service 查询 `(actor_id, PCR realm_id)` authoring frontier 得到 `404`，但仅按 actor 查询历史 aggregate frontier 仍为 `200` 且包含原 PCR realm；撤销只关闭 authoring，不删除历史 identity resolution

## Observable assertions (合并清单)

- 步骤 3-4:applet install 返回 201,`bot_actor_id` 形式正确,并写入 `ak.applet.registration` projection
- 步骤 6:`realmId` 形如 `ak:realm:...`
- 步骤 8-9:bot 出现在 Realm members
- 步骤 11-13:外部事件 30s 内在 alice timeline 出现
- 步骤 14:UI 上 ghost 消息有 ghost badge,actor_id 是 ghost_actor_id
- 步骤 15:accepted Profile + accountability grant + registration/install 构成规范问责闭包
- 步骤 17:revoke preview/commit 返回 200 + `status=complete`
- 步骤 18:revoke 后再发的 ghost 消息被拒(403 + `applet_registration_unauthorized`),timeline 不出现新文本
- 步骤 19:历史 accepted 问责事实保留，revoke refs/fence 标记 runtime 已撤销
- 步骤 20-21:绕过 Applet ingress 的普通 Event 仍被 revoke fence 拒绝；PCR authoring frontier 关闭而历史 aggregate frontier 保留

## Edge cases / sub-tests

- **E4.1 namespace 冲突**:Phase A 之后,mock 再生成一个不同的 `package_id` 但相同 `namespace = "bridge.demo"` 的 package;soland install preview/commit 返回 `409`,error code 含 `applet_namespace_conflict`;首次 applet 不受影响
- **E4.2 capability revoke**：revoke 后 Bot/Ghost creation anchors 与历史 resolution 仍可读；测试用正式通用 Event submit 构造 Ghost 自签写入并断言 `applet_revoked`，并断言 combined authoring frontier 关闭、actor-only 历史 frontier 保留；不得调用已删除的私有 typed bot message route。
- **E4.3 idempotency**:同一 install body 用相同 `Idempotency-Key` 重复 commit 两次,第二次返回 200 + 与第一次完全相同的 `{ applet_id, bot_actor_id }`;同一 `(applet_id, effective_scope)` 换 `Idempotency-Key` 再次 commit 返回 `409 duplicate_conflict`（`applet_already_registered` 在 error-code-registry 为 reserved，生产者不得发射）

- **Inbound transaction push**（§7.3、§7.3.1、§11.1）：Bot 消息以 producer-only Event 投递，outcome `accepted` 且 `committed_event_refs` 恰含该 Event；accepted Event 的 `producer_proof` 与提交逐字相同、无 Station 附加签名。同一 Event 换成不验签的 producer proof（外来 key、篡改 jws）逐条 `rejected`；旧 `proofs[]` carrier 整体 `422 schema_violation`。Service 自署写入不带 `executed_by`，`actor_id` 为 install grant 的 subject authority pair `(service_id, target_station_id)`（§4b）。revoke 后投递 `403 applet_registration_unauthorized`，与 revoke 竞争的投递要么唯一接纳、要么不入 history。缺签名 / 伪签名 / 过期窗口分别为 `401 http_signature_required` / `http_signature_invalid` / `signature_window_invalid`。

主流程之外的 E4.x 子测试建议放在同一个 `tests/extensions/applet-bridge.spec.ts` 的 `test.describe` 内,各自独立建 Realm 或共用 Phase A,以避免 namespace 状态干扰。

## Implementation notes

- 主链已 live 化。精确回归命令：

  ```powershell
  .\scripts\run-joint-e2e.ps1 -StartCoauth -StartMockAppletRegistry -RunProfile joint-full -PlaywrightProject chromium -Grep 'applet package installs, bot joins space, ghost actor relays external messages with accountability chain'
  ```

  通过证据：`artifacts/runs/20260726-033554/joint-e2e/playwright-report`。

- canonical surface 包含 `/_arkret/self/applets/install/preview`、Applet service 的 `/_arkret/edge/applet/managed-actors/author`、`/_arkret/self/applets/install`、revoke preview/commit、Ghost preview/commit 与 `/_arkret/edge/applet/transactions`；不得以私有路由或 Station 代签替代标准 co-sign relay。
- mock-applet-registry 提供这些 endpoint:
  - `GET /healthz`
  - `POST /sign-package` → `{ applet_package, package_digest }`
  - 不提供 Bot membership 私有 endpoint；Bot/Ghost 入场是测试经 transaction rail 投递的 Service 执行 `ak.invite.accept`。
  - `POST /external-event` → `{ ghost_actor_id, message_id }` 或错误
- `COTEST_MOCK_APPLET_REGISTRY_BASE_URL` 由 cotest harness 在启动 mock 时注入;mock 自身仍用 `MOCK_APPLET_REGISTRY_PORT` 绑定本地监听端口
- Inkson UI 侧:`ghost-actor-badge`、`accountability-trace-button`、`/settings/applets` 当前都不存在 — 主测试用 timeline 可见性 + HTTP accountability 断言为主
- Portal realm 是 spec §5 引入的"消息归属于 applet 而非 Space"的概念;当前 soland route 返回 `portal_realm_id` 并在 projection payload / content portal metadata 中保留,同时按 `realm_id` 投影到用户 timeline

## 总耗时预估

主流程跑通约 1-5s(单 browser context + 多次 HTTP 直调 mock-applet-registry / soland);E4.1/E4.2/E4.3 各通常小于 1s。
