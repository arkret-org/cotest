# MIMI federation 互通

## 目标

验证 Arkret 与外部 MIMI (IETF Messaging Interoperability) 网络通过 MIMI Provider Facade 互通的完整链路:Realm 声明 `federation_profile = "mimi_interop"` → 外部 MIMI 用户经 facade 申请加入 → soland 通过 facade 验证 MIMI identity 并生成 pairwise DID → 双向消息在 Arkret Strand/Message 与 MIMI room/event 之间双向翻译 → consent / E2EE / content kind 在跨网络边界上得到正确处理。

不验证:同质 Arkret server 之间的联邦 (见 federation/cross-server)、Matrix 专属桥接 (out of scope for v1 core)、MIMI Provider Facade 本身的内部实现细节 (它是 extension profile,v1 core 不要求实现)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/extensions/mimi-interop.md` §1 — MIMI Provider Facade 总览;Arkret 把外部 MIMI 网络当作一个外部 federation peer 看待
- `arkret-spec/spec/v1/zh/extensions/mimi-interop.md` §2 — Realm `federation_profile = "mimi_interop"` 字段语义;暴露 MIMI endpoint
- `arkret-spec/spec/v1/zh/extensions/mimi-interop.md` §3 — Room binding:Arkret Strand ↔ MIMI room 的双向映射;event ↔ Message 翻译
- `arkret-spec/spec/v1/zh/extensions/mimi-interop.md` §4 — Content mapping:MIMI 标准 content type ↔ `ak.morph` content kind;未知类型 quarantine
- `arkret-spec/spec/v1/zh/extensions/mimi-interop.md` §5 — Policy mapping:Arkret join_rule / history_visibility ↔ MIMI room policy
- `arkret-spec/spec/v1/zh/extensions/mimi-interop.md` §6 — Identity bridging:MIMI 用户 → pairwise DID;同一个 MIMI 身份在不同 Realm 中产生不同 pairwise DID
- `arkret-spec/spec/v1/zh/extensions/mimi-interop.md` §7 — E2EE 边界:MIMI 可能使用不同的 group encryption (MLS via IETF profile);transcript binding 或 downgrade 标记

## 拓扑

- 1 × soland (principal server,声明支持 MIMI 互通) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 1 × mimi_facade (cotest mock,模拟 MIMI Provider Facade) — 由 `run-joint-e2e.ps1 -StartMockMimiFacade` 或 `-StartMocks` 启动,并通过 `COTEST_MOCK_MIMI_FACADE_BASE_URL` 注入

(soland 与 coauth 都是 cotest 现有 harness 直接提供的;mimi_facade 是新的可选外部组件,在 v1 core 不必需。)

## Actors

| 名字 | DID | 在 extensions/mimi-federation 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s1-<uuid>.example` | Arkret principal,Realm owner;声明支持 MIMI | 测试开始前 |
| bob_mimi | `did:pairwise:<realm-scope>/<facade-mapped-id>` | 外部 MIMI 网络用户,通过 facade 映射为 pairwise DID | facade 在 Phase C 中按需 mint |
| mimi_facade | (no DID — 是 server-side 适配器,不是 principal) | mock / stub,模拟 MIMI Provider Facade | 测试 setup 阶段启动 (可选) |

## Pre-conditions

- alice 通过 `POST /_soland/self/account/register` 注册 (与现有 `ensureRegistered` 行为一致)
- alice 持有有效 dev session token (`POST /_soland/gate/auth/dev-login`)
- alice 的 browser context 通过 `inkson.config.v1` localStorage 注入 server_url + account_did + device_id + session_credential
- soland 配置中启用了 `extensions.mimi_interop = true` (extension profile);如果未启用,整个 spec 应该跳过而非失败
- mimi_facade mock 在测试运行时可达,且预置了 bob_mimi 这一个 MIMI 身份;mock helper 已在 `helpers/mimi-facade.ts` 提供,真实 soland/inkson federation 仍由当前 `.fixme` 锚定

## Steps

### Phase A — Realm 声明支持 MIMI

1. **alice** 通过 `/setup` 多步向导建 Realm `R`:
   - title = `"extensions/mimi-federation MIMI Realm ${stamp}"`
   - discoverability = `listed`
   - join_rule = `invite`
   - history_visibility = `joined`
   - `ak.realm.federation_profile = "mimi_interop"` ← 关键:声明该 Realm 暴露 MIMI 互通 endpoint
2. 断言:`realm-lifecycle-strand` 显示 `created ak:realm:...`,记录 `realmId`
3. 断言:Realm 的 `federation-profile-indicator` testid 渲染、文本含 `mimi_interop`
4. MIMI 互通暴露面走 spec 注册的协议面(SPEC-CR-020:零新增 operation,不存在 `/_arkret/self/realm/:id/federation/mimi/*` 端点):
   - 断言:`GET /_arkret/describe` 宣告 `mimi_interop` extension 支持
   - 断言:`GET /_arkret/open/mimi/provider-directory`(`ak.open.mimi.query.provider_directory`)返回 200 的 MIMI provider feature profile
   - room binding 通过 `POST /_arkret/open/mimi/strands/{strand_id}/update`(`ak.open.mimi.command.update_room`)以 `ak.mimi.room_binding` 建立,记录 `room_binding` 的 `mimi_room_uri`

### Phase B — bob_mimi 经 MIMI federation 申请加入

5. mimi_facade (mock) 接收一个来自外部 MIMI 网络的 "join request",目标是 alice 的 `room_binding_id`:
   - facade 把它翻译为 Arkret 的 `ak.invite.request` (或 knock,取决于 Realm 的 join_rule),投递到 soland
6. 断言:soland 收到 facade 投递的请求,产生 `ak.morph.federation_inbound = "mimi"` 事件,记录 `inbound_request_id`
7. alice 的 `/realm/${realmId}/admin` 看到 inbound request,标记来源 `mimi`
   - 断言:`federation-inbound-panel` 渲染,含 `mimi` 标签;`inbound-request-item` 数量 ≥ 1

### Phase C — Identity bridging:MIMI identity → pairwise DID

8. alice 在 admin panel 中点 "approve" inbound MIMI request
9. soland 调 facade 取 bob_mimi 的 MIMI identity 证明 (MIMI handle、key material、network of origin)
10. soland 验证 facade 返回的 identity 证明,通过 `extensions/mimi-interop` §6 的规则生成 pairwise DID:
    - DID = `did:pairwise:${realmId}/${hash(bob_mimi.mimi_handle, realmId.salt)}`
    - 同一个 bob_mimi 在不同 Realm 中得到不同的 pairwise DID(不可关联)
11. 断言:approve 是事件面动作(不存在 `/_arkret/self/realm/:id/federation/mimi/approve` 端点)——alice 在 admin panel(inkson UI 或 `/_soland/` 产品面)执行 approve 后,事件面出现针对 pairwise DID 的 `ak.member.state{membership=join}` 事件,pairwise DID 符合 `did:pairwise:...` 形态
12. 断言:bob_mimi 现在是 Realm `R` 的成员——通过 `/_arkret/self/events` 查询(`queryRealmEventsApi`)读取 `ak.member.state` 事件流,包含该 pairwise DID 且带 `mimi` 来源标记(不存在 `GET /_arkret/self/realm/:id/members` 端点)

### Phase D — 双向消息 + content/policy mapping

13. **alice** 进 `/timeline/${realmId}`,发消息 `M1 = "alice hello mimi ${stamp}"`
    - 断言:`timeline` 出现 `M1`、`write-status` 文本含 `persisted`
14. soland 通过 facade 把 `M1` 翻译为 MIMI event,投递到 MIMI 网络
    - 断言:facade mock 记录到一条 outbound MIMI event,内容含 `M1` 的文本
    - 断言:soland 的 message 上有 `ak.morph.federation_outbound = "mimi"`、`mimi_event_id` 字段
15. mimi_facade mock 模拟 bob_mimi 在 MIMI 网络发一条消息 `MM2 = "bob_mimi greet ${stamp}"`,facade 把它翻译为 Arkret Message 投递到 soland
16. 断言:alice 的 `/timeline/${realmId}` 在 30s 内出现 `MM2`,发送者显示为 bob_mimi 的 pairwise DID
17. 断言:`MM2` 上有 `ak.morph.federation_inbound = "mimi"`、`mimi_origin_event_id` 字段
18. **alice** 回复 `MM2`,发 `M3 = "alice reply to bob_mimi ${stamp}"`
    - 断言:`M3` 渲染、`chat-reply-indicator` 指向 `MM2`
    - 断言:facade mock 记录到第二条 outbound MIMI event,reply 关系映射到 MIMI 的 `m.in_reply_to` 等价字段

### Phase E — Consent 在 MIMI 互通中应用

19. alice 收到 bob_mimi 的请求 (Phase B 的 inbound),实际上隐含了一次 consent 决策:approve 等价于授予 bob_mimi 在该 Realm 中的成员权限,但**不**等价于跨 Realm 的全局 consent
20. 断言:bob_mimi 的 pairwise DID 只对当前 Realm `R` 有效;尝试在另一个 Realm `R2` 中以同一 pairwise DID 投递消息应被拒绝
21. cross-link 到 identity/consent-grant scenario:Arkret 的 consent strand 在 MIMI 互通中由 pairwise DID 的 scoping 隐式提供

## Observable assertions (合并清单)

- 步骤 2 之后:`realmId` 形如 `ak:realm:...`,`federation_profile` 字段 = `mimi_interop`
- 步骤 4:`/_arkret/describe` 宣告 mimi_interop;`/_arkret/open/mimi/provider-directory` 可达;Realm 与 MIMI room_binding 经 `/_arkret/open/mimi/strands/{strand_id}/update` 绑定
- 步骤 6-7:facade 投递的 inbound request 在 alice 的 admin panel 中可见,标记 `mimi` 来源
- 步骤 11-12:approve 之后生成 pairwise DID,事件面出现该 pairwise DID 的 `ak.member.state{membership=join}`,bob_mimi 成为 Realm 成员
- 步骤 14:alice 发的 `M1` 被 facade 翻译为 outbound MIMI event
- 步骤 16-17:bob_mimi 在 MIMI 网络发的消息经 facade 翻译为 Arkret Message,显示在 alice timeline
- 步骤 18:reply 关系在 MIMI ↔ Arkret 双向保留
- 步骤 20:pairwise DID 不能跨 Realm 复用

## Edge cases / sub-tests

- **E5.1 MIMI endpoint 不可达 → federation fallback (本地停留)**:alice 发 `M1` 时 facade 不可达 (timeout / 5xx);消息应该正常存入 soland 本地、对 Arkret 成员可见,但不投递到 MIMI;消息上挂 `ak.morph.federation_outbound_status = "deferred"`,等 facade 恢复后重试
- **E5.2 E2EE 在 MIMI 中的转换**:MIMI 可能使用不同的 group encryption (e.g., MLS via IETF profile);Arkret 的 E2EE message 进入 MIMI 时,要么有 transcript binding 桥(两套 group key 都能解密),要么留下明确的 `ak.morph.e2ee_downgrade = "mimi_bridge"` 标记;两种情况都不能静默泄露明文
- **E5.3 content type 差异:unknown content kind quarantine**:bob_mimi 经 MIMI 发了一条 content type 是 Arkret 不支持的 (e.g., MIMI 特有的 `m.location.share.live`);facade 翻译时无法映射,该消息进入 soland 时被 quarantine,挂 `ak.morph.unknown_content_kind = "<mimi.type>"`;timeline 渲染为 "unsupported content from MIMI" 占位,而不是丢弃也不是渲染原始 payload

后两条建议拆成独立的小 spec(`extensions/mimi-federation.e2ee`、`extensions/mimi-federation.content`),保持主 scenario 紧凑。

## Implementation notes

- MIMI Provider Facade 是 **extension profile**,v1 core 不要求实现。业务 spec 在 facade mock 缺席时应跳过或保持 fixme,而不是 fail
- pairwise DID 的生成规则参见 `arkret-spec/spec/v1/zh/extensions/mimi-interop.md` §6;关键点是同一个 MIMI 身份在不同 Realm 得到不同 DID(unlinkability)
- soland gap (当前):MIMI Provider Facade 绑定、`federation_profile = "mimi_interop"` Realm 字段、identity bridging 到 pairwise DID、outbound retry 仍未形成完整业务链路。已落地的服务端面包括 room binding、MIMI ingress 到 canonical timeline、E2EE boundary policy(未标记 E2EE 明文拒绝;transcript binding / explicit downgrade 可过)、unknown content kind quarantine。
- `helpers/mimi-facade.ts` 提供 `createMimiFacadeClient()`;harness 自检 [`harness/mocks-selftest`](../harness/mocks-selftest.md) 负责锁住 facade mock 契约。
- 与 `messaging/triad-collaboration` 的差别:这里的 "晚到成员" 不是 history_visibility 测试,而是跨 federation boundary 的 identity bridging 测试;消息双向不是 Arkret-Arkret 而是 Arkret-MIMI

## 总耗时预估

facade mock 已实装;E5.2/E5.3 已是 live soland API 覆盖,主业务流与 E5.1 outbound fallback 仍为 fixme。当前 live 边界测试预计 < 10s;soland/inkson 侧 federation profile 落地后,单次完整业务 spec 预计约 90-120s(2 个 actor 但跨 federation,翻译延迟、approve 流程、多次双向消息)。
