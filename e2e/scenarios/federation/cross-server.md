# 跨服务器联邦

## 目标

验证两个独立 principal server 之间的联邦推送能完成完整的协作链路:跨服务器邀请、被邀方接受、双向消息推送、anchor frontier 收敛、撤销服务委托后停止推送。证明协议是 federated 的 — 单一服务器不是全局权威,信任根是签名 Event + RFC 9421 HTTP Message Signature + 服务绑定快照。

不验证:第三方邮件邀请 (后续 invites/third-party,本 scenario 用 DID-to-DID 直接邀请)、knock 审核 (spaces/knock-application)、moderation (spaces/moderation-ban)。

## Spec 锚点

- `cokret-spec/spec/v1/zh/sync/federation.md` §2.1 — Event Chain 是信任锚点
- `cokret-spec/spec/v1/zh/sync/federation.md` §2.2 — Principal Server 是受控同步边界,不是全局权威
- `cokret-spec/spec/v1/zh/sync/federation.md` §3.1-§3.2 — 基于 DID 的服务器身份 + RFC 9421 请求签名
- `cokret-spec/spec/v1/zh/sync/federation.md` §4.1 — Push 协议、`POST /_cokret/peer/federation/push-operations` 请求字段
- `cokret-spec/spec/v1/zh/sync/federation.md` §4.1.0 — Push 时序图(信任根说明)
- `cokret-spec/spec/v1/zh/sync/federation.md` §4.1.1 — 批量推送幂等 (`(origin, destination, event_id)` 去重)
- `cokret-spec/spec/v1/zh/sync/federation.md` §4.2 — Pull / Backfill (`pull-operations`)
- `cokret-spec/spec/v1/zh/sync/federation.md` §4.5 — Fork Detection / Frontier Exchange
- `cokret-spec/spec/v1/zh/sync/federation.md` §5.1 — 跨域邀请流程 (6 步)
- `cokret-spec/spec/v1/zh/sync/federation.md` §4.4 — Capability Revoke Fanout

## 拓扑

```
                    +-------+
                    | coauth|  (shared auth server)
                    +---+---+
                        |
        +---------------+---------------+
        |                               |
   +----v----+                     +----v----+
   | soland  |  <--- federation ---|  soland |
   |  alpha  |   push-operations   |   beta  |
   +----+----+                     +----+----+
        |                               |
   alice@alpha                     bob@beta
```

- **2 × soland** 实例
  - α 监听 `http://127.0.0.1:<port_α>`,service DID `did:web:soland-alpha.joint-e2e.local`
  - β 监听 `http://127.0.0.1:<port_β>`,service DID `did:web:soland-beta.joint-e2e.local`
- **1 × coauth** 共享给两个 soland
- 两个 soland 在 config 里互相把对方列为 `federation_peers` 或等价机制(具体看 soland 实现)

## Actors

| 名字 | DID | 注册服务器 | 角色 |
|---|---|---|---|
| alice | `did:web:alice-s2-<uuid>.example` | α (soland-alpha) | space 创建者 + 跨域 inviter |
| bob | `did:web:bob-s2-<uuid>.example` | β (soland-beta) | 跨域 invitee |
| mallory (sub-test) | `did:web:mallory-s2-<uuid>.example` | β | 服务委托被撤销后的旁观者 |

## Pre-conditions

- α 和 β 两个 soland 都启动并 ready
- coauth 启动并 ready
- alice 在 α 上注册;bob 在 β 上注册;两端都通过同一 coauth 拿到 access token
- DID Document(或等效的服务发现源)能让 α 通过 bob 的 DID 解析出 `did:web:soland-beta.joint-e2e.local` 是 bob 的 Principal Server (`sync/federation.md` §6.2 Actor Event Source 发现)
- α 和 β 互信对方的 service DID (HTTP Message Signature 校验能过)

## Steps

### Phase A — alice@α 创建空间 + 跨域 invite

1. **alice** 通过 α 的 yougen 进 `/setup`,建空间 `S`:
   - discoverability = `listed`
   - join_rule = `invite`
   - history_visibility = `joined`
   - seed_members = `[]`(本次不在创建阶段邀,改用空间管理面 invite 流程,这样能精确捕获 `ck.invite.create` 事件)
2. 记录 `spaceId`
3. **alice** 进 `/space/${spaceId}/admin`,通过 `invite-member` 邀请 `bob.did`
   - 在 α 侧产生 `ck.invite.create` Event,subject_did = bob.did
4. 断言:α 侧 `space-admin-panel` 显示 `invited bob.did`

### Phase B — 联邦 push 把 invite 送到 β

5. α 检测到 bob 不在本地,通过服务发现拿到 `did:web:soland-beta.joint-e2e.local` 是 bob 的 Principal Server
6. α `POST http://<port_β>/_cokret/peer/federation/push-operations`,body 含:
   - `origin = did:web:soland-alpha.joint-e2e.local`
   - `destination = did:web:soland-beta.joint-e2e.local`
   - `space_id = spaceId`
   - `service_binding_ref` 含 `space_policy_hash` / `membership_frontier` / `reducer_profile_digest`
   - `events: [<完整签名的 ck.invite.create Envelope>]`
   - HTTP headers `Signature-Input`、`Signature`、`Content-Digest`
7. β 校验:
   - HTTP signature transcript + destination DID 匹配
   - content-digest 覆盖 body
   - service_binding_ref 与 β 本地的 space policy snapshot 一致
   - 每个 Event 的 actor 签名 + 因果链
   - `reducer_profile_digest` 与 β 本地匹配(不匹配整批返回 `reducer_profile_mismatch`)
8. β 返回 `{accepted: [invite_event_id], rejected: [], quarantine: []}`
9. 断言(测试侧从 α 视角拿响应,或者从测试 harness 直接读 β 的 sync state):invite event 在 β 上可见

### Phase C — bob@β 接受 invite

10. **bob** 通过 β 的 yougen 加载;客户端检测到收到一个 invite (yougen 应该有 invite 列表 UI;如果没有,scenario 注释成需要 yougen 补 UI 或者通过 API call 走)
11. bob 触发接受;β 上产生 `ck.invite.accept` Event,refs 指向 `ck.invite.create.event_id`
12. β 主动把 `ck.invite.accept` push 到 α (反向 federation push)
13. α 校验后接受;α 上 reducer 收敛 bob 的 `membership=join`
14. 断言:α 上 `/space/${spaceId}/admin` 的成员列表含 bob.did

### Phase D — 双向消息推送

15. **alice** (在 α) 进 `/timeline/${spaceId}` 发 `M_a = "alice from alpha ${stamp}"`
    - α 上 reducer 接受,push 到 β
16. 断言:β 那边 bob 进 `/timeline/${spaceId}` 后 30s 内 timeline 含 `M_a`
17. **bob** (在 β) 发 `M_b = "bob from beta ${stamp}"`
    - β 上 reducer 接受,push 到 α
18. 断言:α 那边 alice 30s 内 timeline 含 `M_b`
19. (Edit + redact 子流程可选;主要验证传播方向,不重复 messaging/triad-collaboration 的 message 内部细节)

### Phase E — Frontier 一致性

20. 测试 harness 分别查询 α 和 β 的 `/_cokret/self/spaces/${spaceId}/anchor-frontier` (或等价 endpoint),拿到两端的 anchor frontier 集合
21. 断言:两端 frontier 覆盖相同的 event 集合;event_id 相同,顺序可能不同但因果一致

### Phase F — Pull / Backfill (sub-test E2.1)

22. 把 β 临时离线(harness 用 `route.block` 拦掉 α→β 的 push,模拟网络分区)
23. **alice** 发 `M_offline = "during partition ${stamp}"`,α 多次重试 push 失败
24. 恢复 β,**bob** 进 timeline → β 检测因果缺口(本地缺 `M_offline` 的 `prev_refs`),发起 `GET /_cokret/peer/federation/pull-operations?space_id=...&after_cursor=...`
25. α 返回缺口 event 数组,β 落库,bob 现在能看到 `M_offline`

### Phase G — Capability revoke fanout (sub-test E2.2)

26. **alice** 在 α 撤销 `did:web:soland-beta.joint-e2e.local` 对该 Space 的服务委托 (具体事件类型按 `ck.service.delegation` 或等价)
27. 撤销 fanout 推到 β (`§4.4`)
28. **alice** 再发 `M_after_revoke = "post-revoke ${stamp}"`
29. 断言:α **不再** 把该 event push 给 β;β 上 bob 看不到 `M_after_revoke`(spec §4.1 末尾:"撤销后的 service DID 不得继续接收非加密私有内容")

## Observable assertions (合并清单)

- 步骤 6-8:α→β 的 push 成功,β 返回 `accepted` 含 invite event_id
- 步骤 12-13:β→α 的 accept push 成功
- 步骤 14:α 视图中 bob 是 member
- 步骤 16、18:两边消息双向 30s 内可见
- 步骤 21:frontier 在两端覆盖同一 event 集合
- 步骤 25:pull-operations 能补齐缺口
- 步骤 29:撤销后 α 不再向 β 推送

## Edge cases / sub-tests

- **E2.3 reducer_profile_mismatch**:把 β 的 reducer profile 改一个 hash,α push 时整批拒绝;断言返回 `rejected` 且 `reason_code=reducer_profile_mismatch`
- **E2.4 idempotent push**:α 把同一个 invite event 推两次,β 第二次也返回 `accepted`(幂等),不重复写入
- **E2.5 signature 失败**:篡改 α 的 HTTP signature header,β 整批拒绝;断言 4xx 状态码 + 标准 JSON error envelope
- **E2.6 dependency_missing**:α 发一个 `prev_refs` 指向 β 未见过的 event 的 message,β 把它放 `rejected[]` with `reason_code=dependency_missing`

## Implementation notes — harness 改动

这是这条 scenario 最关键的部分,scripts/run-joint-e2e.ps1 需要扩展:

1. **双 soland 启动**:
   - 当前 script 只起一个 soland。需要参数化:`-SolandInstances 2` 或新加参数 `-Soland2Manifest`、`-Soland2BaseUrl`
   - 每个 soland 自己的 service DID、自己的 service_did 配置、自己的 objects root 目录
   - coauth 的 `cokret.principal_servers[]` 配置要包含两个 soland 的 entry
2. **soland 之间的联邦发现**:
   - 需要 soland 支持 "已知 federation peers" 配置(看 soland 实现是 env var 还是 config)
   - 或者 soland 通过 DID Document `service.CokretPrincipalServer` 自动发现
   - **依赖 soland**:这条 scenario 在 soland 不能联邦的情况下无法跑
3. **环境变量**给测试用:
   - `COTEST_SOLAND_ALPHA_BASE_URL` / `COTEST_SOLAND_ALPHA_SERVICE_DID`
   - `COTEST_SOLAND_BETA_BASE_URL` / `COTEST_SOLAND_BETA_SERVICE_DID`
4. **新 helper**:
   - `openUserPage(browser, user, { server: "alpha" | "beta" })` — 在指定 soland 上注册并打开 yougen
   - 当前 yougen 通过 `yougen.config.v1.server_url` 决定连哪个 soland,所以只要切 server_url 就能实现
   - 但 alice@α 和 bob@β 需要分别用 α / β 的 base url 注入

## 风险 / 前置依赖

- **已落地**:双 soland 拓扑、`push-operations` / `pull-operations` endpoint、α→β invite 自动 push、β→α invite-accept member join push、双向 message push、幂等 replay、网络分区恢复后的 pull/backfill operation frontier coverage、入站 RFC 9421 HTTP Message Signature 验证、key rotation hint、relay outer/inner signature 边界。
- **仍待后续 GAP**:`reducer_profile_digest` 强校验、服务委托 revoke fanout。
- **yougen invite accept UI** 仍可补强;当前 live 用 β 的 authz invite API + canonical `ck.member.state{membership=join, reason=invite_accept}` 覆盖接受链路。

## 总耗时预估

单次跑约 3-5 分钟(双服务器启动、跨域 push 重试窗口、frontier 检查)。
