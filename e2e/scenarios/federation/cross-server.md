# 跨服务器联邦

## 目标

验证两个独立 Station 之间的联邦推送能完成完整的协作链路:跨服务器邀请、被邀方接受、双向消息推送、anchor frontier 收敛、撤销服务委托后停止推送。证明协议是 federated 的 — 单一服务器不是全局权威,信任根是签名 Event + RFC 9421 HTTP Message Signature + 服务绑定快照。

不验证:第三方邮件邀请 (后续 invites/third-party,本 scenario 用 DID-to-DID 直接邀请)、moderation (spaces/moderation-ban)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/sync/federation.md` §2.1 — Event Chain 是信任锚点
- `arkret-spec/spec/v1/zh/sync/federation.md` §2.2 — Station 是受控同步边界,不是全局权威
- `arkret-spec/spec/v1/zh/sync/federation.md` §3.1-§3.2 — 基于 DID 的服务器身份 + RFC 9421 请求签名
- `arkret-spec/spec/v1/zh/sync/federation.md` §4.1 — Push 协议、`POST /_arkret/peer/peer/events` 请求字段
- `arkret-spec/spec/v1/zh/sync/federation.md` §4.1.0 — Push 时序图(信任根说明)
- `arkret-spec/spec/v1/zh/sync/federation.md` §4.1.1 — 批量推送幂等 (`(origin, destination, event_id)` 去重)
- `arkret-spec/spec/v1/zh/sync/federation.md` §4.2 — Pull / Backfill (`peer events query`)
- `arkret-spec/spec/v1/zh/sync/federation.md` §4.5 — Fork Detection / Frontier Exchange
- `arkret-spec/spec/v1/zh/sync/federation.md` §5.1 — 跨域邀请流程 (6 步)
- `arkret-spec/spec/v1/zh/sync/federation.md` §4.4 — Capability Revoke Fanout

## 拓扑

```
                    +-------+
                    |coauth1| / |coauth2|  (independent account authorities)
                    +---+---+
                        |
        +---------------+---------------+
        |                               |
   +----v----+                     +----v----+
   | soland  |  <--- federation ---|  soland |
   |  server1  |   peer events submit   |   server2  |
   +----+----+                     +----+----+
        |                               |
   alice@server1                     bob@server2
```

- **2 × soland** 实例
  - server1 监听 `http://127.0.0.1:<port_server1>`,service DID `did:web:soland-server1.joint-e2e.local`
  - server2 监听 `http://127.0.0.1:<port_server2>`,service DID `did:web:soland-server2.joint-e2e.local`
- **2 × coauth**，每台 server 使用独立身份与存储
- 两个 soland 在 config 里互相把对方列为 `federation_peers` 或等价机制(具体看 soland 实现)

## Actors

| 名字 | DID | 注册服务器 | 角色 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s2-<uuid>.example` | server1 (soland-server1) | Realm 创建者 + 跨域 inviter |
| bob | `did:webvh:z6mkfixture:bob-s2-<uuid>.example` | server2 (soland-server2) | 跨域 invitee |
| mallory (sub-test) | `did:webvh:z6mkfixture:mallory-s2-<uuid>.example` | server2 | 服务委托被撤销后的旁观者 |

## Pre-conditions

- server1 和 server2 两个 soland 都启动并 ready
- coauth 启动并 ready
- alice 在 server1 上注册;bob 在 server2 上注册;两端都通过同一 coauth 拿到 session credential
- DID Document(或等效的服务发现源)能让 server1 通过 bob 的 DID 解析出 `did:web:soland-server2.joint-e2e.local` 是 bob 的 Station (`sync/federation.md` §6.2 Actor Event Source 发现)
- server1 和 server2 互信对方的 service DID (HTTP Message Signature 校验能过)

## Steps

### Phase A — alice@server1 创建 Realm + 跨域 invite

1. **alice** 通过 server1 的 inkson 进 `/setup`,建 Realm `R`:
   - discoverability = `listed`
   - join_rule = `invite`
   - history_access = `since_join`
   - seed_members = `[]`(本次不在创建阶段邀,改用空间管理面 invite 流程,这样能精确捕获 `ak.invite.create` 事件)
2. 记录 `realmId`
3. **alice** 进 `/realms/${realmId}/admin`,通过 `invite-member` 邀请 `bob.did`
   - 在 server1 侧产生 `ak.invite.create` Event,subject_did = bob.did
4. 断言:server1 侧 `realm-admin-panel` 显示 `invited bob.did`

### Phase B — 联邦 push 把 invite 送到 server2

5. server1 检测到 bob 不在本地,通过服务发现拿到 `did:web:soland-server2.joint-e2e.local` 是 bob 的 Station
6. server1 `POST http://<port_server2>/_arkret/peer/events`,body 含:
   - `origin = did:web:soland-server1.joint-e2e.local`
   - `destination = did:web:soland-server2.joint-e2e.local`
   - `realm_id = realmId`
   - `service_binding_ref` 含 `realm_policy_digest` / `membership_frontier`; 成员 ActorId 中的 Station 是路由真相
   - `events: [<完整签名的 ak.invite.create Envelope>]`
   - HTTP headers `Signature-Input`、`Signature`、`Content-Digest`
7. server2 校验:
   - HTTP signature transcript + destination DID 匹配
   - content-digest 覆盖 body
   - service_binding_ref 与 server2 本地的 Realm policy snapshot 一致
   - 每个 Event 的 actor 签名 + 因果链
   - server2 从每个 Event 的 `seal_ref` 或 `seal_basis` 所确定的 CBS 读取 Realm reducer-profile cell；请求和 binding 均不声明 profile
8. server2 返回 `{accepted: [invite_event_id], rejected: [], quarantine: []}`
9. 断言(测试侧从 server1 视角拿响应,或者从测试 harness 直接读 server2 的 sync state):invite event 在 server2 上可见

### Phase C — bob@server2 接受 invite

10. **bob** 通过 server2 的 inkson 加载;客户端检测到收到一个 invite (inkson 应该有 invite 列表 UI;如果没有,scenario 注释成需要 inkson 补 UI 或者通过 API call 走)
11. bob 触发接受;server2 上产生 `ak.invite.accept` Event,refs 指向 `ak.invite.create.event_id`
12. server2 主动把 `ak.invite.accept` push 到 server1 (反向 federation push)
13. server1 校验后接受;server1 上 reducer 收敛 bob 的 `membership=join`
14. 断言:server1 上 `/realms/${realmId}/admin` 的成员列表含 bob.did

### Phase D — 双向消息推送

15. **alice** (在 server1) 进 `/timeline/${realmId}` 发 `M_a = "alice from server1 ${stamp}"`
    - server1 上 reducer 接受,push 到 server2
16. 断言:server2 那边 bob 进 `/timeline/${realmId}` 后 30s 内 timeline 含 `M_a`
17. **bob** (在 server2) 发 `M_b = "bob from server2 ${stamp}"`
    - server2 上 reducer 接受,push 到 server1
18. 断言:server1 那边 alice 30s 内 timeline 含 `M_b`
19. (Edit + redact 子流程可选;主要验证传播方向,不重复 messaging/triad-collaboration 的 message 内部细节)

### Phase E — Frontier 一致性

20. 测试 harness 分别查询 server1 和 server2 的 `GET /_arkret/peer/events/frontier?realm_id=${realmId}` (或等价 endpoint),拿到两端的 anchor frontier 集合
21. 断言:两端 frontier 覆盖相同的 event 集合;event_id 相同,顺序可能不同但因果一致

### Phase F — Pull / Backfill (sub-test E2.1)

22. 把 server2 临时离线(harness 用 `route.block` 拦掉 server1→server2 的 push,模拟网络分区)
23. **alice** 发 `M_offline = "during partition ${stamp}"`,server1 多次重试 push 失败
24. 恢复 server2,**bob** 进 timeline → server2 检测因果缺口(本地缺 `M_offline` 的 `prev_refs`),发起 `GET /_arkret/peer/events?realms=...&after=...`
25. server1 返回缺口 event 数组,server2 落库,bob 现在能看到 `M_offline`

### Phase G — Capability revoke fanout (sub-test E2.2)

26. **alice** 在 server1 撤销 `did:web:soland-server2.joint-e2e.local` 对该 Realm 的服务委托 (具体事件类型按 `ak.service.delegation` 或等价)
27. 撤销 fanout 推到 server2 (`§4.4`)
28. **alice** 再发 `M_after_revoke = "post-revoke ${stamp}"`
29. 断言:server1 **不再** 把该 event push 给 server2;server2 上 bob 看不到 `M_after_revoke`(spec §4.1 末尾:"撤销后的 service DID 不得继续接收非加密私有内容")

## Observable assertions (合并清单)

- 步骤 6-8:server1→server2 的 push 成功,server2 返回 `accepted` 含 invite event_id
- 步骤 12-13:server2→server1 的 accept push 成功
- 步骤 14:server1 视图中 bob 是 member
- 步骤 16、18:两边消息双向 30s 内可见
- 步骤 21:frontier 在两端覆盖同一 event 集合
- 步骤 25:peer events query 能补齐缺口
- 步骤 29:撤销后 server1 不再向 server2 推送

## Edge cases / sub-tests

- **E2.3 unsupported_profile**：让 Event 的 CBS 落在 server2 未实现的 reducer profile；断言 Event 以 `unsupported_profile` 拒绝
- **E2.4 idempotent push**:server1 把同一个 invite event 推两次,server2 第二次也返回 `accepted`(幂等),不重复写入
- **E2.5 signature 失败**:篡改 server1 的 HTTP signature header,server2 整批拒绝;断言 4xx 状态码 + 标准 JSON error envelope
- **E2.6 dependency_missing**:server1 发一个 `prev_refs` 指向 server2 未见过的 event 的 message,server2 把它放 `rejected[]` with `reason_code=dependency_missing`

## Implementation notes — harness 改动

这是这条 scenario 最关键的部分,scripts/run-joint-e2e.ps1 需要扩展:

1. **双 soland 启动**:
   - 当前 script 只起一个 soland。需要参数化:`-SolandInstances 2` 或新加参数 `-Soland2Manifest`、`-Soland2BaseUrl`
   - 每个 soland 自己的 service DID、自己的 service_id 配置、自己的 objects root 目录
   - coauth 的 `arkret.stations[]` 配置要包含两个 soland 的 entry
2. **soland 之间的联邦发现**:
   - 需要 soland 支持 "已知 federation peers" 配置(看 soland 实现是 env var 还是 config)
   - 或者 soland 通过 DID Document 中 `type="ArkretService"` 且
     `serviceKind="station"` 的 service entry 自动发现
   - **依赖 soland**:这条 scenario 在 soland 不能联邦的情况下无法跑
3. **环境变量**给测试用:
   - `COTEST_SOLAND_SERVER1_BASE_URL` / `COTEST_SOLAND_SERVER1_SERVICE_ID`
   - `COTEST_SOLAND_SERVER2_BASE_URL` / `COTEST_SOLAND_SERVER2_SERVICE_ID`
4. **新 helper**:
   - `openUserPage(browser, user, { server: "server1" | "server2" })` — 在指定 soland 上注册并打开 inkson
   - 当前 inkson 通过 `inkson.config.v1.server_url` 决定连哪个 soland,所以只要切 server_url 就能实现
   - 但 alice@server1 和 bob@server2 需要分别用 server1 / server2 的 base url 注入

## 风险 / 前置依赖

- **已落地**:双 soland 拓扑、`peer events submit` / `peer events query` endpoint、server1→server2 invite 自动 push、server2→server1 invite-accept member join push、双向 message push、幂等 replay、网络分区恢复后的 pull/backfill operation frontier coverage、入站 RFC 9421 HTTP Message Signature 验证、key rotation hint、relay outer/inner signature 边界。
- **仍待后续 GAP**：服务委托 revoke fanout。
- **inkson invite accept UI** 仍可补强;当前 live 用 server2 的 authz invite API + canonical `ak.member.state{membership=join, reason=invite_accept}` 覆盖接受链路。

## 总耗时预估

单次跑约 3-5 分钟(双服务器启动、跨域 push 重试窗口、frontier 检查)。
