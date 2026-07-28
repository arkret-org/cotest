# Transport binding negotiation (HTTP / WebSocket / TSP fallback)

## 目标

验证两个 soland 实例(soland_a 和 soland_b)能完成「HTTP signed baseline → 协商升级到 WebSocket → 进一步切到 TSP relationship envelope → 任一 transport 断连后回退到 HTTP」的完整 transport negotiation 链路;过程中 RFC 9421 HTTP Message Signature、origin/destination service DID、nonce、key rotation 等约束在所有 transport 上一致执行,binding fallback chain 在故障时收敛到 HTTP/JSON baseline。

不验证:单服务器 sync (见 sync/offline-conflict)、cross-server federation push 业务逻辑 (见 federation/cross-server)、push notification gateway (见 discovery/push-notifications)、blob transport (见 media/blob-transport)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/sync/transport-bindings.md` §2 — 分层:semantic operation vs transport binding;v1 core 锁定 HTTP/JSON
- `arkret-spec/spec/v1/zh/sync/transport-bindings.md` §3 — Binding Requirements:认证、授权上下文、幂等、流式、错误、背压
- `arkret-spec/spec/v1/zh/sync/transport-bindings.md` §4 — Canonical Operation IDs (federation push 复用 `ak.self.events.command.submit` + service_signature)
- `arkret-spec/spec/v1/zh/sync/service-http-binding.md` §3 — 通用认证 / RFC 9421 / 服务间签名要求
- `arkret-spec/spec/v1/zh/sync/service-http-binding.md` §4 — 服务间 origin/destination service DID 绑定
- `arkret-spec/spec/v1/zh/sync/service-http-binding.md` §5 — 错误 envelope、404 unrecognized_endpoint、405 method_not_allowed
- `arkret-spec/spec/v1/zh/sync/federation.md` §3.2 — RFC 9421 HTTP Message Signature 在 federation 调用上的具体要求
- `arkret-spec/spec/v1/zh/sync/federation.md` §4.1 — push 协议(复用 `POST /_arkret/peer/peer/events` 在当前 implementation 路径下)

## 拓扑

- 1 × soland_a (server A,通过 `solandBaseUrl("alpha")` / `SOLAND_A_PUBLIC_URL` 访问)
- 1 × soland_b (server B,通过 `solandBaseUrl("beta")` / `SOLAND_B_PUBLIC_URL` 访问)
- 1 × coauth (共享 auth server)

两个 soland 实例通过 `SOLAND_FEDERATION_PEERS` 互相宣告;DID 文档(`did:web:soland-alpha.joint-e2e.local`、`did:web:soland-beta.joint-e2e.local`)在各自 `/.well-known/did.json` 暴露 service endpoint。

## Actors

| 名字 | DID | 在 transport-negotiation 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s8-<uuid>.example` (注册在 soland_a) | server A 上的 originating actor;触发跨域操作以产生 federation traffic | 测试开始前 |
| bob | `did:webvh:z6mkfixture:bob-s8-<uuid>.example` (注册在 soland_b) | server B 上的 destination actor;接收 federation push | 测试开始前 |

服务 actor:
- soland_a 自身 service DID = `did:web:soland-alpha.joint-e2e.local`,所有 outbound 请求 MUST 以该 service DID 作为 RFC 9421 keyid 签名
- soland_b 自身 service DID = `did:web:soland-beta.joint-e2e.local`,验证入站签名时按 `Source-Service-ID` header 解析 keyid

## Pre-conditions

- 两个 soland 实例 `/health` 返回 200(通过 `hasDualSoland()` gate)
- alice 在 soland_a 上 `POST /_soland/self/account/register` + `POST /_soland/gate/auth/dev-login` 完成
- bob 在 soland_b 上完成同样的注册 + dev session
- 两侧 DID 文档暴露 `service` 数组,其中包含 `ak.profile.principal_server.v1` 条目和 `supported_bindings`(至少 `http_json`)
- alice 已经在 soland_a 上 createRealm,该 space 的 `service_binding_ref` 包含 soland_b 为允许的 federation peer

## Steps

### Phase A — HTTP binding baseline (RFC 9421 signed)

1. **soland_a → soland_b**:测试 harness 触发 alice 在 server A 上对 bob 发 `ak.invite.create`(remote DID)
2. 期望:soland_a 自动构造 federation push 请求
   - URL: `${SOLAND_B_PUBLIC_URL}/_arkret/peer/peer/events`
   - Method: `POST`
   - Headers:
     - `Content-Type: application/json`
     - `Source-Service-ID: did:web:soland-alpha.joint-e2e.local`
     - `Destination-Service-ID: did:web:soland-beta.joint-e2e.local`
     - `Signature-Input: sig1=("@method" "@target-uri" "content-digest" "source-service-id" "destination-service-id");created=<ts>;keyid="<alpha-key-id>";alg="ed25519"`
     - `Signature: sig1=:<base64>:`
     - `Content-Digest: sha-256=:<base64>:`
     - `Idempotency-Key: <uuid>`
   - Body: canonical `EventEnvelope`(invite event)
3. **soland_b** 收到请求,按 RFC 9421 验证:
   - 解析 `Signature-Input` 的 covered components
   - 用 `Source-Service-ID` 解析 origin key (通过 `/.well-known/did.json`)
   - 验证 `Signature` 对 covered components 的签名
   - 验证 `Content-Digest` 与 body 一致
   - 验证 `Destination-Service-ID` 是自身 DID
   - 验证 nonce / `created` ts 在窗口内(防 replay)
4. 断言:`POST /_arkret/peer/peer/events` 返回 200,响应 body 含 `accepted[<invite_event_id>]`
5. 断言:bob 通过 `GET /_arkret/self/authz/invites` 的 invite projection
   在 30s 内看到 invite 通知(意味着 server B 已经把事件入库)

### Phase B — WebSocket upgrade (negotiate via ak.transport.negotiate)

6. **soland_a** 通过 `GET ${SOLAND_B_PUBLIC_URL}/_arkret/describe` 读取 server B 的 `supported_bindings`
   - 期望返回中包含 `{kind: "http_json", ...}` 和 `{kind: "websocket_frame", extension_profile_required: "ak.profile.binding.websocket.v1", upgrade_path: "/_arkret/peer/events stream binding"}`
7. **soland_a** 发起 WebSocket 升级:
   - URL: `${SOLAND_B_PUBLIC_URL}/_arkret/peer/events stream binding`(`wss://` 在生产、`ws://` 在测试)
   - Headers:`Upgrade: websocket`、`Connection: Upgrade`、`Sec-WebSocket-Key: <random>`、`Sec-WebSocket-Version: 13`、`Sec-WebSocket-Protocol: ak.federation.v1`
   - 同时携带 RFC 9421 `Signature` 对 upgrade 请求的 covered components 签名(handshake 阶段)
8. **soland_b** 接受 upgrade,返回 `101 Switching Protocols`,后续帧使用 `ak.federation.v1` subprotocol
9. **soland_a** 通过 WebSocket 帧推送下一批 federation event(例如 alice 在 space 发的消息)
   - 每个帧 body 仍然是 canonical EventEnvelope;帧本身携带 `frame_signature`(per-frame service signature) 而非 per-request RFC 9421
10. **soland_b** 验证 frame_signature → 入库 → bob 30s 内看到消息
11. 断言:server A 和 server B 都通过 `GET /_arkret/describe` 或内部 admin endpoint 报告当前活跃 binding = `websocket_frame`(至少一条 active connection)

### Phase C — TSP binding (optional extension)

12. **soland_a** 在 `GET /_arkret/describe` 中宣布支持 TSP binding(`extension_profile_required: "ak.profile.binding.tsp.v1"`)
13. **soland_b** 选择 TSP — 通过 `ak.transport.negotiate` 协商把后续 federation 流量切到 TSP relationship envelope
14. **soland_a** 通过 TSP node 向 soland_b 发送下一批事件
    - TSP envelope: outer wrapper 携带 sender/receiver VID(verifiable identifier),inner payload 是 canonical EventEnvelope
    - 不再需要 RFC 9421 — TSP envelope 自身 cryptographic binding 取代 HTTP 层签名
15. 断言:soland_b 通过 TSP 收到 envelope → 解封 → 入库 → bob 看到消息

注:Phase C 是未发布扩展的设计记录。当前 soland 无 TSP binding 实现,且 v1 registry 没有对应 operation,因此不进入 Playwright test discovery。

### Phase D — Binding fallback (WebSocket 断连 → 回到 HTTP)

16. 在 Phase B 的 WebSocket 连接活跃时,测试 harness 通过 `route.abort` 或 `forceClose` 让 soland_a 与 soland_b 之间的 WebSocket 断开
17. soland_a 检测到 connection lost(ping/pong 超时或 socket close 帧)
18. 期望:soland_a 不立即重连 WebSocket,而是按 binding fallback chain 回到 HTTP/JSON
    - fallback chain: `tsp` → `websocket_frame` → `http_json`
    - 既然 TSP 没启用、WebSocket 刚 fail,直接降级到 HTTP
19. soland_a 用下一个 outbound event 触发 HTTP POST(同 Phase A 的形态),重新走 RFC 9421 signed POST
20. 断言:30s 内 bob 看到该事件(经 HTTP 投递),即使 WebSocket 暂时不可用
21. 断言:server A 的内部 metric/log 显示 `binding.fallback{from=websocket_frame,to=http_json}` 计数增加

## Observable assertions (合并清单)

- Phase A:POST `/_arkret/peer/peer/events` 入站签名验证成功(返回 200 + `accepted[]`),失败(签名错)返回 401
- Phase A:bob 在 `/_arkret/self/authz/invites` 看到 invite
- Phase B:`GET /_arkret/describe` 含 `supported_bindings[].kind=websocket_frame`
- Phase B:WebSocket upgrade 返回 101;subprotocol = `ak.federation.v1`
- Phase B:bob 在 30s 内看到通过 WebSocket 帧投递的消息
- Phase C(设计 backlog):TSP binding 出现在未来扩展的 `supported_bindings` 中;TSP envelope 解封成功
- Phase D:WebSocket 断后,server A 自动回退到 HTTP/JSON;bob 仍然在 30s 内收到下一个事件
- 全程:任何 transport 上,`origin` / `destination` service DID 与 DID Document 一致;签名 / envelope 验证失败 → 整批 reject

## Edge cases / sub-tests

- **E8.1 签名过期 / 密钥轮换**
  - soland_a 用一个已过期的 keyid 签 POST /peer/events
  - soland_b MUST 返回 `401` + body `{error: {code: "signature_expired" 或 "unknown_keyid", key_rotation_hint: {current_keyid, valid_from}}}`
  - soland_a 收到 hint 后用新 keyid 重签 → 第二次请求 200
  - 断言:server B 没有把过期签名 push 入库;新签名后入库成功

- **E8.2 federation 跨越多个 hop (indirect relay)**
  - 拓扑:soland_a → relay (soland_c 或 mock relay) → soland_b
  - soland_a 对 relay 发 push,relay 不解开 EventEnvelope 的签名层,只用自己的 service signature 把请求转发给 soland_b
  - soland_b MUST 同时验证:
    1. relay 的 RFC 9421 outer signature(`Source-Service-ID = relay`)
    2. EventEnvelope 内 origin actor(`alice@soland_a`)的事件签名
    3. relay 是否被 Realm policy 授权作为 service delegation
  - 断言:多 hop 的端到端签名验证成功;任一层失败整批 reject

- **E8.3 binding negotiation timeout**
  - soland_a 通过 `ak.transport.negotiate` 请求升级到 WebSocket
  - 测试 harness 让 soland_b 在 30s 内不响应(`route.fulfill` 延迟 / 不响应)
  - 30s 后 soland_a MUST:
    1. 取消 negotiation 请求
    2. 标记 `websocket_frame` 该 peer 上暂时不可用
    3. 用 HTTP/JSON 作为默认 binding 发出 pending events
  - 断言:30s 后 bob 仍然在 ~ 60s 内通过 HTTP/JSON 收到 pending events;`binding.negotiation_timeout` metric 计数 +1

## Implementation notes

- **soland 缺口**:
  - WebSocket transport binding 整体未实现(只在 spec slot 中保留 — `transport-bindings.md` §6 明说 non-HTTP binding 是 extension profile)
  - TSP binding 完全未实现
  - HTTP RFC 9421 入站签名验证 partial(`federation.rs` 已有 stub,但完整 RFC 9421 components / `Content-Digest` / nonce / key rotation hint 路径未完成)
  - 出站签名生成不完整(`federation.rs:548-572` 出站 push 是 logs-only stub)
  - `ak.transport.negotiate` operation 在 contract catalog 中作为 slot 保留,无运行时实现
  - binding fallback chain 是 client-side 逻辑,目前 soland 没有 fallback state machine

- **测试侧**:
  - WebSocket 用 Playwright `page.context().on('websocket', ...)` 或直接 `ws` 客户端发起
  - RFC 9421 签名构造可用 cotest helpers `helpers/signatures.ts`(若不存在则 fixme)
  - 多 hop relay 用第三个 mock service(`MOCK_RELAY_BASE_URL`)或 `route.fulfill` 拦截 + 重写
  - WebSocket forceClose 用 `ws.close()` 或 `page.context().setOffline(true)` 配合 host filter

- **预期结果**:可执行 spec 只覆盖已注册的 HTTP/JSON federation 与 RFC 9421 边界。WebSocket/TSP negotiation 与 relay-inner 只保留为未来扩展设计,不得通过空 `test.fixme` 进入测试报告。

## 总耗时预估

当前单次跑约 30-60s。一旦 spec 正式发布 WebSocket/TSP 扩展并完成实现,应新增真实测试,预计约 90-120s。
