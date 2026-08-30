# TSP relationship bootstrap 与 Arkret over TSP

## 目标

验证跨 VID 体系(`did:webvh` / `did:web` / `did:webs`)的 Trust Spanning Protocol 接入路径:内部 Arkret 用户 `alice` (`did:webvh`) 与外部组织 `bob_extern` (`did:web`) 通过各自 DID Document 上声明的 `ak.service.tsp` endpoint,完成 TSP relationship bootstrap (公钥交换、VID 验证、relationship id 建立);随后 alice 用 TSP envelope 包装一个 Arkret operation (`ak.invite.create`) 发给 bob_extern;bob_extern 验证 TSP authenticity + 解出内层 Arkret payload + 用 Arkret event signature 二次校验,然后通过反向 TSP 通道回 `ak.member.state{join}`;整个过程中 metadata 通过 nested message 对中间 relay 不可见。

不验证:Arkret v1 core 的 HTTPS JWE / MLS DM transport(默认路径,已被 messaging/triad-collaboration 等覆盖)、KERI AID 解析(本 scenario 只覆盖 did:webvh/did:web/did:webs 三种 VID)、Realm 内 E2EE epoch 演化(crypto-media/mls 系列)、TSP routed mode 的 multi-hop intermediary 链路(后续 federation/tsp-routed scenario)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/identity/tsp-integration.md` §2 — TSP 适用位置(身份相关控制消息、federation bootstrap、跨组织 service DID)
- `arkret-spec/spec/v1/zh/identity/tsp-integration.md` §3 — VID/Endpoint/Relationship/Support System 到 Arkret 的映射;DID method adapter SHOULD 暴露是否支持 TSP
- `arkret-spec/spec/v1/zh/identity/tsp-integration.md` §4 — `ak.service.tsp` endpoint declaration 的 wire 形态(`serviceEndpoint`、`supported_vid_schemes`、`supported_modes`、`supported_payloads`、`metadata_privacy`)
- `arkret-spec/spec/v1/zh/identity/tsp-integration.md` §5 — Arkret over TSP 规则:TSP authenticity 不替代 Arkret event signature;TSP confidentiality 不替代 Realm E2EE;TSP relationship 不自动授予 Realm membership / capability;nested 模式下外层 endpoint 仍需满足 routing/policy
- `arkret-spec/spec/v1/zh/identity/tsp-integration.md` §8 — Security requirements:验证 remote VID、记录 support system、TSP binding 显式绑定 principal、metadata privacy 显式声明、audit log 记录 relationship id + payload hash + verification result

## 拓扑

- 1 × soland (Station) — 承载 alice 的事件与 audit log;假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (private authentication process) — 签 alice 的 session credential
- 1 × WebVH host — 服务 alice 的 `did:webvh:<scid>:<host>` 解析(发布 `did.jsonl`,含 `ak.service.tsp` endpoint 声明)
- 1 × DID:web host — 服务 bob_extern 的 `did:web:bob-extern.example` 解析(发布 `did.json`,同样含 `ak.service.tsp` endpoint 声明)
- 1 × mock TSP endpoint(并行任务产出的 `mock-tsp-endpoint.mjs`) — 同时扮演 alice 与 bob_extern 的 TSP endpoint;harness 通过 `process.env.MOCK_TSP_ENDPOINT_PORT` 决定监听端口,`process.env.MOCK_TSP_ENDPOINT_VID` 决定其向外宣告的 VID;在 Phase D / E 自动 ACK 收到的 TSP envelope

(coauth + soland 走现有 harness;TSP mock 由 scripts/run-joint-e2e.ps1 启动并把 `MOCK_TSP_ENDPOINT_*` 注入测试进程环境。)

## Actors

| 名字 | VID | 在 identity/tsp-bootstrap 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:<scid>:alice-tsp-<uuid>.example` | 内部 Arkret 用户;TSP relationship 发起方;发送 `ak.invite.create` | 测试开始前 |
| bob_extern | `did:webvh:z6mkfixture:bob-extern-tsp-<uuid>.example` | 外部组织;通过 TSP 接入;接收 invite 并回 `ak.member.state{join}` | 测试开始前(只在 DID:web host 注册 DID Document,不在 soland 注册账户) |
| tsp_endpoint | mock | 双向 TSP 通道的承载者;`MOCK_TSP_ENDPOINT_PORT` 指定端口、`MOCK_TSP_ENDPOINT_VID` 指定其代为宣告的 VID | 由 harness 在测试启动前拉起 |

## Pre-conditions

- alice 已通过 `POST /_soland/self/account/register` 注册;DID 形如 `did:webvh:<scid>:...`,entry 0 已发布
- alice 的 DID Document v0 中的 `service` 数组**已包含**一项 `ak.service.tsp` endpoint,`serviceEndpoint` 指向 `http://127.0.0.1:${MOCK_TSP_ENDPOINT_PORT}/tsp`
- bob_extern 的 `did:web` document 同样包含 `ak.service.tsp` endpoint,指向同一个 mock(mock 通过 `MOCK_TSP_ENDPOINT_VID` 区分入站消息归属哪个 VID)
- alice 持有有效 dev session token (`POST /_soland/gate/auth/dev-login`)
- alice browser context 通过 `inkson.config.v1` localStorage 注入 server_url + account_did + device_id + session_credential
- alice 与 bob_extern **之间没有现成的 TSP relationship**(mock 启动时 relationship table 为空)

## Steps

### Phase A — 双方 DID Document 声明 TSP 支持

1. **alice** 解析自己的 `did:webvh` 文档 (`GET https://<host>/.well-known/did/webvh/<scid>`),断言 `service` 数组里至少存在一项 `type === "ak.service.tsp"`,且 `serviceEndpoint` 与 `MOCK_TSP_ENDPOINT_PORT` 对应
2. **alice** 解析 `bob_extern` 的 `did:web` 文档 (`GET https://bob-extern-.../did.json`),断言同样存在 `ak.service.tsp` 声明,记录其 `serviceEndpoint`、`supported_vid_schemes`、`supported_modes`、`metadata_privacy.nested_messages === true`
3. 断言:alice 的 client (inkson) 在 feature discovery view 中将 `bob_extern` 标记为 "TSP-capable" (例如 directory 卡片上出现 `ak.service.tsp` chip / `tsp-capable-badge` testid)
4. (spec §3 line: DID method adapter SHOULD 暴露 TSP 能力)断言 `GET /_arkret/root/identity/${aliceDid}/transports` 返回数组里包含 `"tsp"`,且 `GET /_arkret/root/identity/${bobExternDid}/transports` 同样含 `"tsp"`

### Phase B — TSP relationship bootstrap

5. **alice** 通过 inkson 入口触发 "Establish TSP channel with bob_extern" (例如 `/directory` → 找到 bob_extern → `establish-tsp-button`)
6. 客户端组 TSP bootstrap message:
   - `vid_local` = alice 的 VID(`did:webvh:...`)
   - `vid_remote` = bob_extern 的 VID(`did:web:...`)
   - `local_pubkey` = alice 当前 device key 的 X25519 公钥(或 spec 指定的 KEM pubkey)
   - `nonce` = 随机
7. 客户端把 bootstrap message POST 到 bob_extern 的 `ak.service.tsp` endpoint(=mock,端口 `MOCK_TSP_ENDPOINT_PORT`)
8. mock(以 `MOCK_TSP_ENDPOINT_VID === bob_extern` 的身份)接收 → 校验 alice 的 VID(`did:webvh` resolve + signature 验证) → 返回 `relationship_id` + bob_extern 的 pubkey
9. 断言:alice 侧 `/settings/connections` 出现一行 TSP relationship,字段含 `relationship_id`、`remote_vid = bob_extern.did`、`support_system = "did:webvh / did:web"`、`trust_level = "verified"`
10. 断言:soland audit log (`GET /_soland/self/audit/tsp` 或等价 endpoint) 至少有一条 `tsp.relationship.bootstrap` 记录,包含 `remote_vid`、`relationship_id`、`verification_result: "ok"`(spec §8 要求)

### Phase C — alice 通过 TSP 发送 Arkret invite operation

11. **alice** 在 inkson 中(承接 Phase B 建立的 relationship) 触发 "Invite bob_extern via TSP" 流程,指向一个已存在的 Realm `R_tsp`
12. 客户端组装内层 Arkret operation:
    - `operation = "ak.invite.create"`
    - `realm_id = R_tsp`
    - `invitee = bob_extern.did`
    - `actor = alice.did`,带 Arkret event signature(alice 当前 update key)
13. 客户端把该 operation 作为 TSP application payload 包进 TSP envelope:
    - `content_type = "application/arkret+json"`
    - `payload_digest = sha256(...)`
    - 外层用 Phase B 的 relationship key 签名 + 加密
    - **使用 nested mode**:外层 envelope 的 sender VID 用 alice 的 pairwise DID,真实 `vid_local` 隐藏在内层(spec §4 `metadata_privacy.nested_messages`、§5 nested 规则)
14. 客户端 POST 到 bob_extern 的 TSP endpoint(mock)
15. 断言:mock 收到一条 TSP envelope,external relay view(`GET mock://relay-view`)显示**外层只能看到 pairwise VID,内层 payload 是 ciphertext**(metadata privacy 验证点)

### Phase D — bob_extern 验证 + 执行(mock 自动 ACK)

16. mock(作为 bob_extern)解开外层 → 用 relationship key 解密 → 拿到内层 Arkret payload
17. mock 验证内层 Arkret event signature(alice 的 webvh key,通过 §4 resolver 拉 DID Doc)→ pass
18. 断言:mock 把验证结果回成 TSP ACK,`verification.arkret_signature = "ok"`、`verification.tsp_authenticity = "ok"`(spec §5:两者 SHOULD 都验证,且独立)
19. 断言:alice 侧 inkson `/settings/connections` 该 relationship 的 outbox 标记最后一条 `ak.invite.create` 为 `delivered + acked`
20. 断言:soland audit log 出现 `tsp.message.send` 记录,包含 `relationship_id`、`payload_digest`、`payload_type: "ak.invite.create"`、`verification_result: "ok"`(spec §8)

### Phase E — 反向通道:bob_extern → alice 的 `ak.member.state{join}`

21. mock(作为 bob_extern)通过 Phase B 的同一 relationship 反向 POST 一个 TSP envelope,内层为 `ak.member.state` operation:`actor = bob_extern.did`、`realm_id = R_tsp`、`state = "join"`
22. alice 客户端的 TSP listener(由 alice 自己的 `ak.service.tsp` endpoint 承载,= 同一个 mock 实例的另一侧)收到 envelope → 验证外层 → 解出内层 → 验证 Arkret event signature(bob_extern 的 `did:web` key)
23. 断言:alice 侧 `/realms/${R_tsp}/admin` 显示 bob_extern 状态为 `joined`(或在 `realm-admin-panel` 中匹配 `joined ${bobExternDid}`)
24. 断言:alice 侧 audit log 含一条 `tsp.message.receive` 记录,`payload_type: "ak.member.state"`,且 `verification_result: "ok"`

## Observable assertions(合并清单)

- Phase A 步骤 1-2:两个 VID 的 DID Document 都含 `ak.service.tsp` endpoint 声明,字段形态匹配 spec §4
- Phase A 步骤 4:`/_arkret/root/identity/{did}/transports` 暴露 `"tsp"`(spec §3 line: DID method adapter SHOULD 暴露)
- Phase B 步骤 9-10:relationship 建立后客户端有可见记录,soland audit 有 `tsp.relationship.bootstrap` 条目
- Phase C 步骤 15:nested mode 下外层 relay 看不到内层 payload 明文(metadata privacy)
- Phase D 步骤 18:**TSP authenticity 与 Arkret event signature 各自独立验证**(spec §5 关键)
- Phase D-E 步骤 20、24:audit log 字段齐全(`relationship_id` / `payload_digest` / `payload_type` / `verification_result`),满足 spec §8 要求

## Edge cases / sub-tests

- **E2.1 TSP endpoint unreachable → fallback 到直接 HTTPS**:测试 harness 把 mock TSP endpoint 端口下掉(`process.kill(MOCK_TSP_ENDPOINT_PID)` 或 `route.block`);alice 再次尝试发 `ak.invite.create`;客户端应当**降级**到 Arkret v1 core 默认的 HTTPS JWE transport(spec 顶部 status 行:v1 core 默认走 HTTPS JWE / MLS DM),soland 通过 alice 的常规 `POST /_arkret/self/events` 路径接收。断言:invite 仍然送达 bob_extern(或在 soland 端进入 outbound queue 等待 bob_extern 上线),并且 audit log 出现一条 `transport.fallback{from: "tsp", to: "https-jwe", reason: "endpoint_unreachable"}` 记录
- **E2.2 VID resolver degraded(no witness)→ TSP relationship 降级**:把 alice 的 webvh witness service 下掉,让 bob_extern 解析 alice VID 时进入 degraded 状态;bob_extern 仍然能用已验证的 cached history 验证 signature,但 trust level 下降。断言:Phase B 第 9 步的 `trust_level` 字段从 `"verified"` 变成 `"degraded"`,UI 显示 ⚠ 标记;Phase D 第 18 步的 ACK 中 `verification.tsp_authenticity = "ok"`,但 `verification.vid_trust = "degraded_no_witness"`(spec §8:记录 support system 与 trust assessment result)
- **E2.3 metadata privacy (nested message)**:同 Phase C 的 nested mode,但显式引入一个 routing intermediary(mock 增加一个 `relay` 角色);intermediary 收到外层 envelope 后,只能看见 pairwise VID 与 `payload_digest`,看不到 `vid_local`(真实 alice DID)、看不到内层 `operation` 字段、也看不到 `payload` 明文。断言:`GET mock://relay-view?relationship_id=...` 返回的相关字段都被打码或缺失;唯有 bob_extern 这一终点能解出内层(spec §5:nested 隐藏内层 VID;intermediary 不应被视为可信授权方)

## Implementation notes

- **soland 缺口**:`ak.service.tsp` endpoint declaration 的注入、TSP envelope verify/route 路径、`tsp.*` audit event、`/_arkret/root/identity/{did}/transports` 暴露 — 整组未实现。整个 scenario fixme starter
- **inkson 缺口**:`/directory` 上的 `establish-tsp-button`、`/settings/connections` 的 TSP relationship 列表、relationship `trust_level` 的 ⚠ 标记 UI 都缺
- **mock-tsp-endpoint.mjs**:由并行任务交付;测试只通过 `process.env.MOCK_TSP_ENDPOINT_PORT` 与 `process.env.MOCK_TSP_ENDPOINT_VID` 访问。若两个 env 未设置,本 spec 应当 `test.skip` 而非 fail(下方 spec 用 `optionalEnv` 风格 guard)
- **WebVH host / DID:web host**:沿用 onboarding 的 current-root inception harness;DID Document 中 `ak.service.tsp` 注入需要 harness 支持(否则 Phase A 第 1-2 步会 fail closed)
- **TSP 是 extension profile,不是 v1 core 必需**:`tsp-integration.md` 顶部明确标注,整个文件目前是 SHOULD/MAY,因此 .spec.ts 全 fixme 不会 block release

## 总耗时预估

单次跑约 30-60s(单 browser context for alice + mock 两端独立处理 envelope + soland audit 轮询)。
