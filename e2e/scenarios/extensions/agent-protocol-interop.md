# Agent Protocol Interop:外部 A2A/ACP handoff 全链路

## 目标

验证 cokret v1 在 agent-protocol-interop extension profile 下的完整 handoff 闭环:Alice 通过 yougen 选定一个支持 A2A/ACP 的 agent endpoint → 完成 capability approval (含 human-approval gate) → soland 校验 endpoint 与目标 DID Document 的 service binding 一致 → 颁发 `cx.agent.protocol_session.start` 并把执行权移交给外部 agent runtime → 远端 agent 通过节流 `protocol_session.status` 回写进度并最终回写 `protocol_session.result` (含 audit_binding) → result 被 reducer 接受后 publish 一个 Flow/Morph 落地到 source space → audit chain 上 `start / status* / result` 全链能被 yougen agents-panel 验证签名通过。

过程中 cokret 始终持有身份 / capability / 任务登记 / 审计,外部协议只承担实时执行通道。

不验证:applet bot / ghost actor 链路 (见 `extensions/applet-bridge`)、MIMI federation handoff (见 `extensions/mimi-federation`)、capability chain 的 delegation 细节 (见 `authz/capability-chain`)、policy server obligation executor (见 `authz/policy-server-check`)、纯 MCP tool 调用 (见 §10,与 v1 agent-to-agent upgrade 无关)。

## Spec 锚点

- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §4 — 升级触发条件 (显式、可授权、可审计)
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §5.1 — `cx.agent.endpoint` 声明 (agent_card_url / metadata_url / transport / auth)
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §5.2 — `cx.agent.protocol_session.start` 字段集 (session_id / counterparty_agent / capability_grant / audit_mode)
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §5.3 — `cx.agent.protocol_session.status` 节流回写与标准状态枚举
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §5.4 — `cx.agent.protocol_session.result` 的 `result_objects` / `artifacts` / `external_transcript_digest`
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §6 步骤 4 — Endpoint validation 是 normative MUST (DID Document service binding + TLS / HTTP Sig pinning)
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §7 — Capability actions (`cx.agent.protocol.discover` / `protocol_session.start` / `cancel` / `stream_status` / `attach_artifact` / `read_transcript`) 与 constraint (`allowed_protocols` / `allowed_endpoints` / `requires_human_approval` / `max_duration_seconds` / `max_artifact_bytes` / `egress_policy`)
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §8 — 安全边界 (启动前 capability 检查、不信任外部 task status、artifact hash/MIME/size/policy 扫描)
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §9 — `audit_mode` 四档 (`status_only` / `summary_and_artifacts` / `full_transcript_hash` / `full_transcript`)
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §11 — Adapter registry (a2a / acp / mcp_bridge / http_custom) 与 adapter MUST 声明项
- `cokret-spec/spec/v1/zh/extensions/agent-protocol-interop.md` §12 — 失败码集合 (`discovery_failed` / `protocol_not_supported` / `auth_failed` / `policy_denied` / `remote_rejected` / `timeout` / `cancelled` / `artifact_rejected`)

## 拓扑

- 1 × soland (principal server) — 假设监听 `http://127.0.0.1:<soland_port>`,负责 agent endpoint registry、capability 校验、session reducer、audit binding 签发 (Ed25519,见 `soland/src/routing/events/agent_bridge.rs::REFERENCE_AGENT_AUDIT_ED25519_SEED`)
- 1 × coauth (auth server) — 仅用来给 alice 颁发 dev session 与 capability grant signing key
- 1 × yougen — 渲染 `/agents` (AgentsPanel);提供 capability approval UI 与 audit-binding badge
- 1 × mock-agent-runtime (gap) — 外部 A2A/ACP 端,负责接收 session start、回写 status 与 result,以及一份外部 transcript 摘要。**当前 cotest harness 没有 `mock-agent-runtime.mjs`**;短期方案是复用 `mock-applet-registry` 作为 HTTP echo stand-in (见 `helpers/env.ts::mockAppletRegistryBaseUrl`),把它当作 "支持 a2a 协议的远端" 来跑;长期方案是新增独立 mock,详见 Implementation notes。

(soland / coauth / yougen 都是 cotest 现有 harness 直接提供的,不需要改 `scripts/run-joint-e2e.ps1`;但 §5 / §6 的 normative endpoint validation 与外部 mock 都是 gap,见 Implementation notes。)

## Actors

| 名字 | DID | 在 agent-protocol-interop 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:web:alice-agent-handoff-<uuid>.example` | 人类 delegator;在 yougen 上选定 endpoint、批准 capability grant、签 `cx.agent.protocol_session.start`、最终接收 result 并 publish | 测试开始前 |
| local_agent | `did:web:local-agent-handoff-<uuid>.example` | alice 名下的 local agent actor;持 `cx.agent.protocol.discover` + `cx.agent.protocol_session.start` 两条 capability;实际 session.start 的 `actor_id` | 测试开始前 (`cx.agent.endpoint` 注册时由 alice 颁发 capability) |
| remote_agent | `did:web:agent-handoff-<uuid>.example` | 远端 agent,在 DID Document 的 `service` 数组里声明 a2a + acp 双 endpoint;由 mock-agent-runtime 代表;target of `counterparty_agent` 字段 | 测试开始前由 mock-agent-runtime 注入 (生成 DID Document 并 expose `agent-card.json`) |

> 命名约定:`local_agent` 与 `remote_agent` 都是 agent-class actor;alice 是 human delegator,签发 capability 但不直接执行 handoff。Spec §4 要求 upgrade MUST 是显式、可授权、可审计的行为,因此每条 capability grant 的 `actor` 都必须能被 audit chain 反查到 alice。

## Pre-conditions

- `alice`、`local_agent`、`remote_agent` 都通过 `POST /api/v1/account/register` 注册过 (`ensureRegistered`)
- `alice` 持有 dev session token (`POST /api/v1/auth/dev-login`)
- `alice` 的 browser context 通过 `yougen.config.v1` localStorage 注入 server_url / account_did / device_id / session_token
- `remote_agent` 的 DID Document 暴露至少一个 `service` entry,且 `serviceEndpoint` 字段精确等于 mock-agent-runtime 实际监听的 base URL (spec §6 步骤 4 normative MUST)
- mock-agent-runtime 健康检查 `GET /healthz` 返回 200,且 `GET /.well-known/agent-card.json` 返回符合 A2A AgentCard 形状的 JSON;ACP `GET /info` 返回 metadata
- soland 已认领 `cx.profile.agent_runtime.v1` extension profile (gap:目前 `/api/v1/server/describe` 的 `claimed_profiles` 大概率没有这一条,见 Implementation notes)

## Steps

### Phase A — Agent endpoint discovery (§5.1 / §6 步骤 1 / §7 `cx.agent.protocol.discover`)

1. **alice** 进入 yougen `/agents`,断言 `agents-panel` 渲染 (live probe);
2. **alice** 通过 `agent-register-form` 录入 `remote_agent.did` + `protocol = "a2a"` + `capabilities = "flow.read,flow.publish"`,点 `agent-register-submit-button`;
3. 断言 `agent-register-status` 文本包含 `event_id`,且 `agent-endpoint-row` 出现一条以 `remote_agent.did` 为 head 的记录;
4. **harness** 调 `GET /api/v1/identity/${remote_agent.did}/did-document` 拉 DID Document,断言其中 `service[].serviceEndpoint` 与 mock-agent-runtime base URL 字节级相等 (spec §6 步骤 4 的 host pinning 前置条件);
5. **local_agent** (通过 harness HTTP) 调 `POST /api/v1/agents/discover` (gap),传 `{ agent_id: remote_agent.did }`;断言返回 `{ supported_protocols: ["a2a", "acp"], agent_card_url, metadata_url }`,且 protocol 列表与 §11 adapter registry 合法 ID 子集一致 (`a2a` / `acp` / `mcp_bridge` / `http_custom`)。

### Phase B — Capability approval (§4 / §7 capability constraint / §8 启动前检查)

6. **alice** 在 yougen `/agents` 触发一个 protocol session draft — 选择 `remote_agent.did`、勾选 `requires_human_approval = true`、把 `allowed_protocols` 限定为 `["a2a"]`、`max_duration_seconds = 3600`、`max_artifact_bytes = 10485760`、`egress_policy = "metadata_only"`、`audit_mode = "summary_and_artifacts"`;
7. **alice** 在 `publish-modal-confirm` 之前必须看到一个明确的 human-approval gate (spec §4 要求 explicit + authorizable);**alice** 点 confirm 提交 capability grant `cg`;
8. 断言 soland 写入一条 `cx.capability.grant.create` 事件,`payload.actions` 包含 `cx.agent.protocol_session.start`,`payload.constraint.allowed_endpoints` 是单值列表精确指向 mock-agent-runtime base URL (spec §7 的 wildcard `https://*.trusted.example` 在测试里要收敛成精确值);
9. **harness** 再用 `local_agent` token 调 `POST /api/v1/agents/sessions` 不带 `capability_grant_ref` → 断言 HTTP 4xx 且 `error.code === "policy_denied"` (spec §12),证明启动前 capability 检查生效。

### Phase C — Invocation handoff with transcript (§5.2 / §5.3 / §6 步骤 5-7 / §9 audit modes)

10. **local_agent** (harness HTTP) 调 `POST /api/v1/agents/sessions` body `{ session_id, counterparty_agent: remote_agent.did, protocol: "a2a", endpoint_ref, capability_grant: cg, allowed_artifact_types: ["text","json"], max_duration_seconds: 3600, audit_mode: "summary_and_artifacts" }`;
11. 断言响应 200,且 soland 在 `GET /api/v1/account/subscribe?catchup=true` 或 `GET /api/v1/events` 里能立即观察到 `cx.agent.protocol_session.start` 事件 (kind 严格相等);
12. **soland** (`routing/events/agent_bridge.rs`) 触发外部协议握手:向 mock-agent-runtime `POST /v1/a2a/tasks` 投递 task,带 RFC 9421 HTTP Message Signature + Content-Digest (gap,见 Implementation notes);
13. **mock-agent-runtime** 在 N×500ms 节奏内向 soland `POST /api/v1/agents/sessions/${session_id}/status` 至少回写三条 `status` 事件,枚举至少包含 `negotiating → accepted → working` (spec §5.3 标准状态集合);
14. **alice** 在 yougen `/agents` 的 `agent-session-list` 看到 `agent-session-row` 出现,`status` 字段在 3s 内从 `negotiating` 推进到 `working`;
15. **harness** 断言:在 `audit_mode = "summary_and_artifacts"` 下,soland **不会**为每个外部 token 都持久化 status 事件;3 条 status 摘要事件足以满足 spec §9 的节流要求;反向证明:同一次 handoff 在 `status_only` 模式下 status 事件数 ≤ 1。

### Phase D — Publish-to-source (§5.4 / §6 步骤 8-9)

16. **mock-agent-runtime** 模拟终态,向 soland 回写 `cx.agent.protocol_session.result` 事件 body:`{ session_id, status: "completed", result_objects: [{ object_type: "flow", object_ref: "ck:flow:<uuid>", track: "synthesis", role: "primary_result" }], artifacts: [{ artifact_type: "text", object_ref: "ck:morph:<uuid>", hash: "sha256:..." }], external_transcript_digest: "sha256:...", completed_at: "<iso>" }`;
17. soland 用 `REFERENCE_AGENT_AUDIT_ED25519_SEED` 给 `audit_binding` 块签 Ed25519,canonical subject 形如 `{session_id, agent_id, result.echo, actor}`,断言响应里 `audit_binding.binding_kind === "ed25519_v1"` 且 `audit_binding.key_id === "soland.reference.agent_echo.ed25519_v1"`;
18. **alice** 在 yougen `/agents` 的 `agent-incoming-results` 看到一条 `agent-incoming-result-row`,`agent-audit-verify-badge` 文本严格等于 `audit valid` (绿色徽章);
19. **alice** 在 `/agents` 的对应 protocol session detail 区确认 result artifact;保留 remote_agent attribution,点 `publish-modal-confirm`;
20. 断言 source space 里出现一条新 Flow,其 `fields.workflow_type` 包含 `synthesis`,且 `relation` 指向 `ck:morph:<uuid>` artifact;Flow 创建事件的 `actor_id` 是 `alice.did`,但 `attribution` 字段保留 `remote_agent.did` (spec §5.4 关于 publish 的语义)。

### Phase E — Audit chain verification (§5 + §9 + agent_binding SDK)

21. **harness** 调 `GET /api/v1/events?after=<cursor>` 拉一组事件,按 `event_kind` 过滤出本次 session_id 的全部记录,断言顺序严格为 `start → status (negotiating) → status (accepted) → status (working) → result (completed)` (不允许 status 在 start 之前出现,不允许 result 之后再有 status);
22. 对每个事件,断言其 `prev_event_id` 与上一条的 `event_id` 一致 (audit chain hash 链);
23. 对 `result` 事件,用 `contrix_sdk::agent_binding::verify_audit_binding_by_kind` 跑一次 in-process 校验 — 通过则证明 SDK 与 soland 签发端一致 (与 `yougen/src/views/agents.rs::verify_agent_audit_binding` 完全等价);
24. **alice** 在 `/agents` 顶部的 `agent-incoming-poll-tick` 出现 `tick N`,且 `agent-incoming-status` 显示 `1 result event(s) (1 new since last poll)` 至少一次,证明 yougen 的 4s 轮询拉到了刚回写的 result 事件;
25. **harness** 把整段事件链写入测试 artifact (testInfo attach `agent-handoff-audit-chain.json`),便于人工审查。

## Observable assertions (合并清单)

- Phase A:`agents-panel` 渲染、`agent-endpoint-row` 出现、DID Document `service.serviceEndpoint` 与 mock URL 字节级相等、`POST /api/v1/agents/discover` 返回 `supported_protocols` 是 §11 adapter registry 子集
- Phase B:`cx.capability.grant.create` 持久化、`allowed_endpoints` 精确单值、缺失 `capability_grant_ref` 的启动尝试返回 `policy_denied`
- Phase C:session.start event 在 backfill 中可见;status 事件 3s 内推进 `negotiating → working`;`summary_and_artifacts` 节流模式下 status 事件数远少于实际 token 数
- Phase D:result 事件携带 `result_objects` / `artifacts` / `external_transcript_digest` 三者至少之一;`audit_binding.binding_kind === "ed25519_v1"`;yougen 渲染 `audit valid` 徽章;publish 落地 Flow 保留 `attribution`
- Phase E:事件顺序 start → status* → result,`prev_event_id` 链不断;SDK 与 soland 签发端一致;yougen 轮询拉到新 result

## Edge cases / sub-tests

- **E1.1 agent rejects capability**:mock-agent-runtime 在 Phase C 步骤 12 收到 task 后直接返回 403 / `remote_rejected`;soland 必须写入一条 `cx.agent.protocol_session.result` (status=`failed`、`error.code="remote_rejected"`),并**不再**伪造 status(working);yougen 徽章应该是 `no binding` (Absent,因为 fail-closed 路径不签 audit_binding,见 `agent_bridge.rs::maybe_emit_echo_result_for_session_start` 的 unknown_agent 分支)。
- **E1.2 transcript hash mismatch**:mock-agent-runtime 在 result 里故意写一个错误的 `external_transcript_digest` (不匹配它实际投递的 transcript);harness 用本地重算的 hash 与 result 字段比对,断言报告 mismatch;reducer 在严格 audit 模式下应拒绝 publish (返回 4xx + `error.code="artifact_rejected"`,spec §12)。
- **E1.3 endpoint binding drift**:mock-agent-runtime 在 Phase A 之后偷偷换 `serviceEndpoint` 到另一个 host;在 Phase C 步骤 10 调 `POST /api/v1/agents/sessions` 时,soland 必须重新校验 DID Document service binding (spec §6 步骤 4 normative MUST),发现 mismatch 后返回 `policy_denied`。
- **E1.4 audit gap repaired**:故意 drop 一条 status 事件 (模拟网络),手动 POST 一条带正确 `prev_event_id` 的补偿事件,断言 reducer 接受并把 audit chain 修补回完整链;再跑一次 Phase E 步骤 21-22,顺序与 prev_event_id 链都仍然连贯。
- **E1.5 cancel mid-flight**:alice 在 Phase C `working` 状态时点 session cancel;soland 发出 `cx.agent.protocol_session.cancel` (capability `cx.agent.protocol_session.cancel`,spec §7),mock-agent-runtime 回写 `status="cancelled"` + 一个空 result `{ status: "cancelled", error: {...} }`;yougen 徽章是 `audit valid` (cancellation 仍签 audit_binding,只是 result 不含 artifacts);Phase D publish 路径必须 disabled。

后两条 (E1.4, E1.5) 建议拆成独立的小 spec (`extensions/agent-protocol-interop.audit-gap`、`extensions/agent-protocol-interop.cancel`),保持主 scenario 紧凑。

## Implementation notes

- **soland 缺口**:
  - `POST /api/v1/agents/discover` 端点目前**未实现**,需新增 (从 `cx.agent.endpoint` projection 反查 supported_protocols + agent_card_url)。
  - `POST /api/v1/agents/sessions` 与 `POST /api/v1/agents/sessions/${id}/status` 当前由 `agent_bridge.rs` 内部 fan-out 模拟 (in-process echo);真实的外部 HTTP handoff (RFC 9421 + Content-Digest + DID Document service binding 校验) 仍**未实现**,见 `agent_bridge.rs` 头注 "When the registered agent carries an `endpoint_url`, the runtime POSTs the invocation to it via reqwest"。
  - `claimed_profiles` 数组应该包含 `cx.profile.agent_runtime.v1`,但 `routing/system/describe.rs` 还没把它写进去 — 这条覆盖 Phase A 步骤 5 的 supported_protocols 列表来源。
  - audit_binding 签名 / 校验 SDK 已有 (`contrix_sdk::agent_binding`),但 fail-closed 路径 (E1.1) 故意 absent,需要 e2e 显式钉住。
- **yougen 缺口**:
  - `/agents` 的 protocol session draft 仍需与 soland capability grant API 做真实绑定。
  - publish modal 的 "保留 remote_agent attribution" 选项 (testid `publish-modal-signer-self-with-attribution`) 需要从 protocol session result 状态进入。
  - `/agents` 顶部的 `agent-incoming-poll-tick` 与 `agent-incoming-status` 已存在 (4s 轮询 + diff 提示),Phase E 步骤 24 可直接断言。
- **mock-agent-runtime 缺口**:**当前没有 `cotest/scripts/mock-agent-runtime.mjs`**。短期方案:在测试代码里复用 `mockAppletRegistryBaseUrl()` 作为 HTTP echo target,只跑 Phase A 的 endpoint registry + DID document lookup 路径,Phase C-E 全 fixme;长期方案:新增 `cotest/scripts/mock-agent-runtime.mjs`,实现 `/.well-known/agent-card.json` + `/info` + `/v1/a2a/tasks` + `/v1/acp/tasks` 四个端点,以及对 soland status webhook 的回调能力,然后在 `helpers/env.ts` 添加 `mockAgentRuntimeBaseUrl()` 与 `mockAgentRuntimeDid()`。
- **fixture loader**:Phase D 的 result event canonical bytes 应该可以挂到 `cokret-spec/spec/v1/artifacts/fixtures/cx.agent.protocol_session.result.*.json`,但目前 fixture 目录还没有 agent 相关条目 (本 scenario 落地后可同步追加)。
- **no new helper**:用现有 `request` fixture + `ensureRegistered` / `issueDevSession` / `openUserPage`;**不要**新增 `helpers/agents.ts`,session lifecycle 调用直接写在 spec 文件里。Phase B 的 capability grant create 暂时也直接打 HTTP,等真有 3 个以上 scenario 共享时再抽 helper。
- **why ed25519 signing seed is fine in test**:`soland/src/routing/events/agent_bridge.rs` 头注已经声明 reference seed 是公开的 (production 必须通过 `AppConfig::agent_audit_binding_signing_seed` 注入),所以 e2e 直接用 reference public key 校验签名是符合预期的。

## 总耗时预估

单次跑约 60-90s (1 个 browser context、5 个 phase、~25 步,其中 Phase C 的 status 节流断言占 ~10s 等待窗口)。Phase A 单独跑 (smoke-live) < 5s。
