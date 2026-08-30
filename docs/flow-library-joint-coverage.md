# `arkret-work/docs/flows` 与 joint-e2e 覆盖矩阵

> as_of：2026-08-30
> 审计范围：`arkret-work/docs/flows` 的 12 篇流程/模型文档、60 个 Mermaid 图，以及 cotest Playwright 与 Rust conformance/scenario 入口。
> “joint smoke”专指 `scripts/run-server-conformance.ps1 -Profile joint`：启动 Soland、Inkson、Coauth，以 `joint-inkson` project 运行 `@fully-implemented` 用例。
> “full/分层”表示证据存在于完整 Playwright、双 Soland 或 Rust conformance/scenario 中，不等于标准 joint smoke 会执行。

## 结论

- 不能宣称 joint-e2e 已包含流程库的全部流程。标准 joint smoke 现在直接覆盖账号注册/登录/会话、24 词 Recovery Key 设置与 fresh-browser MLS 恢复、首设备与第二设备授权、普通 Realm 明文/MLS 两种创建与写入、Direct Conversation founding、基础消息同步、Agent/Sidecar 边界，以及当前 service route 认证。
- planned route handover、ACK barrier/cutover、mirror 失联恢复、完整设备撤销/全设备 recovery、Direct Conversation repair、native Agent/Sidecar 生产链和完整 Invite+MLS+history 重启链仍没有单条标准 joint smoke 闭环。
- `ordinary-realm-creation.md` 与 `realm-invitation-history-bootstrap.md` 的 `since_join` current-projection 测试必须遵守 `arkret-spec/spec/v1/zh/sync/client-sync.md` 的已闭合 current object/security baseline 合同。
- canonical `identity/recovery-key-to-encrypted-realm` 现在以同一真实注册账号对称验证 `encryption_profile=none` 与 `mls_rfc9420`：两者都必须创建、写入、刷新后读取；前者 wire 必须有明文且无 `encrypted_content`，后者必须有 `encrypted_content` 且不得泄露消息明文。
- `encryption/key-backup` 的 A3 真实 OIDC 第二浏览器恢复已提升为 `@fully-implemented`，默认 smoke 同时要求该 scenario 与 canonical Realm scenario 出现在 JUnit 中，避免“测试存在但默认未选择”的假覆盖。
- 本轮把已有、适合标准拓扑的合同测试加入 `joint-inkson` 选择面，并新增 current service-resolution live 测试；需要双服务、Savfox 或尚不存在生产编排的流程继续留在专用 lane。

## 流程图复核结果

- 12 篇流程/模型文档共 60 个 Mermaid block 均成对闭合，图类型可识别；图中引用的 `/_arkret/...` endpoint 和 `ak.*` operation/event identifier 在 current spec 的 schema/registry/OpenAPI 中没有发现未登记项。
- 修正 `registration-pcr-genesis.md` 与 `device-pairing-and-recovery.md`：`InitialSessionGrantRequest` 已被 `InitialSessionGrantIntent` 取代，且 Standard human intent 不允许携带 `requested_scope`。
- 修正普通 Realm、Invite/history、Direct Conversation 与 Personal Agent 流程的状态头：这些流程依赖的 `since_join` current baseline 或默认 availability holder-role 派生仍有已登记规范 blocker，不能标成 protocol closed。
- 修正 route 两篇流程的实现边界：owner plan/inspect/cancel 和 Realm audience snapshot/reconcile 已落地；outbound publish、ACK barrier、cutover 和主动 mirror fetch 仍缺。
- 删除已不存在的 `history-joined-enforcement.spec.ts` 引用，改指向现存 Playwright/Rust 分层证据；删除已经完成迁移的“旧 MLS creator payload 字段”状态说明。

## 覆盖矩阵

| 流程文档 | 标准 joint smoke 直接证据 | full / Rust 分层证据 | 判断与主要缺口 |
| --- | --- | --- | --- |
| `account-authentication-and-session-lifecycle.md` | `identity/oidc-login-flow.spec.ts`、`passkey-login-flow.spec.ts`、`session-grant-dpop.spec.ts`、`device-key-lifecycle.spec.ts` | `identity/account-device-auth.spec.ts`、`account-states.spec.ts`；`auth_session_proof.rs`、issuer-ledger conformance | **较强但非全流程**：真实密码/OIDC 的 login→reload→logout→returning login、错误密码、Passkey、handoff、DPoP 与 refresh 主链已进 smoke；全部撤销/失效竞态仍是分层证据。 |
| `registration-pcr-genesis.md` | `identity/account-handoff.spec.ts`、`identity/onboarding.spec.ts` | `identity/account-states.spec.ts`、`coauth-account-lifecycle-fixture.json` | **主链覆盖**：真实 Coauth+Soland 注册与 PCR genesis 已进 smoke；故障注入/saga 恢复不是一条浏览器闭环。 |
| `ordinary-realm-creation.md` | `identity/recovery-key-to-encrypted-realm.spec.ts`、`events/batch-realm-bootstrap.spec.ts`、`joint/joint-inkson-smoke.spec.ts` | `encryption/mls-group.spec.ts`、`realm_wire_round_trip.rs`、`realm_actor_frontier_e2e.rs` | **明文/MLS 创建主链对称覆盖**：真实 UI 对两种 profile 均验证 create→message→reload，并检查 wire 明文边界；late-join current projection 与 successor Seal availability 仍需专门场景。 |
| `realm-invitation-history-bootstrap.md` | `joint/multi-profile-same-server.spec.ts` 覆盖同服务多账号邀请/协作切片 | `invites/invite-addressing.spec.ts`、`messaging/triad-collaboration.spec.ts`、`kanban/cross-member-encrypted.spec.ts`、`agent_encrypted_realm_member_e2e.rs`、`interaction_models.rs` | **分层覆盖，未形成单条 smoke 闭环**：Invite、MLS、history 各有证据；规范合同已闭合，但完整四次 Control Move、双账号设备、两种 history policy、availability receipt 与重启恢复仍缺联合 live 证据。 |
| `service-route-discovery-handover-and-repair.md` | `joint/service-resolution-bootstrap.spec.ts` 仅覆盖 current signed record、Describe reverse binding、稳定重读与错误 core 拒绝 | `service_route_handover_mirror*.rs`、`fanout_route_miss_live.rs` | **部分覆盖**：current route 已进 smoke；outbound publish、durable ACK、safe cutover、Realm/configured mirror 主动恢复尚无生产闭环，不能补成伪 live 测试。 |
| `service-route-authentication-and-relocation.md` | 同上 | 同上，另有 Soland owner plan/audience 单元与存储合同证据 | **部分覆盖**：认证已 live；plan→publish→ACK→cutover→grace 未覆盖。 |
| `realm-event-server-fanout.md` | `joint/joint-inkson-smoke.spec.ts` 覆盖单服务 author/sync | `federation/cross-server.spec.ts`、`invite_service_fanout_live.rs`、`fanout_route_miss_live.rs`；`dual-soland` lane | **双服务 lane 覆盖**，不进入标准 joint smoke；route miss/repair 与跨服务 fanout 需专用双 Soland 拓扑。 |
| `message-authoring-seal-sync.md` | `joint/joint-inkson-smoke.spec.ts`、`joint/multi-profile-same-server.spec.ts` | `sync/offline-conflict.spec.ts`、`offline-queue-replay.spec.ts`、`messaging/*`、`account_subscribe_long_poll.rs` | **主链覆盖，边界分层**：author/seal/read/sync 有 live；offline、stream/backfill、冲突修复由 full/Rust 覆盖。 |
| `contact-direct-conversation-lifecycle.md` | `identity/direct-conversation-founding.spec.ts` | `federation/contact-graph-federation.spec.ts`、`governance/personal-blocklist.spec.ts`、`direct_conversation_flow.rs` | **founding 覆盖、repair 未闭环**：跨服务 contact/DC 与 block 有分层证据；successor Seal 合同已闭合，真实 Commit/Welcome availability 与 lost-state repair/rejoin live 证据仍缺。 |
| `personal-agent-sidecar-strand-relay.md` | `joint/circle-sidecar-boundary.spec.ts`、`contact-agent-sidebar.spec.ts`；`agent-savfox-split-live.spec.ts` 仅在 Savfox 可用时执行 | Agent/Sidecar conformance、`agent_encrypted_realm_member_e2e.rs` | **部分且条件化**：对象边界进 smoke；successor Seal 合同已闭合，native Sidecar/Agent 生产入口、完整 availability/relay/恢复没有无条件闭环。 |
| `device-pairing-and-recovery.md` | `identity/device-key-lifecycle.spec.ts`、`identity/multi-device.spec.ts`、`encryption/key-backup.spec.ts` A3 | `identity/recovery.spec.ts`、`recovery_completion_grant.rs`、`recovery_transaction_faults.rs` | **配对与内容恢复主链覆盖，身份全恢复未覆盖**：第二浏览器真实 OIDC 登录、设备配对、输入 24 词、恢复并解密历史 MLS 已进 smoke；旧设备撤销、全设备丢失、PCR re-anchor 与恢复后 Standard grant 尚未组合成一条 live 闭环。 |
| `contact-lineage-model.md` | `identity/direct-conversation-founding.spec.ts`、`joint/contact-agent-sidebar.spec.ts` | `identity/contact-graph.spec.ts`、`federation/contact-graph-federation.spec.ts`、`direct_conversation_flow.rs` | **模型不变量有分层覆盖**；跨域 lineage repair、合并/冲突和完整生命周期未形成单条 joint 场景。 |

## 本轮关键用户验收盘点

| 用户场景 | 当前默认 smoke 证据 | 结论 |
| --- | --- | --- |
| 新账号注册并设置 24 词 | `identity/recovery-key-to-encrypted-realm`、`identity/oidc-login-flow` onboarding case | 已覆盖真实 Coauth 注册/OAuth/Inkson onboarding；读取 24 个词、原样确认、完成身份创建，禁止 session injection 与 recovery override。 |
| 返回用户登录 | `identity/oidc-login-flow` | 已覆盖密码登录、reload 保持、hard logout、同一 device returning login、错误密码；Passkey 另有真实虚拟认证器场景。 |
| 24 词恢复历史加密内容 | `encryption/key-backup` A3 | 已覆盖 fresh browser 登录、第二设备配对、输入 Recovery Key、DPoP-bound unlock、reload 与历史 MLS 内容解密；bearer-only unlock 必须拒绝。 |
| 非加密 Realm | `identity/recovery-key-to-encrypted-realm` matrix | 已覆盖真实 UI create/write/reload；Event ingress 必须包含消息明文且无 `encrypted_content`。 |
| MLS 加密 Realm | 同上 | 已覆盖真实 UI create/write/reload；Event ingress 必须包含 `encrypted_content` 且不含明文，reload 后仍可解密。 |
| Realm 邀请与 history | `joint/joint-inkson-smoke`、`kanban/cross-member-encrypted` 等分层证据 | 邀请、post-join MLS、shared-history 分散覆盖；仍缺两种 history policy、重启和 current baseline 的单条联合闭环。 |
| 全设备身份恢复 | Rust recovery conformance 与局部 UI 证据 | 尚未形成“撤销/全丢失→PCR re-anchor→新 Standard grant→旧设备失效”的 live-product 闭环。 |
| Service 搬迁修复 | route conformance/局部 live | current record 认证已覆盖；plan→ACK→cutover→旧端下线→mirror repair 仍缺生产闭环。 |

## 默认 joint-smoke 选择面

默认 `joint-smoke` 使用 `@fully-implemented` grep。除既有 `joint/*.spec.ts` 与已标记合同外，身份专项 `joint-inkson` project 显式选择：

- `events/batch-realm-bootstrap.spec.ts`
- `encryption/key-backup.spec.ts`
- `identity/account-handoff.spec.ts`
- `identity/direct-conversation-founding.spec.ts`
- `identity/device-key-lifecycle.spec.ts`
- `identity/multi-device.spec.ts`
- `identity/onboarding.spec.ts`
- `identity/oidc-login-flow.spec.ts`
- `identity/passkey-login-flow.spec.ts`
- `identity/recovery-key-to-encrypted-realm.spec.ts`
- `identity/session-grant-dpop.spec.ts`

本轮新增选择项的标准是：能在标准 Soland+Inkson+Coauth 拓扑中执行，不依赖双 Soland、Savfox 或外部 provider，并且断言生产 HTTP/UI 行为。`joint/*.spec.ts` 中既有的 Savfox 条件场景仍会在缺少 Savfox 时 skip；专用拓扑测试继续由对应 lane 运行，避免标准 smoke 的绿色结果被误读成全流程闭环。

此外，默认 `joint-smoke` 现在把 `identity/recovery-key-to-encrypted-realm` 与 `encryption/key-backup` 都列为 required scenario；缺少任一 JUnit 证据、运行时 skip 或零选择都会使 gate 失败。

## 本轮验证状态

- `npm run typecheck`：通过。
- `scripts/generate-e2e-coverage.ps1 -Check`、`scripts/generate-scenario-evidence.ps1 -Check`、`npm run check:wire-types`、`npm run check:fixme`：通过。
- `scripts/tests/identity-ci-selection.tests.ps1`：通过；并固定 Recovery Key restore 与 Realm profile matrix 的 smoke/required-scenario 选择合同。
- `npx playwright test --list --project joint-inkson --grep <两条关键标题>`：通过，明确选择 `encryption/key-backup` A3 与 `identity/recovery-key-to-encrypted-realm`，共 2 个文件 2 条测试；这同时验证两个 spec 已进入默认 conformance project，而不只是全量 `chrome` project 可发现。
- 流程库复核：12 篇流程/模型文档加 README、60 个 Mermaid block 的 fence/type 均有效；本地 Markdown 失效链接为 0，图文引用的 `/_arkret/*` 路径均能在 current operation registry 中解析，旧 `recipient_service_id` 与未登记 Agent grant 端点均已移除。
- `git diff --check`：`cotest` 与 `arkret-work` 均通过。
- live-product 定向运行：**未启动服务**。runner freshness rebuild 后，Soland、Coauth、Inkson、`cotest-wire` 产物与 Playwright 1.60.0 均通过预检；本机 Docker Desktop daemon 随后因失效的 `AppData/Local/Docker/run/dockerInference` reparse point 自行崩溃，临时 PostgreSQL 无法启动。该结果只能记为环境阻塞，不能记成两条 E2E 通过或失败。

## 后续补测优先级

1. 增加 `since_join` 新成员“不可见旧数据，但能取得当前默认 Strand/governance/security baseline”的联合测试；该规范合同已闭合，剩余工作是生产实现与 live 证据验收。
2. Soland G3–G7 生产编排落地后，增加双 Principal Server `plan → publish → ACK → cutover → old endpoint down → mirror repair` 的 live 场景。
3. 增加无测试后门的两账号 MLS Invite 场景，覆盖 Commit/Welcome finality、两种 history policy 与进程重启。
4. 增加第二设备配对、旧设备撤销、全设备 recovery/re-anchor、恢复后 Standard grant 的一条完整联合场景。
5. native Agent/Sidecar 入口可达后，把当前条件化/分层证据升级为无条件 joint lane。
