# `arkret-work/docs/flows` 与 joint-e2e 覆盖矩阵

> as_of：2026-08-24
> 审计范围：`arkret-work/docs/flows` 的 12 篇流程/模型文档、60 个 Mermaid 图，以及 cotest Playwright、Rust conformance/scenario 和 agent journey 入口。
> “joint smoke”专指 `scripts/run-cotest.ps1 -Profile joint`：启动 Soland、Inkson、Coauth，以 `joint-inkson` project 运行 `@fully-implemented` 用例。
> “full/分层”表示证据存在于完整 Playwright、双 Soland、Rust conformance/scenario 或 agent journey 中，不等于标准 joint smoke 会执行。

## 结论

- 不能宣称 joint-e2e 已包含流程库的全部流程。标准 joint smoke 现在直接覆盖账号注册/登录/会话、首设备与第二设备授权、普通 Realm bootstrap、Direct Conversation founding、基础消息同步、Agent/Sidecar 边界，以及当前 service route 认证。
- planned route handover、ACK barrier/cutover、mirror 失联恢复、完整设备撤销/全设备 recovery、Direct Conversation repair、native Agent/Sidecar 生产链和完整 Invite+MLS+history 重启链仍没有单条标准 joint smoke 闭环。
- `ordinary-realm-creation.md` 与 `realm-invitation-history-bootstrap.md` 的 `since_join` current-projection 问题是规范缺口，不应通过补测试把未定义行为固化。见 `arkret-work/review/spec-open/2026-08-24-0941-since-join-default-strand-current-projection-undefined.md`。
- 本轮把已有、适合标准拓扑的合同测试加入 `joint-inkson` 选择面，并新增 current service-resolution live 测试；需要双服务、Savfox 或尚不存在生产编排的流程继续留在专用 lane。

## 流程图复核结果

- 12 篇流程/模型文档共 60 个 Mermaid block 均成对闭合，图类型可识别；图中引用的 `/_arkret/...` endpoint 和 `ak.*` operation/event identifier 在 current spec 的 schema/registry/OpenAPI 中没有发现未登记项。
- 修正 `registration-pcr-genesis.md` 与 `device-pairing-and-recovery.md`：`InitialSessionGrantRequest` 已被 `InitialSessionGrantIntent` 取代，且 Standard human intent 不允许携带 `requested_scope`。
- 修正普通 Realm、Invite/history、Direct Conversation 与 Personal Agent 流程的状态头：这些流程依赖的 `since_join` current baseline 或默认 availability holder-role 派生仍有已登记规范 blocker，不能标成 protocol closed。
- 修正 route 两篇流程的实现边界：owner plan/inspect/cancel 和 Realm audience snapshot/reconcile 已落地；outbound publish、ACK barrier、cutover 和主动 mirror fetch 仍缺。
- 删除已不存在的 `history-joined-enforcement.spec.ts` 引用，改指向现存 Playwright/Rust 分层证据；删除已经完成迁移的“旧 MLS creator payload 字段”状态说明。

## 覆盖矩阵

| 流程文档 | 标准 joint smoke 直接证据 | full / Rust / journey 分层证据 | 判断与主要缺口 |
| --- | --- | --- | --- |
| `account-authentication-and-session-lifecycle.md` | `identity/oidc-login-flow.spec.ts`、`passkey-login-flow.spec.ts`、`session-grant-dpop.spec.ts`、`device-key-lifecycle.spec.ts` | `identity/account-device-auth.spec.ts`、`account-states.spec.ts`；`auth_session_proof.rs`、issuer-ledger conformance | **较强但非全流程**：登录、handoff、DPoP、refresh/relogin 主链已进 smoke；全部撤销/失效竞态仍是分层证据。 |
| `registration-pcr-genesis.md` | `identity/account-handoff.spec.ts`、`identity/onboarding.spec.ts` | `identity/account-states.spec.ts`、`coauth-account-lifecycle-fixture.json` | **主链覆盖**：真实 Coauth+Soland 注册与 PCR genesis 已进 smoke；故障注入/saga 恢复不是一条浏览器闭环。 |
| `ordinary-realm-creation.md` | `events/batch-realm-bootstrap.spec.ts`、`joint/joint-inkson-smoke.spec.ts` | `realm_wire_round_trip.rs`、`realm_actor_frontier_e2e.rs` | **创建主链覆盖**；late-join current projection 受 0941 阻断，首个 successor Seal 的 holder-role 派生受 1102 阻断。 |
| `realm-invitation-history-bootstrap.md` | `joint/multi-profile-same-server.spec.ts` 覆盖同服务多账号邀请/协作切片 | `invites/invite-addressing.spec.ts`、`messaging/triad-collaboration.spec.ts`、`kanban/cross-member-encrypted.spec.ts`、`agent_encrypted_realm_member_e2e.rs`、`interaction_models.rs` | **分层覆盖，未形成单条 smoke 闭环**：Invite、MLS、history 各有证据；完整四次 Control Move、双账号设备、两种 history policy、重启恢复仍缺，且受 0941/1102 影响。 |
| `service-route-discovery-handover-and-repair.md` | `joint/service-resolution-bootstrap.spec.ts` 仅覆盖 current signed record、Describe reverse binding、稳定重读与错误 core 拒绝 | `service_route_handover_mirror*.rs`、`fanout_route_miss_live.rs` | **部分覆盖**：current route 已进 smoke；outbound publish、durable ACK、safe cutover、Realm/configured mirror 主动恢复尚无生产闭环，不能补成伪 live 测试。 |
| `service-route-authentication-and-relocation.md` | 同上 | 同上，另有 Soland owner plan/audience 单元与存储合同证据 | **部分覆盖**：认证已 live；plan→publish→ACK→cutover→grace 未覆盖。 |
| `realm-event-server-fanout.md` | `joint/joint-inkson-smoke.spec.ts` 覆盖单服务 author/sync | `federation/cross-server.spec.ts`、`invite_service_fanout_live.rs`、`fanout_route_miss_live.rs`；`dual-soland` lane | **双服务 lane 覆盖**，不进入标准 joint smoke；route miss/repair 与跨服务 fanout 需专用双 Soland 拓扑。 |
| `message-authoring-seal-sync.md` | `joint/joint-inkson-smoke.spec.ts`、`joint/multi-profile-same-server.spec.ts` | `sync/offline-conflict.spec.ts`、`offline-queue-replay.spec.ts`、`messaging/*`、`account_subscribe_long_poll.rs` | **主链覆盖，边界分层**：author/seal/read/sync 有 live；offline、stream/backfill、冲突修复由 full/Rust 覆盖。 |
| `contact-direct-conversation-lifecycle.md` | `identity/direct-conversation-founding.spec.ts` | `federation/contact-graph-federation.spec.ts`、`governance/personal-blocklist.spec.ts`、`direct_conversation_flow.rs` | **founding 覆盖、repair 未闭环**：跨服务 contact/DC 与 block 有分层证据；Commit/Welcome successor Seal 受 1102 阻断，真实 lost-state repair/rejoin 仍缺。 |
| `personal-agent-sidecar-strand-relay.md` | `joint/circle-sidecar-boundary.spec.ts`、`contact-agent-sidebar.spec.ts`；`agent-savfox-split-live.spec.ts` 仅在 Savfox 可用时执行 | Agent/Sidecar conformance、`agent_encrypted_realm_member_e2e.rs`、agent journeys | **部分且条件化**：对象边界进 smoke；successor Seal 受 1102 阻断，native Sidecar/Agent 生产入口、完整 relay 与恢复没有无条件闭环。 |
| `device-pairing-and-recovery.md` | `identity/device-key-lifecycle.spec.ts`、`identity/multi-device.spec.ts` | `identity/recovery.spec.ts`、`recovery_completion_grant.rs`、`recovery_transaction_faults.rs`；`device-pairing-revocation-recovery` journey | **配对/第二设备授权覆盖，完整恢复未覆盖**：撤销、re-anchor、全设备丢失和恢复后 grant 尚未组合成标准 live 闭环。 |
| `contact-lineage-model.md` | `identity/direct-conversation-founding.spec.ts`、`joint/contact-agent-sidebar.spec.ts` | `identity/contact-graph.spec.ts`、`federation/contact-graph-federation.spec.ts`、`direct_conversation_flow.rs` | **模型不变量有分层覆盖**；跨域 lineage repair、合并/冲突和完整生命周期未形成单条 joint 场景。 |

## 本轮 joint-smoke 选择面

`joint-inkson` 除 `joint/*.spec.ts` 外，显式选择以下 `@fully-implemented` 合同测试：

- `events/batch-realm-bootstrap.spec.ts`
- `identity/account-handoff.spec.ts`
- `identity/direct-conversation-founding.spec.ts`
- `identity/device-key-lifecycle.spec.ts`
- `identity/multi-device.spec.ts`
- `identity/onboarding.spec.ts`
- `identity/oidc-login-flow.spec.ts`
- `identity/passkey-login-flow.spec.ts`
- `identity/session-grant-dpop.spec.ts`

本轮新增选择项的标准是：能在标准 Soland+Inkson+Coauth 拓扑中执行，不依赖双 Soland、Savfox 或外部 provider，并且断言生产 HTTP/UI 行为。`joint/*.spec.ts` 中既有的 Savfox 条件场景仍会在缺少 Savfox 时 skip；专用拓扑测试继续由对应 lane 运行，避免标准 smoke 的绿色结果被误读成全流程闭环。

## 本轮验证状态

- `npm run typecheck`：通过。
- `npx playwright test --list --project joint-inkson`：通过，发现 17 个文件、30 条测试；新增 route 场景 2 条均被选择。
- `scripts/generate-e2e-coverage.ps1 -Check`、`npm run check:wire-types`、`npm run check:fixme`、`scripts/tests/identity-ci-selection.tests.ps1`：通过。
- 流程库 60 个 Mermaid block 的 fence/type 检查、本地 Markdown 链接检查和两个仓库的 `git diff --check`：通过。
- 定向 live run `20260824-192725-joint-smoke-selection`：**未执行到 Playwright**。runner 在 freshness build 阶段编译 Soland 失败；当前 `arkret-rust-sdk` 已采用扁平 `AvailabilityReceipt`，而 `soland/crates/http/src/notary.rs` 仍引用已删除的 `AvailabilityReceiptContent`、`receipt`、`receipt_digest` 与 `validate_receipt_digest`，共 9 个 Rust 编译错误。该跨仓中间态不是本轮 TypeScript 变更造成，不能把结果记成 route 测试失败或通过。

## 后续补测优先级

1. 先闭合 0941 规范问题，再增加 `since_join` 新成员“不可见旧数据，但能取得当前默认 Strand/governance/security baseline”的联合测试。
2. Soland G3–G7 生产编排落地后，增加双 Principal Server `plan → publish → ACK → cutover → old endpoint down → mirror repair` 的 live 场景。
3. 增加无测试后门的两账号 MLS Invite 场景，覆盖 Commit/Welcome finality、两种 history policy 与进程重启。
4. 增加第二设备配对、旧设备撤销、全设备 recovery/re-anchor、恢复后 Standard grant 的一条完整联合场景。
5. native Agent/Sidecar 入口可达后，把当前条件化/分层证据升级为无条件 joint lane。
