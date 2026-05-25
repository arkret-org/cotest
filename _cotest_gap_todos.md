# cotest gap todos

生成日期: 2026-05-21

本文件从 `e2e/tests/**.spec.ts`、`e2e/scenarios/**.md`、`_e2e_report.md`、`_e2e_fixes_report.md` 反推当前相关项目完成度,并把未完成项集中成任务列表。`test.fixme` 仍是 contract-first 占位:服务端 / 客户端能力落地后,去掉 `.fixme` 即可激活。

## 本轮新增 / 补齐的 cotest 覆盖

- [x] 新增 `e2e/tests/workflows/incident-response.spec.ts` + `e2e/scenarios/workflows/incident-response.md`,覆盖事故响应 war room、SEV priority、状态 FSM、postmortem 文档。
- [x] 补齐 `identity/consent-grant.spec.ts` 的 5 条 consent lifecycle fixme 主体。
- [x] 补齐 `messaging/chat-advanced.spec.ts` 的 mention routing、poll、typing、presence、E2EE mention sidecar fixme 主体。
- [x] 补齐 `discovery/notifications.spec.ts` 的 muted space、DND、cross-device read-state fixme 主体。
- [x] 补齐 `kanban/end-to-end.spec.ts` 的 column reorder / child_order cell fixme 主体。
- [x] 补齐 `governance/gdpr-audit-retention.spec.ts` 的 cross-server erasure fan-out fixme 主体。
- [x] 验证: `npx playwright test --config playwright.config.ts --list` 通过,列出 576 条项目测试(Chrome + Chromium,50 个 spec 文件)。

## 完成度反推

| Domain | 当前信号 | 完成度判断 |
|---|---|---|
| account / handle / GDPR basics | handle、export、erase、audit log 多条 live case 已存在 | soland 部分已可用;GDPR retention / cross-server fan-out 未完成 |
| spaces / timeline / edits | 多个 workflow 主体可用,但 seed-member invite 仍是历史失败点 | 基础消息链路 partial;invite projection / admin hydration 是关键阻塞 |
| authz grants | grant / delegate / revoke / audit 有 live tests | capability core partial;policy-server 外挂和 obligation executor 未完成 |
| notifications | mark-all-read live;mute/DND/mention/blind wake/cross-device 仍 fixme | 只有基础 marker 可用;push policy projection 未完成 |
| chat advanced | reactions/replies已有主体;mentions/polls/typing/presence补齐为 fixme | yougen chat sync + content-type UI + soland projection 未完成 |
| kanban | 单用户 board/card/archive 有 live tests | cross-user sync、status FSM、rank/child_order、list/archive cascade 未完成 |
| documents | `/document` route probe live | Document Morph、range comments、presence、versions、restore 未完成 |
| calls | ICE endpoint probe live | WebRTC signaling、Call Morph、SFU、recording policy 未完成 |
| federation / sync | endpoint probes live | dual-soland push/pull、signature、reconciliation、transport negotiation 未完成 |
| identity advanced | dev-login baseline live | consent、passkey/OIDC/email onboarding、device revoke、WebVH、TSP、recovery 未完成 |
| encryption | endpoint/surface probes live | MLS welcome/epoch,backup restore,encrypted attachments,audited E2EE 未完成 |
| extensions | mock selftests exist | applet bridge、MIMI facade、ghost actor accountability 未完成 |

## P0 - 先解除当前 live/workflow 阻塞

- [x] GAP-P0-001 `[soland]` 修复 seed-member invite 投射:由 `cx.member.state{membership:"invite"}` 写入的邀请必须出现在 `GET /api/v1/authz/invites`,让 `acceptInvite()` 在 workflows / notifications / kanban project simulation 中可用。
  - 2026-05-25 local close: `soland` event projection persists pending `SpaceInviteRecord` for `cx.member.state{membership:"invite"}` and `GET /api/v1/authz/invites` surfaces it to the invitee. Evidence: `cargo test --locked --test http_api seed_member_invite_event_surfaces_via_authz_invites -- --nocapture` passed.
- [x] GAP-P0-002 `[yougen]` 修复 `/space/:id/admin/members` hydration race: fresh navigation 后必须稳定渲染 `member-row`、`invite-member`、`refresh-members-button`。
  - 2026-05-25 local close: `soland /account/subscribe` now publishes Realm members in sync projections, `yougen` hydrates the Members admin table from top-level/summary projection members on direct section entry, and the regression probe asserts `invite-member`, `refresh-members-button`, and `member-row`. Evidence: `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p0-002-admin-route-hydration-rerun -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "space-admin-active-section reflects route" -SkipNpmInstall -SkipBrowserInstall` passed.
- [x] GAP-P0-003 `[soland]` 落实 `history_visibility=joined/shared/world_readable` 读侧过滤,让 late joiner、world readable、redaction tests 不互相污染。
  - 2026-05-25 local close: joined/shared filtering is covered in `soland` sync/events query tests, and cotest verifies joined late-join filtering, shared backfill, world_readable anonymous/non-member reads, incompatible encrypted world-readable create rejection, and redaction filtering. Evidence: `cargo test --locked --test discussion_sync -- --nocapture` passed; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p0-003-history-visibility -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "history_visibility=joined|world_readable history|redaction filters public timeline" -SkipNpmInstall -SkipBrowserInstall` passed with 10 passed / 1 skipped.
- [x] GAP-P0-004 `[cotest]` 在 joint runner 下提供可靠 soland runtime tracing,避免 seed invite / projection 类问题只能从 HAR 反推。
  - 2026-05-25 local close: `run-joint-e2e.ps1` now writes per-instance `SOLAND_LOG_FILE` traces for alpha/beta and emits `service-traces.md` beside `service-gaps.md`, indexing trace/stdout/stderr/command logs for every managed service.
- [x] GAP-P0-005 `[cotest]` 跑一轮干净 `scripts/run-joint-e2e.ps1 -StartCoauth -StartMocks -RunProfile joint-full` 基线,更新 passed/failed/skipped 与根因表。
  - 2026-05-25 local close: `scripts/run-joint-e2e.ps1 -OutputRoot artifacts\baseline-p0-005-clean -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -SkipNpmInstall -SkipBrowserInstall` passed with 178 passed / 231 skipped / 0 failed. Evidence: `artifacts\baseline-p0-005-clean\runs\20260525-095716\joint-e2e\summary.md`.

## P1 - 消息、通知与协作体验

- [x] GAP-P1-010 `[yougen]` 修复 `/chat/:space_id` 首次加载时 `channel-item` 不 hydrate 的问题,让 chat advanced 主体可激活。
  - 2026-05-25 local close: `yougen` now routes `/chat/:space_id` directly to `ChatPanel` with the default discussion flow selected, and cotest verifies a fresh browser mount renders `chat-panel` plus `channel-item`. Evidence: `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-010-chat-route -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "chat route hydrates the default discussion channel" -SkipNpmInstall -SkipBrowserInstall` passed.
- [x] GAP-P1-011 `[soland]` 实现 reaction OR-Set、reply relation、mention routing projection,并输出可审计的 mention routing hint。
  - 2026-05-25 local close: `soland` sync timeline messages now expose active reaction OR-Set summaries, reply relations, mentions, and top-level auditable `mention_routing_hint`; `target_ref: cx:message:*` reactions are normalized to their source event. Evidence: `cargo test --locked --test discussion_sync chat_projection_exposes_reactions_reply_and_mention_routing -- --nocapture`, `cargo check --locked`, and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-011-chat-projection -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "sync projection exposes active reactions" -SkipNpmInstall -SkipBrowserInstall` passed.
- [x] GAP-P1-012 `[yougen]` 实现 poll composer/result/close UI:`open-poll-composer-button`、`poll-card`、`poll-option`、`poll-close-button`。
  - 2026-05-25 local close: `yougen` enables the poll composer by default, hydrates poll cards from sync/backfill, and renders vote rows plus close state with the expected testids. Evidence: `cargo check --locked --features experimental-agents` and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-012-013-poll -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "poll create" -SkipNpmInstall -SkipBrowserInstall` passed.
- [x] GAP-P1-013 `[soland]` 实现 poll content type reducer:每 actor 单票替换、close 后拒绝新 vote、结果可投影。
  - 2026-05-25 local close: `soland` reduces `cx.content.poll`, `cx.content.poll.response`, and `cx.content.poll.close` carried by `cx.message.create`; sync timeline projection includes poll result rows, and closed polls reject later votes with `poll_closed`. Evidence: `cargo test --locked --test discussion_sync poll_content_projection_replaces_votes_and_rejects_after_close -- --nocapture`, `cargo check --locked`, and the same joint poll e2e passed.
- [x] GAP-P1-014 `[soland/yougen]` 实现 `cx.typing` ephemeral 与 presence online/offline TTL,满足 1s propagation / 5s clear。
  - 2026-05-25 local close: `yougen` chat now polls live `cx.typing` ephemeral state and profile presence, renders display-name typing indicators, and opens the users/presence panel by default; `soland` projects stale online presence as offline with `last_seen`. Evidence: `cargo test --locked --test http_api push_profile_and_moderation_contracts_work -- --nocapture`, `cargo check --locked`, `cargo check --locked --features experimental-agents`, and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-014-typing-presence -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "typing indicator|presence state" -SkipNpmInstall -SkipBrowserInstall` passed.
- [x] GAP-P1-015 `[soland/yougen]` 实现 notification preferences:per-space mute、DND、priority override、mention override、cross-device read marker sync。
  - 2026-05-25 local close: `soland` now derives notification rows from message projection with mention-only routing, priority override metadata, and actor-level read cursor state; `yougen` reads `/api/v1/notifications`, calls server mark-all-read, syncs `cx.push_rules`/`cx.dnd_schedule`, and exposes `/notifications/settings`. Evidence: `cargo check --locked`, `cargo check --locked --features experimental-agents`, and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-015-notifications-rerun -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "muting a space|Do-not-disturb|cross-device read state|mentions route notifications" -SkipNpmInstall -SkipBrowserInstall` passed with 4 passed.
- [x] GAP-P1-016 `[soland]` E2EE notification blind wake:server 只发送 envelope metadata / sidecar hash,不泄露 mentionee DID 或 plaintext。
  - 2026-05-25 local close: encrypted message notifications now render as body-free `blind_wakeup` metadata with `privacy_mode`, `wakeup_kind`, `sender_did`, `event_id`, timestamp, and optional `mention_sidecar_hash`; sidecar hashes route E2EE mentions without exposing mentionee DID or plaintext. Evidence: `cargo check --locked` and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-016-e2ee-sidecar -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "E2EE space with evaluation_locus=client|E14.2 mention in E2EE" -SkipNpmInstall -SkipBrowserInstall` passed with 2 passed.

## P1 - Consent 与 identity lifecycle

- [x] GAP-P1-020 `[soland]` 实现 `cx.consent.grant` / `cx.consent.revoke` reducer 与 consent cell projection。
  - 2026-05-25 local close: `soland` now projects accepted `cx.consent.grant` / `cx.consent.revoke` events into holder-private consent cells, preserves canonical `cx:cell:cx.component.consent.grant.v1:<consent_id>` ids, accepts schema `observed_dots`, and keeps contact status in sync. Evidence: `cargo test --locked --test consent_cells -- --nocapture`, `cargo check --locked`, and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-020-consent-events -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "cx.consent.grant event projects consent cell" -SkipNpmInstall -SkipBrowserInstall` passed.
- [x] GAP-P1-021 `[soland]` contact request gate 接入 consent state:无 grant 进入 pending,有 grant 直接 accepted,revoke 对后续请求立即生效。
  - 2026-05-25 local close: contact requests now read the consent cell projection for scoped grant state, create pending cells when no active grant exists, accept immediately after a matching grant, and return to pending after revoke. Evidence: `cargo test --locked --test consent_cells -- --nocapture` covers REST grant/revoke/regrant plus event projection, and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-020-consent-events -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "cx.consent.grant event projects consent cell" -SkipNpmInstall -SkipBrowserInstall` passed.
- [x] GAP-P1-022 `[yougen]` 实现 `/contacts/new` consent-aware 流程:testids `contact-request-panel`、`contact-scope-select`、`contact-request-status`。
  - 2026-05-25 local close: `/contacts/new` now mounts the consent-aware request panel with scoped request submission and visible pending status. Evidence: `cargo check --locked --features experimental-agents` in `yougen`, and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-022-023-consent-ui -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "contacts new page submits scoped consent request|consent settings grants and revokes a pending request" -SkipNpmInstall -SkipBrowserInstall` passed with 2 tests.
- [x] GAP-P1-023 `[yougen]` 实现 `/settings/consent`:pending/granted rows、detail、grant/revoke buttons、valid_until 输入。
  - 2026-05-25 local close: `/settings/consent` now loads live consent cells, displays pending and granted rows, opens pending detail, accepts scope and `valid_until`, and performs grant/revoke against `soland`. Evidence: `cargo check --locked --features experimental-agents` in `yougen`, and the same joint e2e command passed the live settings grant/revoke lifecycle.
- [x] GAP-P1-024 `[soland]` 支持 consent time window、scope 粒度、pairwise DID key,覆盖 E1.1-E1.4。
  - 2026-05-25 local close: consent cells now evaluate `valid_until`, keep grants scoped by `(holder, peer, scope)`, and isolate pairwise DIDs from root DIDs. Evidence: `cargo test --locked --test consent_cells -- --nocapture` in `soland`, and `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-024-consent-edge-cases -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "E1\.1 time-windowed consent expires|E1\.2 revoke then re-grant|E1\.3 scope-granularity|E1\.4 pairwise DID consent" -SkipNpmInstall -SkipBrowserInstall` passed with 4 tests.
- [x] GAP-P1-025 `[coauth/yougen]` 完成 passkey/OIDC/email onboarding 与真实 device authorization,替代 dev-login baseline。
  - 2026-05-25 local close: cotest joint coauth config now enables local WebVH/email registration and publishes the coauth auth server URL through soland; coauth exposes CORS/preflight for browser auth bridge calls; yougen starts sign-in through coauth's browser-bridge session endpoint and uses the principal server DID as the OAuth resource audience. Evidence: `cargo check --locked --features experimental-agents` in `yougen`; `cargo build --locked -p coauth --features cedar`; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-025-onboarding-bridge-final -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "coauth exposes OIDC/passkey bridge metadata|yougen starts the coauth OIDC bridge" -SkipNpmInstall -SkipBrowserInstall` passed with 2 tests; `cargo test --locked --test bridge_contracts session_grant_exchange_uses_configured_coauth_introspection -- --nocapture` passed.
- [x] GAP-P1-026 `[soland]` 完成 account state machine:locked/suspended/deactivated/erased 对 session、directory、audit 的一致效果。
  - 2026-05-25 local close: `soland` now projects account lifecycle state in-process, exposes `state` on `/account/me`, mounts canonical `/api/v1/admin/accounts/*` state actions, blocks new sessions for locked/suspended/deactivated/erased principals, revokes sessions/devices for lock/deactivate/erase, hides terminal directory rows, and emits `cx.account.state_change` audit entries. Evidence: `cargo check --locked` in `soland`; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-026-account-states-rerun -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "account states" -SkipNpmInstall -SkipBrowserInstall` passed with 7 passed / 1 skipped.

## P1 - Kanban / workflow / incident response

- [x] GAP-P1-030 `[yougen]` 稳定 column drag/drop handles:`column-drag-handle`、`column-drop-target-before`、`kanban-column-title`。
  - 2026-05-25 local close: `yougen` now renders stable column drag handles, before-column drop targets, and column-title testids; column drag/drop reorders visible columns locally. Evidence: `cargo check --locked --features experimental-agents` in `yougen`; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-030-kanban-column-handles -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "column drag handles" -SkipNpmInstall -SkipBrowserInstall` passed with 1 test.
- [x] GAP-P1-031 `[soland]` 暴露并维护 `cx.component.child_order.v1`,drag reorder 后与 UI 顺序一致。
  - 2026-05-25 local close: `soland` exposes `GET /api/v1/spaces/{boardId}/cells/cx.component.child_order.v1` from the Space-container projection, sorted by active child rank; `yougen` submits `cx.space.update` rank patches after column drag/drop; cotest promotes the child_order fixture to a live test against a real Board Space. Evidence: `cargo check --locked` in `soland`; `cargo check --locked --features experimental-agents` in `yougen`; `cargo test --lib --locked space_container_child_order_tracks_rank_updates -- --nocapture` in `soland`; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-031-child-order -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "reordering lists" -SkipNpmInstall -SkipBrowserInstall` passed with 1 test.
- [x] GAP-P1-032 `[soland]` 实现 card/list/board archive cascade 与 restore rank 保留。
  - 2026-05-25 local close: `soland` now projects kanban card Flow position into a contains relation, cascades list/board archive and restore into contained card Flow lifecycle, and leaves rank fields intact across restore; cotest folds the restored-rank and whole-list archive cases into the live kanban week workflow. Evidence: `cargo check --locked` in `soland`; `cargo test --lib --locked archive_cascades -- --nocapture` in `soland`; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-032-archive-cascade -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "kanban week-in-review" -SkipNpmInstall -SkipBrowserInstall` passed with 1 test.
- [x] GAP-P1-033 `[soland/yougen]` 实现 kanban cross-user sync,Mei/Bob/Carol 看到同一 board。
  - 2026-05-25 local close: `contrix-spec` / `contrix-rust-sdk` now include derived `board_space_id`, `list_space_id`, and `rank` on Flow projection rows; `soland` fills them from the reducer's `contains` relation backed by `cx.component.flow.position.v1`; cotest promotes the sprint cross-user kanban case so Bob and Carol fresh-mount `/kanban/:spaceId` and hydrate Mei's board columns/cards from server projection. Evidence: `python tools\artifact_pipeline.py check` in `contrix-spec`; `cargo check --locked -p contrix-core` in `contrix-rust-sdk`; `cargo check --locked` and `cargo test --locked --test http_api projection_flows_endpoint_reports_lifecycle_state -- --nocapture` in `soland`; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-033-kanban-cross-user -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "E-sprint.crossuser" -SkipNpmInstall -SkipBrowserInstall` passed with 1 test.
- [x] GAP-P1-034 `[soland]` 实现 flow status FSM:拒绝 `todo -> done` / `investigating -> resolved` 等非法跳转。
  - 2026-05-25 local close: `soland` now keeps Flow `fields.status` in projection state and preflights `cx.flow.update` against the core status FSM, rejecting skipped terminal transitions such as `todo -> done` and `investigating -> resolved` with `flow_status_transition_invalid`; cotest promotes the kanban project-simulation FSM case to a live API-level contract test. Evidence: `cargo check --locked`, `cargo test --locked --test http_api flow_update_status_fsm_rejects_skipped_terminal_transitions -- --nocapture`, `cargo test --locked --test http_api flow_morph_lifecycle_state_machine_returns_412_for_illegal_transitions -- --nocapture` in `soland`; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-034-flow-status-fsm -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "status FSM: Card transitions" -SkipNpmInstall -SkipBrowserInstall` passed with 1 test.
- [x] GAP-P1-035 `[yougen]` 事故响应 UI:incident priority/status controls、postmortem link controls、sanitized public update guard。
  - 2026-05-25 local close: `yougen` now exposes incident status controls on Kanban, SEV priority + public-update guard controls on Timeline, and postmortem title/body/incident-link controls on Document; cotest promotes the incident status, priority/guard, and postmortem edge cases to live joint UI tests. Evidence: `cargo check --locked --features experimental-agents` in `yougen`; `cargo test --locked --features experimental-agents message_create_operation_retags_space_scope_to_flow_id`; `cargo test --locked --features experimental-agents document_body_payload_carries_schema_version_and_blocks`; `cargo test --locked --features experimental-agents incident_status_update_uses_schema_safe_fields_patch`; `scripts\run-joint-e2e.ps1 -OutputRoot artifacts\verify-p1-035-036-incident-response -StartCoauth -StartMocks -RunProfile joint-full -PlaywrightProject chrome -Grep "E-incident" -SkipNpmInstall -SkipBrowserInstall` passed with 3 tests.
- [x] GAP-P1-036 `[soland]` 事故状态 audit:`incident.status.transition` 必须含 actor、from/to、timestamp、space/incident id。
  - 2026-05-25 local close: `soland` now appends `incident.status.transition` audit rows for accepted Flow `fields.status` transitions, carrying actor, from/to, timestamp, space_id, flow_id, and incident_id; cotest verifies those fields through `/api/v1/audit/events` after the live yougen status flow. Evidence: `cargo check --locked`, `cargo test --locked --test http_api flow_update_status_fsm_rejects_skipped_terminal_transitions -- --nocapture`, and `cargo test --locked --test http_api flow_morph_lifecycle_state_machine_returns_412_for_illegal_transitions -- --nocapture` in `soland`; same joint `E-incident` run passed with 3 tests.

## P2 - 文档、附件、加密与恢复

- [ ] GAP-P2-040 `[soland]` 实现 Document Morph:create/update/version/relation/range comment/orphan comment projection。
- [ ] GAP-P2-041 `[yougen]` 实现 `/document/new`、`/document/:id`、版本列表、range comment、cursor presence UI。
- [ ] GAP-P2-042 `[soland/yougen]` 实现 MLS space genesis、KeyPackage claim、Welcome、epoch update、ban/remove 与 `epoch_update_required`。
- [ ] GAP-P2-043 `[soland/yougen]` 实现 key backup:Argon2id + XChaCha20 envelope、restore、wrong passphrase no-oracle、DELETE ownership proof。
- [ ] GAP-P2-044 `[soland/yougen]` 实现 encrypted attachment ciphertext-only metadata、opaque non-member error、client thumbnail encryption。
- [ ] GAP-P2-045 `[mock-audit-agent/soland]` 完成 audited E2EE franking、audit-agent invite、`cx.audit.accessed`、tamper verification。

## P2 - Federation / sync / sovereign

- [x] GAP-P2-050 `[cotest]` DualSoland profile 稳定启动 alpha/beta yougen + soland,并注入 `COTEST_SOLAND_ALPHA/BETA_*`。
  - 2026-05-25 local close: `run-cotest.ps1 -Profile dual-soland` starts the dual topology locally; when the harness owns web startup, `run-joint-e2e.ps1 -DualSoland` starts `yougen-alpha` and `yougen-beta` and exports both `COTEST_SOLAND_ALPHA/BETA_*` and `COTEST_YOUGEN_ALPHA/BETA_BASE_URL`.
- [ ] GAP-P2-051 `[soland]` 实现 α→β federation push 自动投递 invite/message,并保持 idempotent replay。
- [ ] GAP-P2-052 `[soland]` 实现 pull/backfill 与 frontier convergence,网络分区恢复后补齐 missing events。
- [ ] GAP-P2-053 `[soland]` 实现 RFC 9421 signature、key rotation hint、relay outer/inner signature verification。
- [ ] GAP-P2-054 `[soland]` 实现 cross-server erasure fan-out:远端事件 tombstone 为 `[user erased]`,保留 anchored receipt。
- [ ] GAP-P2-055 `[soland/yougen]` 实现 offline outbox、soft_failed -> accepted/rejected reconcile、bottom_cells repair。
- [ ] GAP-P2-056 `[soland]` 实现 sovereign/enclave trust chain、store-and-forward、escape attempt rejection。

## P2 - Governance / moderation / organization

- [ ] GAP-P2-060 `[soland]` 实现 retention_policy TTL tombstone,anchored events 不物理删除。
- [ ] GAP-P2-061 `[soland/yougen]` 实现 personal blocklist UI + server filter + unblock restore + federation block hint。
- [ ] GAP-P2-062 `[soland]` moderation report privacy:reporter/owner 可见,被举报人和普通成员不可见。
- [ ] GAP-P2-063 `[soland/yougen]` ban via `cx.member.state` Move:owner can ban,non-moderator denied,idempotent ban no duplicate。
- [ ] GAP-P2-064 `[soland]` organization policy inheritance:org policy fans out to member spaces,space override 需要 org approval。
- [ ] GAP-P2-065 `[yougen]` organization directory tab 显示 verified badge、member count、policy inheritance hints。

## P3 - Calls / extensions / external profiles

- [ ] GAP-P3-070 `[soland/yougen]` WebRTC Call Morph state machine:ringing/connecting/active/ended,signaling frames routed to peers。
- [ ] GAP-P3-071 `[soland]` ICE/TURN credential auth、pairwise pseudonym、mid-call refresh、recording policy enforcement。
- [ ] GAP-P3-072 `[yougen]` call UI:mute、screen share、hangup、recording indicator、group/SFU roster。
- [ ] GAP-P3-073 `[soland]` applet manifest verifier、bot/ghost DID provisioning、portal realm routing、capability revoke。
- [x] GAP-P3-074 `[cotest]` MIMI facade mock/helper,覆盖 bob_mimi join、fallback/deferred、content-kind quarantine。
  - 2026-05-25 local close: added `e2e/mocks/mock-mimi-facade.mjs`, `e2e/helpers/mimi-facade.ts`, runner wiring via `-StartMockMimiFacade` / `-StartMocks`, and harness selftest coverage for bob_mimi join, realm-scoped pairwise DID, deferred outbound, accepted inbound, and unknown content quarantine.
- [ ] GAP-P3-075 `[soland]` MIMI bridge policy:E2EE downgrade 必须显式标记或 transcript-binding,不得静默明文泄露。

## P3 - cotest maintenance

- [x] GAP-P3-080 `[cotest]` 把新增 `workflows/incident-response` 登记到 scenario catalog,同时修正 catalog/README 的 scenario/test 计数。
  - 2026-05-25 local refresh: refreshed `e2e/scenarios/catalog.md` from `summarize-e2e-coverage.mjs` and updated `e2e/scenarios/README.md` to 66 scenarios / 66 specs / 201 verified / 404 promised / 203 fixme / 19 skip across 19 domains.
- [x] GAP-P3-081 `[cotest]` 为 `test.fixme` 增加静态检查:每条必须含 spec ref、owner gap、可执行主体或明确 blocked reason。
  - 2026-05-25 local close: `e2e/scripts/fixme-debt-report.mjs --strict` now validates owner-gap shape, scenario doc existence, and executable body or `@blocked-reason`; `scripts/run-hygiene.ps1` runs it by default.
- [x] GAP-P3-082 `[cotest]` 增加 fixme promotion checklist:删除 `.fixme` 前必须有对应 soland/yougen feature id、一次单 spec 通过、一条回归截图或 HAR。
  - 2026-05-25 local close: added `docs/fixme-promotion-checklist.md`; `scripts/promote-fixme.ps1` refuses non-dry-run promotion without `-FeatureId`, `-PassedSpecCommand`, and `-EvidencePath`.
- [x] GAP-P3-083 `[cotest]` 将 `_cotest_gap_todos.md` 与 runner summary 互链,让每次 run 的 skipped/fixme 统计能指回具体 gap task。
  - 2026-05-25 local close: joint runner summaries now include `gap_todos` and `fixme_promotion_checklist`, while `scenarios.md` emits owner gaps beside each static fixme count.
