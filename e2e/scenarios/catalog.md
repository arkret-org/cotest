# Scenario Catalog

完整的 e2e scenario 蓝图,按 spec 自己的领域划分(`identity/`、`encryption/`、`messaging/`、`spaces/`、`kanban/`、`documents/`、`calls/`、`federation/`、`authz/`、`discovery/`、`governance/`、`sync/`、`invites/`、`models/`、`extensions/`、`conformance/`、`workflows/`),不用 `S#` 顺序号。

**57 条 scenarios,57 个 playwright spec 文件,83 live test / 248 fixme / 15 条件 skip。**

> 数字来源:由 [`scripts/summarize-e2e-coverage.mjs`](../scripts/summarize-e2e-coverage.mjs) 直接从文件树重算。手工 `grep` 等价命令:scenario doc = `find scenarios -name '*.md' -not -name 'catalog.md' -not -name 'README.md'`;spec 文件 = `find tests -name '*.spec.ts'`;live = `grep -rE '^[[:space:]]*test\(' tests/**/*.spec.ts`;fixme = `grep -rE '^[[:space:]]*test\.fixme\(' tests/**/*.spec.ts`;条件 skip = `grep -rE 'test\.skip\(' tests/**/*.spec.ts`(出现在 live test 体内 / describe 头部:mock 未启动 / DualSoland 拓扑 / transport 实现状态 / claim_kind 缺失等运行时判断)。

## scenario / spec 对齐状态

- **55 条业务 scenario 与 spec 一一对应**(`scenarios/<domain>/<name>.md` ↔ `tests/<domain>/<name>.spec.ts`)
- **2 条 spec 用 harness/probe 风格的 doc 补**:
  - `tests/harness/mocks-selftest.spec.ts` ↔ [`harness/mocks-selftest.md`](harness/mocks-selftest.md) (harness 自检)
  - `tests/spaces/admin-section-route.spec.ts` ↔ [`spaces/admin-section-route.md`](spaces/admin-section-route.md) (yougen routing probe)
- Wave A (G1.T1–T7) 新增 7 条 conformance/sync/models/extensions 域 scenario,全部已附带 spec(参见下面三类分布)

## 三类 spec 分布概览

按 (live, fixme) 把 57 个 spec 分三桶,一眼判断当前回归保护强度。

### Live-only specs(live > 0 且 fixme == 0,共 5 个)

主线全绿,可直接当回归保护层。

- [tests/authz/capability-chain.spec.ts](../tests/authz/capability-chain.spec.ts) — 7 live
- [tests/harness/mocks-selftest.spec.ts](../tests/harness/mocks-selftest.spec.ts) — 8 live(全部 `test.skip` 在 mock 未启动时跳过;见 [harness/mocks-selftest.md](harness/mocks-selftest.md))
- [tests/identity/handle.spec.ts](../tests/identity/handle.spec.ts) — 7 live
- [tests/spaces/admin-section-route.spec.ts](../tests/spaces/admin-section-route.spec.ts) — 1 live(诊断 probe;见 [spaces/admin-section-route.md](spaces/admin-section-route.md))
- [tests/spaces/history-world-readable.spec.ts](../tests/spaces/history-world-readable.spec.ts) — 4 live

### Mixed specs(live > 0 且 fixme > 0,共 36 个)

主线已经有 live probe / happy-path,但 spec 闭环未完成。把对应的 `test.fixme` 改成 `test` 即可激活。

| spec | live | fixme |
|---|---:|---:|
| [calls/webrtc.spec.ts](../tests/calls/webrtc.spec.ts) | 1 | 8 |
| [conformance/encoding-vectors.spec.ts](../tests/conformance/encoding-vectors.spec.ts) | 1 | 7 |
| [conformance/profile-gates.spec.ts](../tests/conformance/profile-gates.spec.ts) | 3 | 3 |
| [conformance/registry-drift.spec.ts](../tests/conformance/registry-drift.spec.ts) | 3 | 3 |
| [conformance/snapshot-query-scalability.spec.ts](../tests/conformance/snapshot-query-scalability.spec.ts) | 2 | 5 |
| [discovery/directory.spec.ts](../tests/discovery/directory.spec.ts) | 4 | 1 |
| [discovery/notifications.spec.ts](../tests/discovery/notifications.spec.ts) | 2 | 4 |
| [documents/collaboration.spec.ts](../tests/documents/collaboration.spec.ts) | 1 | 7 |
| [encryption/audited-e2ee.spec.ts](../tests/encryption/audited-e2ee.spec.ts) | 1 | 5 |
| [encryption/encrypted-attachments.spec.ts](../tests/encryption/encrypted-attachments.spec.ts) | 1 | 6 |
| [encryption/key-backup.spec.ts](../tests/encryption/key-backup.spec.ts) | 1 | 7 |
| [encryption/mls-group.spec.ts](../tests/encryption/mls-group.spec.ts) | 1 | 7 |
| [extensions/agent-protocol-interop.spec.ts](../tests/extensions/agent-protocol-interop.spec.ts) | 1 | 5 |
| [federation/cross-server.spec.ts](../tests/federation/cross-server.spec.ts) | 3 | 6 |
| [governance/gdpr-audit-retention.spec.ts](../tests/governance/gdpr-audit-retention.spec.ts) | 5 | 2 |
| [governance/organization-policy.spec.ts](../tests/governance/organization-policy.spec.ts) | 1 | 6 |
| [governance/personal-blocklist.spec.ts](../tests/governance/personal-blocklist.spec.ts) | 1 | 4 |
| [identity/account-device-auth.spec.ts](../tests/identity/account-device-auth.spec.ts) | 2 | 4 |
| [identity/account-states.spec.ts](../tests/identity/account-states.spec.ts) | 1 | 6 |
| [identity/multi-device.spec.ts](../tests/identity/multi-device.spec.ts) | 2 | 6 |
| [identity/onboarding.spec.ts](../tests/identity/onboarding.spec.ts) | 1 | 7 |
| [identity/recovery.spec.ts](../tests/identity/recovery.spec.ts) | 1 | 7 |
| [invites/third-party.spec.ts](../tests/invites/third-party.spec.ts) | 1 | 6 |
| [kanban/end-to-end.spec.ts](../tests/kanban/end-to-end.spec.ts) | 1 | 4 |
| [kanban/project-simulation.spec.ts](../tests/kanban/project-simulation.spec.ts) | 1 | 6 |
| [models/core-object-invariants.spec.ts](../tests/models/core-object-invariants.spec.ts) | 1 | 4 |
| [models/morph-schema-migration.spec.ts](../tests/models/morph-schema-migration.spec.ts) | 2 | 4 |
| [models/private-read-cursor.spec.ts](../tests/models/private-read-cursor.spec.ts) | 1 | 4 |
| [spaces/knock-application.spec.ts](../tests/spaces/knock-application.spec.ts) | 1 | 7 |
| [sync/service-surface-contract.spec.ts](../tests/sync/service-surface-contract.spec.ts) | 2 | 5 |
| [sync/transport-negotiation.spec.ts](../tests/sync/transport-negotiation.spec.ts) | 2 | 4 |
| [workflows/daily-standup.spec.ts](../tests/workflows/daily-standup.spec.ts) | 1 | 2 |
| [workflows/kanban-week.spec.ts](../tests/workflows/kanban-week.spec.ts) | 1 | 2 |
| [workflows/sprint-planning.spec.ts](../tests/workflows/sprint-planning.spec.ts) | 1 | 3 |
| [workflows/support-escalation.spec.ts](../tests/workflows/support-escalation.spec.ts) | 1 | 2 |
| [workflows/team-onboarding.spec.ts](../tests/workflows/team-onboarding.spec.ts) | 1 | 2 |

### 全 fixme specs(live == 0 且 fixme > 0,共 16 个)

完全停在 contract 形状阶段、等业务实现落地的 spec。最高优先级的 e2e 完善对象。

| spec | fixme |
|---|---:|
| [authz/policy-server-check.spec.ts](../tests/authz/policy-server-check.spec.ts) | 4 |
| [extensions/applet-bridge.spec.ts](../tests/extensions/applet-bridge.spec.ts) | 4 |
| [extensions/mimi-federation.spec.ts](../tests/extensions/mimi-federation.spec.ts) | 4 |
| [identity/consent-grant.spec.ts](../tests/identity/consent-grant.spec.ts) | 5 |
| [identity/tsp-bootstrap.spec.ts](../tests/identity/tsp-bootstrap.spec.ts) | 4 |
| [identity/webvh-rotation.spec.ts](../tests/identity/webvh-rotation.spec.ts) | 8 |
| [messaging/chat-advanced.spec.ts](../tests/messaging/chat-advanced.spec.ts) | 6 |
| [messaging/discussion-upgrade.spec.ts](../tests/messaging/discussion-upgrade.spec.ts) | 7 |
| [messaging/read-receipts.spec.ts](../tests/messaging/read-receipts.spec.ts) | 8 |
| [messaging/triad-collaboration.spec.ts](../tests/messaging/triad-collaboration.spec.ts) | 3 |
| [models/realm-links.spec.ts](../tests/models/realm-links.spec.ts) | 4 |
| [spaces/knock-auto-resolve.spec.ts](../tests/spaces/knock-auto-resolve.spec.ts) | 5 |
| [spaces/moderation-ban.spec.ts](../tests/spaces/moderation-ban.spec.ts) | 2 |
| [sync/offline-conflict.spec.ts](../tests/sync/offline-conflict.spec.ts) | 5 |
| [sync/sovereign-deployment.spec.ts](../tests/sync/sovereign-deployment.spec.ts) | 4 |
| [workflows/incident-response.spec.ts](../tests/workflows/incident-response.spec.ts) | 4 |

合计:5 + 36 + 16 = 57 个 spec 文件。83 live + 248 fixme = 331 个 `test()` / `test.fixme()` 调用。

## 按领域分组(scenario doc × spec)

### identity / 身份与设备

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [account-device-auth](identity/account-device-auth.md) | [identity/account-device-auth.spec.ts](../tests/identity/account-device-auth.spec.ts) | 2 | 4 |
| [account-states](identity/account-states.md) | [identity/account-states.spec.ts](../tests/identity/account-states.spec.ts) | 1 | 6 |
| [consent-grant](identity/consent-grant.md) | [identity/consent-grant.spec.ts](../tests/identity/consent-grant.spec.ts) | 0 | 5 |
| [handle](identity/handle.md) | [identity/handle.spec.ts](../tests/identity/handle.spec.ts) | 7 | 0 |
| [multi-device](identity/multi-device.md) | [identity/multi-device.spec.ts](../tests/identity/multi-device.spec.ts) | 2 | 6 |
| [onboarding](identity/onboarding.md) | [identity/onboarding.spec.ts](../tests/identity/onboarding.spec.ts) | 1 | 7 |
| [recovery](identity/recovery.md) | [identity/recovery.spec.ts](../tests/identity/recovery.spec.ts) | 1 | 7 |
| [tsp-bootstrap](identity/tsp-bootstrap.md) | [identity/tsp-bootstrap.spec.ts](../tests/identity/tsp-bootstrap.spec.ts) | 0 | 4 |
| [webvh-rotation](identity/webvh-rotation.md) | [identity/webvh-rotation.spec.ts](../tests/identity/webvh-rotation.spec.ts) | 0 | 8 |

### encryption / 端到端加密

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [audited-e2ee](encryption/audited-e2ee.md) | [encryption/audited-e2ee.spec.ts](../tests/encryption/audited-e2ee.spec.ts) | 1 | 5 |
| [encrypted-attachments](encryption/encrypted-attachments.md) | [encryption/encrypted-attachments.spec.ts](../tests/encryption/encrypted-attachments.spec.ts) | 1 | 6 |
| [key-backup](encryption/key-backup.md) | [encryption/key-backup.spec.ts](../tests/encryption/key-backup.spec.ts) | 1 | 7 |
| [mls-group](encryption/mls-group.md) | [encryption/mls-group.spec.ts](../tests/encryption/mls-group.spec.ts) | 1 | 7 |

### messaging / 消息与 chat

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [chat-advanced](messaging/chat-advanced.md) | [messaging/chat-advanced.spec.ts](../tests/messaging/chat-advanced.spec.ts) | 0 | 6 |
| [discussion-upgrade](messaging/discussion-upgrade.md) | [messaging/discussion-upgrade.spec.ts](../tests/messaging/discussion-upgrade.spec.ts) | 0 | 7 |
| [read-receipts](messaging/read-receipts.md) | [messaging/read-receipts.spec.ts](../tests/messaging/read-receipts.spec.ts) | 0 | 8 |
| [triad-collaboration](messaging/triad-collaboration.md) | [messaging/triad-collaboration.spec.ts](../tests/messaging/triad-collaboration.spec.ts) | 0 | 3 |

### spaces / 空间与成员关系

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [history-world-readable](spaces/history-world-readable.md) | [spaces/history-world-readable.spec.ts](../tests/spaces/history-world-readable.spec.ts) | 4 | 0 |
| [knock-application](spaces/knock-application.md) | [spaces/knock-application.spec.ts](../tests/spaces/knock-application.spec.ts) | 1 | 7 |
| [knock-auto-resolve](spaces/knock-auto-resolve.md) | [spaces/knock-auto-resolve.spec.ts](../tests/spaces/knock-auto-resolve.spec.ts) | 0 | 5 |
| [moderation-ban](spaces/moderation-ban.md) | [spaces/moderation-ban.spec.ts](../tests/spaces/moderation-ban.spec.ts) | 0 | 2 |
| [admin-section-route](spaces/admin-section-route.md) (诊断 probe) | [spaces/admin-section-route.spec.ts](../tests/spaces/admin-section-route.spec.ts) | 1 | 0 |

### kanban / 看板

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [end-to-end](kanban/end-to-end.md) | [kanban/end-to-end.spec.ts](../tests/kanban/end-to-end.spec.ts) | 1 | 4 |
| [project-simulation](kanban/project-simulation.md) | [kanban/project-simulation.spec.ts](../tests/kanban/project-simulation.spec.ts) | 1 | 6 |

### documents / 文档协作

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [collaboration](documents/collaboration.md) | [documents/collaboration.spec.ts](../tests/documents/collaboration.spec.ts) | 1 | 7 |

### calls / 通话

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [webrtc](calls/webrtc.md) | [calls/webrtc.spec.ts](../tests/calls/webrtc.spec.ts) | 1 | 8 |

### federation / 跨服务器

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [cross-server](federation/cross-server.md) | [federation/cross-server.spec.ts](../tests/federation/cross-server.spec.ts) | 3 | 6 |

`federation/cross-server.spec.ts` 内含 1 条 `test.skip(...)`(条件:仅在 `hasDualSoland()` 拓扑下跑跨服务器 push fanout)。

### authz / 权能授权

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [capability-chain](authz/capability-chain.md) | [authz/capability-chain.spec.ts](../tests/authz/capability-chain.spec.ts) | 7 | 0 |
| [policy-server-check](authz/policy-server-check.md) | [authz/policy-server-check.spec.ts](../tests/authz/policy-server-check.spec.ts) | 0 | 4 |

### discovery / 搜索与通知

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [directory](discovery/directory.md) | [discovery/directory.spec.ts](../tests/discovery/directory.spec.ts) | 4 | 1 |
| [notifications](discovery/notifications.md) | [discovery/notifications.spec.ts](../tests/discovery/notifications.spec.ts) | 2 | 4 |

### governance / 治理与合规

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [gdpr-audit-retention](governance/gdpr-audit-retention.md) | [governance/gdpr-audit-retention.spec.ts](../tests/governance/gdpr-audit-retention.spec.ts) | 5 | 2 |
| [organization-policy](governance/organization-policy.md) | [governance/organization-policy.spec.ts](../tests/governance/organization-policy.spec.ts) | 1 | 6 |
| [personal-blocklist](governance/personal-blocklist.md) | [governance/personal-blocklist.spec.ts](../tests/governance/personal-blocklist.spec.ts) | 1 | 4 |

`governance/gdpr-audit-retention.spec.ts` 内含 1 条 `test.skip(...)`(条件:仅在 DualSoland 拓扑下跑跨服务器 erase)。

### sync / 同步与冲突

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [offline-conflict](sync/offline-conflict.md) | [sync/offline-conflict.spec.ts](../tests/sync/offline-conflict.spec.ts) | 0 | 5 |
| [service-surface-contract](sync/service-surface-contract.md) | [sync/service-surface-contract.spec.ts](../tests/sync/service-surface-contract.spec.ts) | 2 | 5 |
| [sovereign-deployment](sync/sovereign-deployment.md) | [sync/sovereign-deployment.spec.ts](../tests/sync/sovereign-deployment.spec.ts) | 0 | 4 |
| [transport-negotiation](sync/transport-negotiation.md) | [sync/transport-negotiation.spec.ts](../tests/sync/transport-negotiation.spec.ts) | 2 | 4 |

`sync/transport-negotiation.spec.ts` 内含 1 条 `test.skip(...)`(条件:依赖 transport 实现状态)。

### invites / 邀请扩展

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [third-party](invites/third-party.md) | [invites/third-party.spec.ts](../tests/invites/third-party.spec.ts) | 1 | 6 |

### models / 公共数据模型

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [core-object-invariants](models/core-object-invariants.md) | [models/core-object-invariants.spec.ts](../tests/models/core-object-invariants.spec.ts) | 1 | 4 |
| [morph-schema-migration](models/morph-schema-migration.md) | [models/morph-schema-migration.spec.ts](../tests/models/morph-schema-migration.spec.ts) | 2 | 4 |
| [private-read-cursor](models/private-read-cursor.md) | [models/private-read-cursor.spec.ts](../tests/models/private-read-cursor.spec.ts) | 1 | 4 |
| [realm-links](models/realm-links.md) | [models/realm-links.spec.ts](../tests/models/realm-links.spec.ts) | 0 | 4 |

### extensions / 扩展与桥接

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [agent-protocol-interop](extensions/agent-protocol-interop.md) | [extensions/agent-protocol-interop.spec.ts](../tests/extensions/agent-protocol-interop.spec.ts) | 1 | 5 |
| [applet-bridge](extensions/applet-bridge.md) | [extensions/applet-bridge.spec.ts](../tests/extensions/applet-bridge.spec.ts) | 0 | 4 |
| [mimi-federation](extensions/mimi-federation.md) | [extensions/mimi-federation.spec.ts](../tests/extensions/mimi-federation.spec.ts) | 0 | 4 |

### conformance / 协议一致性

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [encoding-vectors](conformance/encoding-vectors.md) | [conformance/encoding-vectors.spec.ts](../tests/conformance/encoding-vectors.spec.ts) | 1 | 7 |
| [profile-gates](conformance/profile-gates.md) | [conformance/profile-gates.spec.ts](../tests/conformance/profile-gates.spec.ts) | 3 | 3 |
| [registry-drift](conformance/registry-drift.md) | [conformance/registry-drift.spec.ts](../tests/conformance/registry-drift.spec.ts) | 3 | 3 |
| [snapshot-query-scalability](conformance/snapshot-query-scalability.md) | [conformance/snapshot-query-scalability.spec.ts](../tests/conformance/snapshot-query-scalability.spec.ts) | 2 | 5 |

### workflows / 产品级组合流

| Scenario | spec 文件 | live | fixme |
|---|---|---:|---:|
| [daily-standup](workflows/daily-standup.md) | [workflows/daily-standup.spec.ts](../tests/workflows/daily-standup.spec.ts) | 1 | 2 |
| [incident-response](workflows/incident-response.md) | [workflows/incident-response.spec.ts](../tests/workflows/incident-response.spec.ts) | 0 | 4 |
| [kanban-week](workflows/kanban-week.md) | [workflows/kanban-week.spec.ts](../tests/workflows/kanban-week.spec.ts) | 1 | 2 |
| [sprint-planning](workflows/sprint-planning.md) | [workflows/sprint-planning.spec.ts](../tests/workflows/sprint-planning.spec.ts) | 1 | 3 |
| [support-escalation](workflows/support-escalation.md) | [workflows/support-escalation.spec.ts](../tests/workflows/support-escalation.spec.ts) | 1 | 2 |
| [team-onboarding](workflows/team-onboarding.md) | [workflows/team-onboarding.spec.ts](../tests/workflows/team-onboarding.spec.ts) | 1 | 2 |

### 无业务 scenario 的特殊 spec(harness / probe)

这两条 spec 不验证业务流程,只验证 harness 自身或 yougen 内部 routing,故没有 soland/yougen/coauth 三方业务的 scenario doc。它们各自有专门的 scenario doc 说明出处:

| spec 文件 | scenario doc | 性质 | live | fixme |
|---|---|---|---:|---:|
| [harness/mocks-selftest.spec.ts](../tests/harness/mocks-selftest.spec.ts) | [harness/mocks-selftest.md](harness/mocks-selftest.md) | harness 自检 (8 个 mock 的契约 probe);每个测试在对应 mock 未启动时 `test.skip` | 8 | 0 |
| [spaces/admin-section-route.spec.ts](../tests/spaces/admin-section-route.spec.ts) | [spaces/admin-section-route.md](spaces/admin-section-route.md) | yougen routing 回归 probe (`active_section` 在 hard nav 时反映 URL) | 1 | 0 |

## Mock services

`cotest/e2e/mocks/` 下共 8 个 mock,任一个未启动时 harness/mocks-selftest 中对应的测试会自动 `test.skip`,业务 scenario 通过 helper 在 `mockXxxBaseUrl()` 返回 `undefined` 时优雅降级。

| 服务 | 文件 | 触发 | helper API | scenarios 受益 |
|---|---|---|---|---|
| OIDC IdP | [mocks/mock-idp.mjs](../mocks/mock-idp.mjs) | `-StartMockIdp` 或 `-StartMocks` | `mockIdpBaseUrl()` | identity/onboarding, identity/account-device-auth |
| Email + 3PID | [mocks/mock-email.mjs](../mocks/mock-email.mjs) | `-StartMockEmail` 或 `-StartMocks` | `mockEmailBaseUrl()` | invites/third-party, identity/onboarding |
| WebVH witness | [mocks/mock-witness.mjs](../mocks/mock-witness.mjs) | `-StartMockWitness` 或 `-StartMocks` | `mockWitnessBaseUrl()` + `mockWitnessDid()` | identity/webvh-rotation |
| Audit agent | [mocks/mock-audit-agent.mjs](../mocks/mock-audit-agent.mjs) | `-StartMockAuditAgent` 或 `-StartMocks` | `mockAuditAgentBaseUrl()` + `mockAuditAgentDid()` | encryption/audited-e2ee, governance/gdpr-audit-retention |
| Policy server | [mocks/mock-policy-server.mjs](../mocks/mock-policy-server.mjs) | `-StartMockPolicyServer` 或 `-StartMocks` | `mockPolicyServerBaseUrl()` + `mockPolicyServerDid()` | authz/policy-server-check, governance/organization-policy |
| Push gateway | [mocks/mock-push-gateway.mjs](../mocks/mock-push-gateway.mjs) | `-StartMockPushGateway` 或 `-StartMocks` | `mockPushGatewayBaseUrl()` | discovery/notifications |
| Applet registry | [mocks/mock-applet-registry.mjs](../mocks/mock-applet-registry.mjs) | `-StartMockAppletRegistry` 或 `-StartMocks` | `mockAppletRegistryBaseUrl()` + `mockAppletRegistryDid()` | extensions/applet-bridge |
| TSP endpoint | [mocks/mock-tsp-endpoint.mjs](../mocks/mock-tsp-endpoint.mjs) | `-StartMockTspEndpoint` 或 `-StartMocks` | `mockTspEndpointBaseUrl()` + `mockTspEndpointVid()` | identity/tsp-bootstrap, extensions/mimi-federation |

`-StartMocks` 一次启动全部 8 个。每个 mock 都是 Node.js 单文件,RS256 / Ed25519 签真 JWT,共享 `mocks/_shared/keypairs.mjs` 与 `mocks/_shared/inspect.mjs`。

## 编排约定

- 每个 scenario 一个 `*.spec.ts` 文件,路径 `tests/<domain>/<name>.spec.ts`,对应 doc 在 `scenarios/<domain>/<name>.md`
- 唯二例外是 `tests/harness/mocks-selftest.spec.ts`(harness 自检)与 `tests/spaces/admin-section-route.spec.ts`(yougen routing probe),它们的 scenario doc 在同名路径下、并显式标注为 harness / probe
- `test.describe.configure({ mode: "serial" })` — actor 之间有时序依赖
- 每个 scenario 用 `uniqueUser("<domain>-<short>")` 避免污染(短前缀方便日志读)
- 关键 phase 末尾 `stepShot()`
- 暂跑不通的 spec 契约用 `test.fixme()`,正文留 spec § + soland gap 说明
- mock 依赖型 live test 用 `test.skip(!mockXxxBaseUrl(), "...")` 在 setup 阶段优雅跳过(不算 fail)
- 跨 scenario 引用按路径写,如 `(见 identity/multi-device)`,不用顺序号

## 运行

```pwsh
# 单服务器,无 mocks
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -RunProfile joint-full

# 单服务器 + 全部 mocks(激活外部依赖)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -StartMocks -RunProfile joint-full

# 双服务器 + 全部 mocks(最大覆盖)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -DualSoland -StartMocks -RunProfile joint-full

# 跑单个领域
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -Grep "kanban/"

# 跑单个 scenario
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -Grep "messaging/triad-collaboration"

# 跑 harness 自检(需要 -StartMocks 才有可执行内容)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -StartMocks -Grep "harness/mocks-selftest"
```

## 产物

`artifacts/runs/<ts>/joint-e2e/`:
- `summary.md` / `scenarios.md` — 整体 + scenario 维度
- `junit.xml` — CI 友好结构化结果
- `playwright-report/` — HTML(含 trace/video/failure screenshot)
- `services/` — soland / coauth / yougen / mock-* 进程日志
- `screenshots/` / `diagnostics/`(console + network HAR)

## 后续候选(已有 scenario doc, 尚无 spec)

| 主题 | scenario doc | 触发条件 |
|---|---|---|
| Agent Protocol Interop | [extensions/agent-protocol-interop.md](extensions/agent-protocol-interop.md) | yougen agent workspace selectors + soland agent bridge endpoint 就绪 |
| Service Surface Contract | [sync/service-surface-contract.md](sync/service-surface-contract.md) | `/server/describe` claim level、标准错误、分页、幂等、unsupported feature fail-closed 形成统一 e2e |
| Conformance Profile Claim Gates | [conformance/profile-gates.md](conformance/profile-gates.md) | soland/coauth/yougen 三家 describe/profile 链路就绪 |
| spaces/moderation-ban + federation/cross-server 组合 | (待文档化) | federation outbound push 在 soland 落地 |
| 性能 / 负载基线 | (待文档化) | 主线全绿后 |
| 跨服务器 MLS welcome | (待文档化) | federation/cross-server + encryption/mls-group 单独通过后 |
