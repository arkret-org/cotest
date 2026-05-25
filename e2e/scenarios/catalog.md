# cotest e2e coverage

Promised: 396 · Verified: 249 (62.9%)

Totals: 66 scenarios / 66 specs / 249 verified / 396 promised / 147 fixme / 22 skip (19 domains)

## Totals

| metric | count |
|---|---:|
| scenario docs | 66 |
| spec files | 66 |
| live tests | 249 |
| test.fixme | 147 |
| promised tests | 396 |
| verified tests | 249 |
| verified ratio | 62.9% |
| test.skip (conditional) | 22 |
| domains | 19 |

## Per-domain rollup

| domain | scenarios | specs | verified | promised | ratio | fixme | skip |
|---|---:|---:|---:|---:|---:|---:|---:|
| authz | 2 | 2 | 8 | 12 | 66.7% | 4 | 0 |
| calls | 4 | 4 | 13 | 13 | 100.0% | 0 | 0 |
| conformance | 4 | 4 | 21 | 33 | 63.6% | 12 | 3 |
| discovery | 2 | 2 | 10 | 11 | 90.9% | 1 | 0 |
| documents | 1 | 1 | 2 | 2 | 100.0% | 0 | 0 |
| encryption | 5 | 5 | 20 | 33 | 60.6% | 13 | 1 |
| extensions | 3 | 3 | 7 | 14 | 50.0% | 7 | 1 |
| federation | 2 | 2 | 14 | 16 | 87.5% | 2 | 1 |
| governance | 4 | 4 | 26 | 28 | 92.9% | 2 | 1 |
| harness | 1 | 1 | 10 | 10 | 100.0% | 0 | 10 |
| identity | 9 | 9 | 31 | 69 | 44.9% | 38 | 2 |
| invites | 1 | 1 | 1 | 7 | 14.3% | 6 | 0 |
| joint | 1 | 1 | 1 | 1 | 100.0% | 0 | 0 |
| kanban | 2 | 2 | 5 | 13 | 38.5% | 8 | 0 |
| messaging | 4 | 4 | 35 | 41 | 85.4% | 6 | 0 |
| models | 4 | 4 | 6 | 21 | 28.6% | 15 | 0 |
| spaces | 6 | 6 | 14 | 26 | 53.8% | 12 | 0 |
| sync | 5 | 5 | 16 | 28 | 57.1% | 12 | 3 |
| workflows | 6 | 6 | 9 | 18 | 50.0% | 9 | 0 |

## Per-spec

| spec | verified | promised | ratio | fixme | skip | status | scenario? | tags |
|---|---:|---:|---:|---:|---:|---|---|---|
| authz/capability-chain | 7 | 7 | 100.0% | 0 | 0 | live-only | yes | @fully-implemented |
| authz/policy-server-check | 1 | 5 | 20.0% | 4 | 0 | mixed | yes |  |
| calls/webrtc | 9 | 9 | 100.0% | 0 | 0 | live-only | yes |  |
| calls/webrtc-renegotiate | 1 | 1 | 100.0% | 0 | 0 | live-only | yes |  |
| calls/webrtc-seq-monotonic | 2 | 2 | 100.0% | 0 | 0 | live-only | yes |  |
| calls/webrtc-signals | 1 | 1 | 100.0% | 0 | 0 | live-only | yes |  |
| conformance/encoding-vectors | 13 | 14 | 92.9% | 1 | 0 | mixed | yes |  |
| conformance/profile-gates | 3 | 6 | 50.0% | 3 | 1 | mixed | yes | @fully-implemented |
| conformance/registry-drift | 3 | 6 | 50.0% | 3 | 1 | mixed | yes | @fully-implemented |
| conformance/snapshot-query-scalability | 2 | 7 | 28.6% | 5 | 1 | mixed | yes | @fully-implemented |
| discovery/directory | 4 | 5 | 80.0% | 1 | 0 | mixed | yes |  |
| discovery/notifications | 6 | 6 | 100.0% | 0 | 0 | live-only | yes |  |
| documents/collaboration | 2 | 2 | 100.0% | 0 | 0 | live-only | yes |  |
| encryption/audited-e2ee | 5 | 6 | 83.3% | 1 | 1 | mixed | yes |  |
| encryption/encrypted-attachments | 3 | 4 | 75.0% | 1 | 0 | mixed | yes |  |
| encryption/key-backup | 1 | 8 | 12.5% | 7 | 0 | mixed | yes |  |
| encryption/key-backup-restore | 7 | 7 | 100.0% | 0 | 0 | live-only | yes |  |
| encryption/mls-group | 4 | 8 | 50.0% | 4 | 0 | mixed | yes |  |
| extensions/agent-protocol-interop | 1 | 6 | 16.7% | 5 | 0 | mixed | yes |  |
| extensions/applet-bridge | 4 | 4 | 100.0% | 0 | 1 | live-only | yes |  |
| extensions/mimi-federation | 2 | 4 | 50.0% | 2 | 0 | mixed | yes |  |
| federation/cross-server | 8 | 10 | 80.0% | 2 | 1 | mixed | yes |  |
| federation/signing-and-trust-domain | 6 | 6 | 100.0% | 0 | 0 | live-only | yes |  |
| governance/gdpr-audit-retention | 7 | 7 | 100.0% | 0 | 1 | live-only | yes |  |
| governance/moderation-appeal | 9 | 9 | 100.0% | 0 | 0 | live-only | yes |  |
| governance/organization-policy | 5 | 7 | 71.4% | 2 | 0 | mixed | yes |  |
| governance/personal-blocklist | 5 | 5 | 100.0% | 0 | 0 | live-only | yes |  |
| harness/mocks-selftest | 10 | 10 | 100.0% | 0 | 10 | live-only | yes | @fully-implemented |
| identity/account-device-auth | 2 | 6 | 33.3% | 4 | 0 | mixed | yes |  |
| identity/account-states | 7 | 8 | 87.5% | 1 | 0 | mixed | yes |  |
| identity/consent-grant | 9 | 10 | 90.0% | 1 | 0 | mixed | yes |  |
| identity/handle | 7 | 7 | 100.0% | 0 | 0 | live-only | yes | @fully-implemented |
| identity/multi-device | 2 | 8 | 25.0% | 6 | 0 | mixed | yes |  |
| identity/onboarding | 3 | 10 | 30.0% | 7 | 2 | mixed | yes |  |
| identity/recovery | 1 | 8 | 12.5% | 7 | 0 | mixed | yes |  |
| identity/tsp-bootstrap | 0 | 4 | 0.0% | 4 | 0 | fixme-only | yes |  |
| identity/webvh-rotation | 0 | 8 | 0.0% | 8 | 0 | fixme-only | yes |  |
| invites/third-party | 1 | 7 | 14.3% | 6 | 0 | mixed | yes |  |
| joint/joint-yougen-smoke | 1 | 1 | 100.0% | 0 | 0 | live-only | yes | @fully-implemented |
| kanban/end-to-end | 3 | 6 | 50.0% | 3 | 0 | mixed | yes |  |
| kanban/project-simulation | 2 | 7 | 28.6% | 5 | 0 | mixed | yes |  |
| messaging/chat-advanced | 11 | 12 | 91.7% | 1 | 0 | mixed | yes |  |
| messaging/discussion-upgrade | 11 | 11 | 100.0% | 0 | 0 | live-only | yes |  |
| messaging/read-receipts | 9 | 13 | 69.2% | 4 | 0 | mixed | yes |  |
| messaging/triad-collaboration | 4 | 5 | 80.0% | 1 | 0 | mixed | yes |  |
| models/core-object-invariants | 1 | 5 | 20.0% | 4 | 0 | mixed | yes |  |
| models/morph-schema-migration | 2 | 6 | 33.3% | 4 | 0 | mixed | yes | @fully-implemented |
| models/private-read-marker | 2 | 6 | 33.3% | 4 | 0 | mixed | yes |  |
| models/realm-links | 1 | 4 | 25.0% | 3 | 0 | mixed | yes |  |
| spaces/admin-section-route | 1 | 1 | 100.0% | 0 | 0 | live-only | yes | @fully-implemented |
| spaces/history-joined-enforcement | 5 | 5 | 100.0% | 0 | 0 | live-only | yes | @fully-implemented |
| spaces/history-world-readable | 4 | 4 | 100.0% | 0 | 0 | live-only | yes | @fully-implemented |
| spaces/knock-application | 1 | 8 | 12.5% | 7 | 0 | mixed | yes |  |
| spaces/knock-auto-resolve | 0 | 5 | 0.0% | 5 | 0 | fixme-only | yes |  |
| spaces/moderation-ban | 3 | 3 | 100.0% | 0 | 0 | live-only | yes |  |
| sync/offline-conflict | 3 | 6 | 50.0% | 3 | 0 | mixed | yes |  |
| sync/offline-queue-replay | 5 | 5 | 100.0% | 0 | 0 | live-only | yes |  |
| sync/service-surface-contract | 2 | 7 | 28.6% | 5 | 1 | mixed | yes | @fully-implemented |
| sync/sovereign-deployment | 4 | 4 | 100.0% | 0 | 1 | live-only | yes |  |
| sync/transport-negotiation | 2 | 6 | 33.3% | 4 | 1 | mixed | yes |  |
| workflows/daily-standup | 1 | 3 | 33.3% | 2 | 0 | mixed | yes |  |
| workflows/incident-response | 3 | 4 | 75.0% | 1 | 0 | mixed | yes |  |
| workflows/kanban-week | 1 | 1 | 100.0% | 0 | 0 | live-only | yes |  |
| workflows/sprint-planning | 2 | 4 | 50.0% | 2 | 0 | mixed | yes |  |
| workflows/support-escalation | 1 | 3 | 33.3% | 2 | 0 | mixed | yes |  |
| workflows/team-onboarding | 1 | 3 | 33.3% | 2 | 0 | mixed | yes |  |

## Orphans

- specs without scenario doc: none
- scenarios without spec file: none

## Catalog drift

- no known-stale phrases detected in `scenarios/catalog.md`.
