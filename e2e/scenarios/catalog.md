# cotest e2e coverage

Promised: 399 · Verified: 269 (67.4%)

Totals: 67 scenarios / 67 specs / 269 verified / 399 promised / 130 fixme / 25 skip (19 domains)

## Totals

| metric | count |
|---|---:|
| scenario docs | 67 |
| spec files | 67 |
| live tests | 269 |
| test.fixme | 130 |
| promised tests | 399 |
| verified tests | 269 |
| verified ratio | 67.4% |
| test.skip (conditional) | 25 |
| domains | 19 |

## Per-domain rollup

| domain | scenarios | specs | verified | promised | ratio | fixme | skip |
|---|---:|---:|---:|---:|---:|---:|---:|
| authz | 2 | 2 | 8 | 12 | 66.7% | 4 | 0 |
| calls | 4 | 4 | 13 | 13 | 100.0% | 0 | 0 |
| conformance | 4 | 4 | 32 | 33 | 97.0% | 1 | 3 |
| discovery | 2 | 2 | 10 | 11 | 90.9% | 1 | 0 |
| encryption | 5 | 5 | 24 | 34 | 70.6% | 10 | 1 |
| events | 1 | 1 | 1 | 1 | 100.0% | 0 | 0 |
| extensions | 3 | 3 | 7 | 14 | 50.0% | 7 | 1 |
| federation | 3 | 3 | 16 | 18 | 88.9% | 2 | 4 |
| governance | 4 | 4 | 26 | 28 | 92.9% | 2 | 1 |
| harness | 1 | 1 | 10 | 10 | 100.0% | 0 | 10 |
| identity | 9 | 9 | 31 | 69 | 44.9% | 38 | 2 |
| invites | 1 | 1 | 1 | 7 | 14.3% | 6 | 0 |
| joint | 1 | 1 | 2 | 2 | 100.0% | 0 | 0 |
| kanban | 2 | 2 | 8 | 16 | 50.0% | 8 | 0 |
| messaging | 4 | 4 | 33 | 39 | 84.6% | 6 | 0 |
| models | 4 | 4 | 6 | 21 | 28.6% | 15 | 0 |
| spaces | 6 | 6 | 14 | 26 | 53.8% | 12 | 0 |
| sync | 5 | 5 | 18 | 27 | 66.7% | 9 | 3 |
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
| conformance/profile-gates | 6 | 6 | 100.0% | 0 | 1 | live-only | yes | @fully-implemented |
| conformance/registry-drift | 6 | 6 | 100.0% | 0 | 1 | live-only | yes | @fully-implemented |
| conformance/snapshot-query-scalability | 7 | 7 | 100.0% | 0 | 1 | live-only | yes | @fully-implemented |
| discovery/directory | 4 | 5 | 80.0% | 1 | 0 | mixed | yes |  |
| discovery/notifications | 6 | 6 | 100.0% | 0 | 0 | live-only | yes |  |
| encryption/audited-e2ee | 5 | 6 | 83.3% | 1 | 1 | mixed | yes |  |
| encryption/encrypted-attachments | 3 | 4 | 75.0% | 1 | 0 | mixed | yes |  |
| encryption/key-backup | 3 | 6 | 50.0% | 3 | 0 | mixed | yes |  |
| encryption/key-backup-restore | 7 | 7 | 100.0% | 0 | 0 | live-only | yes |  |
| encryption/mls-group | 6 | 11 | 54.5% | 5 | 0 | mixed | yes |  |
| events/batch-realm-bootstrap | 1 | 1 | 100.0% | 0 | 0 | live-only | yes | @fully-implemented |
| extensions/agent-protocol-interop | 1 | 6 | 16.7% | 5 | 0 | mixed | yes |  |
| extensions/applet-bridge | 4 | 4 | 100.0% | 0 | 1 | live-only | yes |  |
| extensions/mimi-federation | 2 | 4 | 50.0% | 2 | 0 | mixed | yes |  |
| federation/cross-server | 8 | 10 | 80.0% | 2 | 1 | mixed | yes |  |
| federation/security-hardening | 2 | 2 | 100.0% | 0 | 3 | live-only | yes |  |
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
| joint/joint-yougen-smoke | 2 | 2 | 100.0% | 0 | 0 | live-only | yes | @fully-implemented |
| kanban/end-to-end | 6 | 9 | 66.7% | 3 | 0 | mixed | yes |  |
| kanban/project-simulation | 2 | 7 | 28.6% | 5 | 0 | mixed | yes |  |
| messaging/chat-advanced | 11 | 12 | 91.7% | 1 | 0 | mixed | yes |  |
| messaging/discussion-upgrade | 9 | 9 | 100.0% | 0 | 0 | live-only | yes |  |
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
| sync/offline-conflict | 4 | 5 | 80.0% | 1 | 0 | mixed | yes |  |
| sync/offline-queue-replay | 5 | 5 | 100.0% | 0 | 0 | live-only | yes |  |
| sync/service-surface-contract | 3 | 7 | 42.9% | 4 | 1 | mixed | yes | @fully-implemented |
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
