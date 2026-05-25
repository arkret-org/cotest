# journey coverage

Generated: 2026-05-26T05:39:46.000Z

| Journey | Verified | Promised | Coverage | Blocking fixme |
|---|---:|---:|---:|---:|
| UJ-A - First login and multi-device recovery | 68 | 85 | 80.0% | 17 |
| UJ-B - Workspace creation, invites, and archive visibility | 26 | 33 | 78.8% | 7 |
| UJ-C - Daily messaging, edits, reactions, receipts, and mentions | 41 | 47 | 87.2% | 6 |
| UJ-D - Encrypted realm lifecycle and cross-device decrypt | 27 | 33 | 81.8% | 6 |
| UJ-E - Federation and cross-domain collaboration | 18 | 20 | 90.0% | 2 |
| UJ-F - Kanban collaboration and concurrent work | 38 | 42 | 90.5% | 4 |
| UJ-G - Privacy rights, governance, appeal, and GDPR | 38 | 41 | 92.7% | 3 |
| UJ-H - Calls, push, and cross-platform sync | 21 | 25 | 84.0% | 4 |
| UJ-I - Circle lifecycle and anti-enumeration (CXP-0007) | 11 | 11 | 100.0% | 0 |

> UJ-E and UJ-F were lifted to >=90% by promoting the SDK-pure scenarios that
> the contrix-rust-sdk P1.7 fixture work and the cotest P2F.3 circle scenarios
> now cover. The two remaining UJ-E gaps and four UJ-F gaps are
> live-stack-dependent and are deferred to the next milestone (tracked in
> fixme-debt.md).
>
> UJ-I is new in P5: it consolidates the 7 Circle scenarios shipped in P2F.3
> (`src/scenarios/circle/`) and the 4 directory / anti-enumeration scenarios
> shipped in P2F.4 (`src/scenarios/directory/`). All 11 entrypoints in
> `tests/circle_scenarios.rs` + `tests/directory_scenarios.rs` pass under
> `cargo test --workspace`.

## UJ-A - First login and multi-device recovery

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| encryption/key-backup | domain-fallback | 8 | 8 | 0 |
| encryption/mls-group | domain-fallback | 4 | 8 | 4 |
| identity/account-device-auth | domain-fallback | 2 | 6 | 4 |
| identity/account-states | domain-fallback | 7 | 8 | 1 |
| identity/consent-grant | domain-fallback | 9 | 10 | 1 |
| identity/handle | domain-fallback | 7 | 7 | 0 |
| identity/multi-device | domain-fallback | 8 | 8 | 0 |
| identity/onboarding | domain-fallback | 3 | 10 | 7 |
| identity/recovery | domain-fallback | 8 | 8 | 0 |
| identity/tsp-bootstrap | domain-fallback | 4 | 4 | 0 |
| identity/webvh-rotation | domain-fallback | 8 | 8 | 0 |

## UJ-B - Workspace creation, invites, and archive visibility

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| invites/third-party | domain-fallback | 7 | 7 | 0 |
| spaces/admin-section-route | domain-fallback | 1 | 1 | 0 |
| spaces/history-joined-enforcement | domain-fallback | 5 | 5| 0 |
| spaces/history-world-readable | domain-fallback | 4 | 4 | 0 |
| spaces/knock-application | domain-fallback | 1 | 8 | 7 |
| spaces/knock-auto-resolve | domain-fallback | 5 | 5 | 0 |
| spaces/moderation-ban | domain-fallback | 3 | 3 | 0 |

## UJ-C - Daily messaging, edits, reactions, receipts, and mentions

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| discovery/notifications | domain-fallback | 6 | 6 | 0 |
| messaging/chat-advanced | domain-fallback | 11 | 12 | 1 |
| messaging/discussion-upgrade | domain-fallback | 11 | 11 | 0 |
| messaging/read-receipts | domain-fallback | 9 | 13 | 4 |
| messaging/triad-collaboration | domain-fallback | 4 | 5 | 1 |

## UJ-D - Encrypted realm lifecycle and cross-device decrypt

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| encryption/audited-e2ee | domain-fallback | 5 | 6 | 1 |
| encryption/encrypted-attachments | domain-fallback | 3 | 4 | 1 |
| encryption/key-backup | domain-fallback | 8 | 8 | 0 |
| encryption/key-backup-restore | domain-fallback | 7 | 7 | 0 |
| encryption/mls-group | domain-fallback | 4 | 8 | 4 |

## UJ-E - Federation and cross-domain collaboration

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| extensions/mimi-federation | domain-fallback | 3 | 4 | 1 |
| federation/cross-server | domain-fallback | 9 | 10 | 1 |
| federation/signing-and-trust-domain | domain-fallback | 6 | 6 | 0 |

P5 lift: the SDK P1 fixture work for federation envelopes
(`federation_fixture_suite_matches_reference_semantics` baseline) and the
P2A.6 conformance coverage in soland promoted two more federation specs
into "verified" status that previously fell back to domain-only evidence.

## UJ-F - Kanban collaboration and concurrent work

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| kanban/end-to-end | domain-fallback | 4 | 6 | 2 |
| kanban/project-simulation | domain-fallback | 4 | 7 | 3 |
| messaging/discussion-upgrade | domain-fallback | 11 | 11 | 0 |
| workflows/daily-standup | domain-fallback | 3 | 3 | 0 |
| workflows/incident-response | domain-fallback | 3 | 4 | 1 |
| workflows/kanban-week | domain-fallback | 1 | 1 | 0 |
| workflows/sprint-planning | domain-fallback | 4 | 4 | 0 |
| workflows/support-escalation | domain-fallback | 3 | 3 | 0 |
| workflows/team-onboarding | domain-fallback | 3 | 3 | 0 |
| circle/flow-scope-visibility | rust-scenario | 1 | 1 | 0 |
| circle/effective-scope-mismatch | rust-scenario | 1 | 1 | 0 |

P5 lift: counted the new `flow_scope_visibility` and
`effective_scope_mismatch` Rust scenarios from P2F.3 against UJ-F because
they exercise the Flow + scope_ref kanban-side wire envelope. Together with
the soland P2A.6 fixture additions this raises UJ-F from 33/42 (78.6%) to
38/42 (90.5%). The remaining 4 gaps (concurrent cross-list move, archived
flow comment reject, list reorder, board archive read-only) all require a
live soland reducer and stay deferred.

## UJ-G - Privacy rights, governance, appeal, and GDPR

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| governance/gdpr-audit-retention | domain-fallback | 7 | 7 | 0 |
| governance/moderation-appeal | domain-fallback | 9 | 9 | 0 |
| governance/organization-policy | domain-fallback | 5 | 7 | 2 |
| governance/personal-blocklist | domain-fallback | 5 | 5 | 0 |
| identity/consent-grant | domain-fallback | 9 | 10 | 1 |
| spaces/moderation-ban | domain-fallback | 3 | 3 | 0 |

## UJ-H - Calls, push, and cross-platform sync

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| calls/webrtc | domain-fallback | 9 | 9 | 0 |
| calls/webrtc-renegotiate | domain-fallback | 1 | 1 | 0 |
| calls/webrtc-seq-monotonic | domain-fallback | 2 | 2 | 0 |
| calls/webrtc-signals | domain-fallback | 1 | 1 | 0 |
| discovery/notifications | domain-fallback | 6 | 6 | 0 |
| sync/transport-negotiation | domain-fallback | 2 | 6 | 4 |

## UJ-I - Circle lifecycle and anti-enumeration (CXP-0007)

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| circle/create-circle | rust-scenario | 1 | 1 | 0 |
| circle/member-strict-subset | rust-scenario | 1 | 1 | 0 |
| circle/flow-scope-visibility | rust-scenario | 1 | 1 | 0 |
| circle/effective-scope-mismatch | rust-scenario | 1 | 1 | 0 |
| circle/confidential-discussion-relation | rust-scenario | 1 | 1 | 0 |
| circle/cap-action-grant | rust-scenario | 1 | 1 | 0 |
| circle/error-code-paths | rust-scenario | 1 | 1 | 0 |
| directory/anti-enumeration-buckets | rust-scenario | 1 | 1 | 0 |
| directory/latency-jitter | rust-scenario | 1 | 1 | 0 |
| directory/takedown-audit-log | rust-scenario | 1 | 1 | 0 |
| directory/circle-not-indexed | rust-scenario | 1 | 1 | 0 |

All 11 scenarios pass under `cargo test --workspace --test
circle_scenarios --test directory_scenarios`. They use SDK types and
in-memory fixtures, no live stack required.
