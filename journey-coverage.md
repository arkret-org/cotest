# journey coverage

Generated: 2026-05-25T15:49:26.828Z

| Journey | Verified | Promised | Coverage | Blocking fixme |
|---|---:|---:|---:|---:|
| UJ-A - First login and multi-device recovery | 68 | 85 | 80.0% | 17 |
| UJ-B - Workspace creation, invites, and archive visibility | 26 | 33 | 78.8% | 7 |
| UJ-C - Daily messaging, edits, reactions, receipts, and mentions | 41 | 47 | 87.2% | 6 |
| UJ-D - Encrypted realm lifecycle and cross-device decrypt | 27 | 33 | 81.8% | 6 |
| UJ-E - Federation and cross-domain collaboration | 16 | 20 | 80.0% | 4 |
| UJ-F - Kanban collaboration and concurrent work | 33 | 42 | 78.6% | 9 |
| UJ-G - Privacy rights, governance, appeal, and GDPR | 38 | 41 | 92.7% | 3 |
| UJ-H - Calls, push, and cross-platform sync | 21 | 25 | 84.0% | 4 |

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
| spaces/history-joined-enforcement | domain-fallback | 5 | 5 | 0 |
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
| extensions/mimi-federation | domain-fallback | 2 | 4 | 2 |
| federation/cross-server | domain-fallback | 8 | 10 | 2 |
| federation/signing-and-trust-domain | domain-fallback | 6 | 6 | 0 |

## UJ-F - Kanban collaboration and concurrent work

| spec | mapping | verified | promised | blocking |
|---|---|---:|---:|---:|
| kanban/end-to-end | domain-fallback | 3 | 6 | 3 |
| kanban/project-simulation | domain-fallback | 2 | 7 | 5 |
| messaging/discussion-upgrade | domain-fallback | 11 | 11 | 0 |
| workflows/daily-standup | domain-fallback | 3 | 3 | 0 |
| workflows/incident-response | domain-fallback | 3 | 4 | 1 |
| workflows/kanban-week | domain-fallback | 1 | 1 | 0 |
| workflows/sprint-planning | domain-fallback | 4 | 4 | 0 |
| workflows/support-escalation | domain-fallback | 3 | 3 | 0 |
| workflows/team-onboarding | domain-fallback | 3 | 3 | 0 |

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
