# journey implementation inventory

Generated from `e2e/scenarios/user-journeys.md` by `scripts/generate-e2e-coverage.ps1`.
This static inventory does not claim runtime verification; use an Arkret Joint Product E2E run report for executed evidence.

| Journey | Implemented | Promised | Coverage | Blocking fixme |
|---|---:|---:|---:|---:|
| UJ-A - First login and multi-device recovery | 66 | 66 | 100.0% | 0 |
| UJ-B - Workspace creation, invites, and archive visibility | 19 | 19 | 100.0% | 0 |
| UJ-C - Daily messaging, edits, reactions, receipts, and mentions | 41 | 41 | 100.0% | 0 |
| UJ-D - Encrypted realm lifecycle and cross-device decrypt | 9 | 9 | 100.0% | 0 |
| UJ-E - Federation and cross-domain collaboration | 19 | 19 | 100.0% | 0 |
| UJ-F - Kanban collaboration and concurrent work | 45 | 45 | 100.0% | 0 |
| UJ-G - Privacy rights, governance, appeal, and GDPR | 37 | 44 | 84.1% | 7 |
| UJ-H - Calls, push, and cross-platform sync | 24 | 24 | 100.0% | 0 |

## UJ-A - First login and multi-device recovery

| spec | mapping | implemented | promised | blocking |
|---|---|---:|---:|---:|
| encryption/key-backup | domain-fallback | 5 | 5 | 0 |
| encryption/mls-group | domain-fallback | 1 | 1 | 0 |
| identity/account-device-auth | domain-fallback | 2 | 2 | 0 |
| identity/account-handoff | domain-fallback | 2 | 2 | 0 |
| identity/account-states | domain-fallback | 7 | 7 | 0 |
| identity/circle-member | domain-fallback | 4 | 4 | 0 |
| identity/consent-grant | domain-fallback | 11 | 11 | 0 |
| identity/contact-graph | domain-fallback | 8 | 8 | 0 |
| identity/device-key-lifecycle | domain-fallback | 1 | 1 | 0 |
| identity/direct-conversation-founding | domain-fallback | 1 | 1 | 0 |
| identity/multi-device | domain-fallback | 2 | 2 | 0 |
| identity/oidc-login-chain | domain-fallback | 3 | 3 | 0 |
| identity/oidc-login-flow | domain-fallback | 4 | 4 | 0 |
| identity/onboarding | domain-fallback | 3 | 3 | 0 |
| identity/passkey-login-flow | domain-fallback | 1 | 1 | 0 |
| identity/recovery | domain-fallback | 4 | 4 | 0 |
| identity/recovery-key-to-encrypted-realm | domain-fallback | 1 | 1 | 0 |
| identity/session-grant-dpop | domain-fallback | 2 | 2 | 0 |
| identity/tsp-bootstrap | domain-fallback | 4 | 4 | 0 |

## UJ-B - Workspace creation, invites, and archive visibility

| spec | mapping | implemented | promised | blocking |
|---|---|---:|---:|---:|
| invites/invite-addressing | domain-fallback | 4 | 4 | 0 |
| invites/third-party | domain-fallback | 6 | 6 | 0 |
| spaces/admin-section-route | domain-fallback | 1 | 1 | 0 |
| spaces/knock-auto-resolve | domain-fallback | 5 | 5 | 0 |
| spaces/moderation-ban | domain-fallback | 3 | 3 | 0 |

## UJ-C - Daily messaging, edits, reactions, receipts, and mentions

| spec | mapping | implemented | promised | blocking |
|---|---|---:|---:|---:|
| discovery/notifications | domain-fallback | 2 | 2 | 0 |
| messaging/chat-advanced | domain-fallback | 11 | 11 | 0 |
| messaging/discussion-upgrade | domain-fallback | 9 | 9 | 0 |
| messaging/read-receipts | domain-fallback | 13 | 13 | 0 |
| messaging/triad-collaboration | domain-fallback | 6 | 6 | 0 |

## UJ-D - Encrypted realm lifecycle and cross-device decrypt

| spec | mapping | implemented | promised | blocking |
|---|---|---:|---:|---:|
| encryption/audited-e2ee | domain-fallback | 1 | 1 | 0 |
| encryption/encrypted-attachments | domain-fallback | 2 | 2 | 0 |
| encryption/key-backup | domain-fallback | 5 | 5 | 0 |
| encryption/mls-group | domain-fallback | 1 | 1 | 0 |

## UJ-E - Federation and cross-domain collaboration

| spec | mapping | implemented | promised | blocking |
|---|---|---:|---:|---:|
| extensions/mimi-federation | domain-fallback | 2 | 2 | 0 |
| federation/contact-graph-federation | domain-fallback | 5 | 5 | 0 |
| federation/cross-server | domain-fallback | 10 | 10 | 0 |
| federation/security-hardening | domain-fallback | 2 | 2 | 0 |

## UJ-F - Kanban collaboration and concurrent work

| spec | mapping | implemented | promised | blocking |
|---|---|---:|---:|---:|
| kanban/cross-member-encrypted | domain-fallback | 3 | 3 | 0 |
| kanban/end-to-end | domain-fallback | 9 | 9 | 0 |
| kanban/project-simulation | domain-fallback | 7 | 7 | 0 |
| messaging/discussion-upgrade | domain-fallback | 9 | 9 | 0 |
| workflows/daily-standup | domain-fallback | 3 | 3 | 0 |
| workflows/incident-response | domain-fallback | 3 | 3 | 0 |
| workflows/kanban-week | domain-fallback | 1 | 1 | 0 |
| workflows/sprint-planning | domain-fallback | 4 | 4 | 0 |
| workflows/support-escalation | domain-fallback | 3 | 3 | 0 |
| workflows/team-onboarding | domain-fallback | 3 | 3 | 0 |

## UJ-G - Privacy rights, governance, appeal, and GDPR

| spec | mapping | implemented | promised | blocking |
|---|---|---:|---:|---:|
| governance/gdpr-audit-retention | domain-fallback | 7 | 7 | 0 |
| governance/moderation-appeal | domain-fallback | 9 | 9 | 0 |
| governance/organization-bootstrap | domain-fallback | 0 | 3 | 3 |
| governance/organization-policy | domain-fallback | 1 | 5 | 4 |
| governance/personal-blocklist | domain-fallback | 6 | 6 | 0 |
| identity/consent-grant | domain-fallback | 11 | 11 | 0 |
| spaces/moderation-ban | domain-fallback | 3 | 3 | 0 |

## UJ-H - Calls, push, and cross-platform sync

| spec | mapping | implemented | promised | blocking |
|---|---|---:|---:|---:|
| calls/webrtc | domain-fallback | 4 | 4 | 0 |
| calls/webrtc-call-sequence | domain-fallback | 2 | 2 | 0 |
| calls/webrtc-media-token | domain-fallback | 4 | 4 | 0 |
| calls/webrtc-moderation | domain-fallback | 4 | 4 | 0 |
| calls/webrtc-renegotiate | domain-fallback | 2 | 2 | 0 |
| calls/webrtc-seq-monotonic | domain-fallback | 2 | 2 | 0 |
| calls/webrtc-signals | domain-fallback | 1 | 1 | 0 |
| discovery/notifications | domain-fallback | 2 | 2 | 0 |
| sync/transport-negotiation | domain-fallback | 3 | 3 | 0 |
