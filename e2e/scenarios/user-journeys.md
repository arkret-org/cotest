# User Journey Coverage Map

This file groups the e2e scenario tree by the eight user journeys from
`_test_gap_claude.md` section 2.

| ID | Journey | Primary scenario domains |
|---|---|---|
| UJ-A | First login and multi-device recovery | `identity/*`, `encryption/key-backup`, `encryption/mls-group` |
| UJ-B | Workspace creation, invites, and archive visibility | `spaces/*`, `invites/*` |
| UJ-C | Daily messaging, edits, reactions, receipts, and mentions | `messaging/*`, `discovery/notifications` |
| UJ-D | Encrypted realm lifecycle and cross-device decrypt | `encryption/*` |
| UJ-E | Federation and cross-domain collaboration | `federation/*`, `extensions/mimi-federation` |
| UJ-F | Kanban collaboration and concurrent work | `kanban/*`, `workflows/*`, `messaging/discussion-upgrade` |
| UJ-G | Privacy rights, governance, appeal, and GDPR | `governance/*`, `identity/consent-grant`, `spaces/moderation-ban` |
| UJ-H | Calls, push, and cross-platform sync | `calls/*`, `discovery/notifications`, `sync/transport-negotiation` |

Specs may opt into explicit mapping with source tags such as `@UJ-C`.
