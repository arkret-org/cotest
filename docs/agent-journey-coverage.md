# Agent Journey flow coverage

Agent Journeys exercise visible product stories without prescribing selectors.
This map tracks the cross-component flow references represented by the scenario
catalog. It does not claim that a scenario has passed until a completed run has
checkpoint evidence.

| Flow reference | Coverage | Scenarios | Boundary |
|---|---|---|---|
| `registration-pcr-genesis` | Primary | `first-realm-continuity`, `device-pairing-revocation-recovery`, `federated-team-incident` | Registration readiness and reload are exercised; canonical proof internals remain deterministic conformance assertions. |
| `ordinary-realm-creation` | Primary | `first-realm-continuity`, `invite-history-bootstrap`, `federated-team-incident` | Visible bootstrap, creator membership, main discussion, privacy, and encryption readiness. |
| `message-authoring-seal-sync` | Primary | All five scenarios | Authoring, reload, offline retry, catch-up, cross-device and cross-server visibility. |
| `realm-invitation-history-bootstrap` | Primary | `invite-history-bootstrap`, `federated-team-incident` | Invite discovery, accept-once, MLS readiness, joined-history cutoff, and gap recovery. |
| `realm-event-server-fanout` | Primary | `invite-history-bootstrap`, `federated-team-incident` | Cross-server visibility and read-only convergence checks; outbox internals remain deterministic tests. |
| `device-pairing-and-recovery` | Primary | `device-pairing-revocation-recovery` | Human-confirmed pairing, cross-device decrypt, revoke denial, root recovery, and generation fence. |
| `service-route-authentication-and-relocation` | Partial | `invite-history-bootstrap`, `federated-team-incident` | Target service binding and no bare-URL workflow are exercised; planned endpoint and WebVH relocation need a controllable runtime cutover harness. |
| `service-route-discovery-handover-and-repair` | Partial | `invite-history-bootstrap`, `federated-team-incident` | Initial route carrier and cross-server delivery are exercised; handover notice, mirror fallback, and simultaneous relocation are not yet operable from the journey harness. |
| `personal-agent-sidecar-strand-relay` | Gap | None | The current stack preparation does not expose a separately controlled Agent runtime, and the flow document records Direct Conversation first-chat and native Sidecar product blockers. |

The catalog therefore broadens goal-driven coverage without treating known
runtime or product blockers as passing tests. Repeatable product defects found
by a run must still become deterministic Playwright or conformance regressions.
