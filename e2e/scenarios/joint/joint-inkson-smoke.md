# Joint Inkson Smoke

## Intent

Prove the joint harness can run a real inkson web build against real soland and
coauth processes, including cross-principal chat projections.

## Strand

1. Register Alice and Bob through soland.
2. Open two isolated inkson browser contexts with dev sessions.
3. Alice creates a public, invite-governed, plaintext realm from the inkson UI.
4. Alice sends a plaintext message through real soland.
5. Alice sees the message in the inkson timeline UI.
6. Register a third DPoP principal, add it to Alice's Realm, and project it as
   Alice's agent through selector mention metadata.
7. The agent posts a visible reply in the Realm discussion.
8. Alice opens the Inkson member panel: her controller row is first, carries
   `ME`, reports one agent, and expands to the agent row.
9. Typing `@me/<agent_slug>` offers the agent suggestion with its agent badge.

## Acceptance

- `run-cotest.ps1 -Profile joint` starts soland, coauth, and inkson through `run-joint-e2e.ps1`.
- Playwright project `joint-inkson` discovers this scenario under `e2e/tests/joint`.
- The smoke is tagged `@fully-implemented` so the joint-smoke profile includes it.
- The agent projection case uses a real third DPoP session and real soland
  events. Full personal-agent provisioning, pairing, participation grants, and
  runtime proof enforcement remain covered by `tests/agent_provision_e2e.rs`;
  this browser case owns the Inkson grouping and selector UX boundary.
