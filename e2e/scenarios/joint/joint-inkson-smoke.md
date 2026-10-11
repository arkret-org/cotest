# Joint Inkson Smoke

## Intent

Prove the joint harness can run a real inkson web build against real coland and
coauth processes, including cross-principal chat projections.

## Strand

1. Register Alice and Bob through coland.
2. Open two isolated inkson browser contexts with dev sessions.
3. Alice creates a public, invite-governed, plaintext realm from the inkson UI;
   the submitted genesis batch starts at `actor_seq=0`, links its closed
   bootstrap follow-up facets from sequence 1 onward, and performs no combined
   frontier preflight for that new Realm.
4. Alice sends a plaintext message through real coland.
5. Alice sees the message in the inkson timeline UI.
6. Register a third DPoP principal, add it to Alice's Realm, and project it as
   Alice's agent through selector mention metadata.
7. The agent posts a visible reply in the Realm discussion.
8. Alice opens the Inkson member panel: her controller row is first, carries
   `ME`, reports one agent, and expands to the agent row.
9. Typing `@me/<agent_slug>` offers the agent suggestion with its agent badge.

## Acceptance

- `run-server-conformance.ps1 -Profile joint` starts coland, coauth, and inkson through `run-joint-e2e.ps1`.
- Playwright project `joint-inkson` discovers this scenario under `e2e/tests/joint`.
- The smoke is tagged `@fully-implemented` so the joint-smoke profile includes it.
- The UI-level request trace pins local Realm genesis authoring independently of
  the API helper and Coland reducer tests.
- The agent projection case uses a real third DPoP session and real coland
  events. Full agent provisioning, pairing, participation grants, and
  runtime proof enforcement remain covered by `tests/agent_provision_e2e.rs`;
  this browser case owns the Inkson grouping and selector UX boundary.
