# Joint Inkson Smoke

## Intent

Prove the joint harness can run a real inkson web build against a real soland process.

## Strand

1. Register Alice and Bob through soland.
2. Open two isolated inkson browser contexts with dev sessions.
3. Alice creates a public, invite-governed, plaintext realm from the inkson UI.
4. Alice sends a plaintext message through real soland.
5. Alice sees the message in the inkson timeline UI.

## Acceptance

- `run-cotest.ps1 -Profile joint` starts soland, coauth, and inkson through `run-joint-e2e.ps1`.
- Playwright project `joint-yougen` discovers this scenario under `e2e/tests/joint`.
- The smoke is tagged `@fully-implemented` so the joint-smoke profile includes it.
