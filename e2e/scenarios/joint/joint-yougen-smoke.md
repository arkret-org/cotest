# Joint Yougen Smoke

## Intent

Prove the joint harness can run a real yougen web build against a real soland process.

## Strand

1. Register Alice and Bob through soland.
2. Open two isolated yougen browser contexts with dev sessions.
3. Alice creates a public, invite-governed, plaintext realm from the yougen UI.
4. Alice sends a plaintext message through real soland.
5. Alice sees the message in the yougen timeline UI.

## Acceptance

- `run-cotest.ps1 -Profile joint` starts soland, coauth, and yougen through `run-joint-e2e.ps1`.
- Playwright project `joint-yougen` discovers this scenario under `e2e/tests/joint`.
- The smoke is tagged `@fully-implemented` so the joint-smoke profile includes it.
