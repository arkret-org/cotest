# `conformance-vectors.md` §11 compliance (P5.2)

Generated: 2026-05-27 — pairs with
[`agent-profile-coverage.md`](agent-profile-coverage.md).

`conformance-vectors.md` §11 (personal agent + sidecar) declares 9
normative cross-server invariants introduced by CKP-0008 + CKP-0009.
This page is the one-stop compliance attestation: for every §11 vector,
the (a) cotest scenario module, (b) test entrypoint, and (c) gating output
that proves compliance.

## 9 vector ↔ scenario mapping

| §11 Vector ID | Spec name                                       | Scenario module                                                                                   | Test entrypoint                                  |
|---------------|-------------------------------------------------|---------------------------------------------------------------------------------------------------|--------------------------------------------------|
| V-1           | provisioning + pairing + grant ordering         | `src/scenarios/spec_section_11/provisioning_pairing_grant_order.rs`                               | `s11_provisioning_pairing_grant_order`           |
| V-2           | pairing expiry auto-revoke                      | `src/scenarios/spec_section_11/pairing_expiry_auto_revoke.rs`                                     | `s11_pairing_expiry_auto_revoke`                 |
| V-3           | session grant replay guard                      | `src/scenarios/spec_section_11/session_grant_replay_guard.rs`                                     | `s11_session_grant_replay_guard`                 |
| V-4           | controller deactivate cascade                   | `src/scenarios/spec_section_11/controller_deactivate_cascade.rs`                                  | `s11_controller_deactivate_cascade`              |
| V-5           | act-on-behalf attribution                       | `src/scenarios/spec_section_11/act_on_behalf_attribution.rs`                                      | `s11_act_on_behalf_attribution`                  |
| V-6           | sidecar circle idempotent ensure                | `src/scenarios/spec_section_11/sidecar_circle_idempotent_ensure.rs`                               | `s11_sidecar_circle_idempotent_ensure`           |
| V-7           | existence privacy                               | `src/scenarios/spec_section_11/existence_privacy.rs`                                              | `s11_existence_privacy`                          |
| V-8           | eligibility tri-state + revocation              | `src/scenarios/spec_section_11/eligibility_tristate_and_revocation.rs`                            | `s11_eligibility_tristate_and_revocation`        |
| V-9           | multi-agent publish attribution                 | `src/scenarios/spec_section_11/multi_agent_publish_attribution.rs`                                | `s11_multi_agent_publish_attribution`            |

All 9 entrypoints live in `tests/spec_section_11_scenarios.rs` and are
exercised by:

```powershell
cargo test --workspace --test spec_section_11_scenarios
```

## Per-vector invariant + observable

| V    | Invariant                                                                                                | Observable that closes the gate                                            |
|------|----------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| V-1  | `ck.self.agent.command.provision` → `ck.agent.pairing.create` → `ck.capability.grant` MUST land in order.             | Out-of-order replay is rejected with `precondition_failed`.                |
| V-2  | After `expires_at` elapses, the agent session is auto-revoked.                                            | A `ak.session.grant_revoke{reason="pairing_expired"}` event is produced.   |
| V-3  | Replaying a session_grant with the same nonce MUST be rejected.                                           | Reducer returns `already_exists` (idempotent close), not double-grant.     |
| V-4  | Controller deactivate fans out: `ck.self.agent.deactivate` → `ck.agent.key.revoke` → `ck.capability.revoke`.   | Per-agent fan-out is deterministic and ordered.                            |
| V-5  | Every act-on-behalf event carries `(executed_by, authorization_ref, actor_kind)`.                         | Validator rejects events missing any of the three fields.                  |
| V-6  | `ck.self.agent.sidecar_thread.command.ensure(controller, agent)` MUST return the same `sidecar_circle_id` on retry.    | Two consecutive ensure() calls return byte-identical typed-ids.            |
| V-7  | A non-controller cannot probe agent existence; not-found is indistinguishable from forbidden.             | `ck.directory.lookup{agent_principal}` returns identical shapes either way.|
| V-8  | Capability grants have tri-state eligibility (`active` / `paused` / `revoked`); revocation drains cache.  | `ck.capability.cache.invalidate` is emitted on transition.                 |
| V-9  | Multi-agent publishes preserve per-event attribution (no cross-agent contamination).                      | Consumer reducer renders distinct author panes per event source.           |

## Gating output

### What "gating output" looks like

Each test prints its compliance proof as a single line on success:

```text
test s11_provisioning_pairing_grant_order ... ok
test s11_pairing_expiry_auto_revoke       ... ok
test s11_session_grant_replay_guard       ... ok
test s11_controller_deactivate_cascade    ... ok
test s11_act_on_behalf_attribution        ... ok
test s11_sidecar_circle_idempotent_ensure ... ok
test s11_existence_privacy                ... ok
test s11_eligibility_tristate_and_revocation ... ok
test s11_multi_agent_publish_attribution  ... ok

test result: ok. 9 passed; 0 failed; 0 ignored
```

A single failure flips the gate to red and `coverage-gate.md` records
the failing vector ID under the matching profile (see
[`agent-profile-coverage.md`](agent-profile-coverage.md) for the
profile-side projection).

### Gate matrix (vector × tier)

| Vector | SDK-pure (`cargo test --workspace`) | Live-server (`-- --ignored` with bringup) |
|--------|--------------------------------------|-------------------------------------------|
| V-1    | hard                                 | hard                                      |
| V-2    | hard                                 | hard                                      |
| V-3    | hard                                 | hard                                      |
| V-4    | hard (envelope shape only)           | hard (full fan-out observable)            |
| V-5    | hard                                 | hard                                      |
| V-6    | hard                                 | hard                                      |
| V-7    | hard (constant-time response shape)  | hard (timing variance bound check)        |
| V-8    | hard                                 | hard                                      |
| V-9    | hard                                 | hard                                      |

V-4 and V-7 have an SDK-pure tier weaker than the live tier because the
"deterministic fan-out" and "timing variance bound" observables are only
meaningful against a real reducer. The SDK-pure tier still gates the
envelope shape — a wire-shape regression cannot ship.

### CI / nightly evidence

- `.github/workflows/ci.yml` job `rust` runs the SDK-pure tier on every
  PR. Each toolchain matrix entry (`1.80`, `1.92`) must be green.
- `.github/workflows/integration.yml` job `joint-bringup` runs the
  live-server tier nightly against the sibling `soland` checkout and uploads
  the live harness artifacts from the run.

## Cross-references

- [`agent-profile-coverage.md`](agent-profile-coverage.md) — 4 profiles ×
  9 vectors grid.
- [`seed-reproducibility.md`](seed-reproducibility.md) — how to replay a
  failed §11 case from `artifacts/runs/<ts>/`.
- [`release-evidence-1.0.0.md`](release-evidence-1.0.0.md) — evidence
  pack for the circle-rollout milestone (links this doc).
