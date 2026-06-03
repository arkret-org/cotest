# Agent profile coverage (P4-A / P5.2)

Generated: 2026-05-27 — closes the P4-A "yellow" follow-up (`_cotest_todos.md`
P4-A bullet 5).

This page is the 1-to-1 grid mapping the 4 personal-agent conformance
profiles to the 9 `conformance-vectors.md` §11 vectors. It is the audit
artifact backing the §11 compliance claim — auditors should cross-walk
this grid against [`spec-section-11-compliance.md`](spec-section-11-compliance.md).

## Profiles

| ID  | Profile                                       | SDK module                                            | Test                                            |
|-----|-----------------------------------------------|-------------------------------------------------------|-------------------------------------------------|
| P-1 | `ck.profile.personal_agent_provisioning.v1`   | `cotest::scenarios::personal_agent_provisioning`      | `personal_agent_provisioning_profile`           |
| P-2 | `ck.profile.agent_auth.v1`                    | `cotest::scenarios::agent_auth`                       | `agent_auth_profile`                            |
| P-3 | `ck.profile.agent_delegation_policy.v1`       | `cotest::scenarios::agent_delegation_policy`          | `agent_delegation_policy_profile`               |
| P-4 | `ck.profile.agent_sidecar_thread.v1`          | `cotest::scenarios::agent_sidecar_thread`             | `agent_sidecar_thread_profile`                  |

## §11 vectors

| ID   | Vector (`conformance-vectors.md` §11)             | SDK module                                                                  |
|------|---------------------------------------------------|-----------------------------------------------------------------------------|
| V-1  | provisioning + pairing + grant ordering           | `spec_section_11::provisioning_pairing_grant_order`                         |
| V-2  | pairing expiry auto-revoke                        | `spec_section_11::pairing_expiry_auto_revoke`                               |
| V-3  | session grant replay guard                        | `spec_section_11::session_grant_replay_guard`                               |
| V-4  | controller deactivate cascade                     | `spec_section_11::controller_deactivate_cascade`                            |
| V-5  | act-on-behalf attribution                         | `spec_section_11::act_on_behalf_attribution`                                |
| V-6  | sidecar circle idempotent ensure                  | `spec_section_11::sidecar_circle_idempotent_ensure`                         |
| V-7  | existence privacy                                 | `spec_section_11::existence_privacy`                                        |
| V-8  | eligibility tri-state + revocation                | `spec_section_11::eligibility_tristate_and_revocation`                      |
| V-9  | multi-agent publish attribution                   | `spec_section_11::multi_agent_publish_attribution`                          |

## 4 profiles x 9 vectors grid

A `*` cell is a normative requirement: the profile MUST satisfy this vector.
A `o` cell is informational — the vector may exercise paths the profile
declares but the profile contract does not gate on the vector itself
(e.g. provisioning is informationally exercised by `act-on-behalf
attribution` because the act-on-behalf event must reference a provisioned
agent, but the act-on-behalf vector does not gate the provisioning
profile).

A `-` cell means the vector is out of scope for that profile.

| Profile \\ Vector                                  | V-1 | V-2 | V-3 | V-4 | V-5 | V-6 | V-7 | V-8 | V-9 |
|----------------------------------------------------|-----|-----|-----|-----|-----|-----|-----|-----|-----|
| P-1 `personal_agent_provisioning.v1`               | *   | o   | -   | *   | o   | -   | *   | -   | o   |
| P-2 `agent_auth.v1`                                | *   | *   | *   | *   | -   | -   | *   | -   | -   |
| P-3 `agent_delegation_policy.v1`                   | o   | *   | -   | *   | *   | -   | -   | *   | *   |
| P-4 `agent_sidecar_thread.v1`                      | o   | -   | -   | *   | o   | *   | *   | -   | *   |

### Reading the grid

- **P-1 row** — provisioning gates V-1 (ordering), V-4 (cascade reaches the
  freshly provisioned agent), and V-7 (existence-probe answer for a
  newly provisioned agent is indistinguishable from not-found).
- **P-2 row** — auth gates V-1 (auth handshake is part of the ordered
  pipeline), V-2 (pairing expiry kills the session), V-3 (replay guard),
  V-4 (deactivate cascade revokes the session), and V-7.
- **P-3 row** — delegation gates V-2 (expired pairing implies expired
  delegation), V-4 (cascade revokes the delegation), V-5 (the
  attribution invariant lives inside the delegation envelope), V-8
  (tri-state eligibility is delegation-scoped), and V-9 (multi-agent
  publish reads delegation-attached identities).
- **P-4 row** — sidecar gates V-4 (cascade tears down the sidecar
  circle), V-6 (idempotent ensure), V-7 (sidecar membership cannot be
  probed), and V-9 (multi-agent publish into a sidecar thread).

## Gating table

Each cell answers "what happens if the cotest run for this (profile,
vector) cell observes a failure?" The runtime gate (per
`scripts/run-cotest.ps1`) is wired against
`config/coverage-profiles.json`; the table below is the human-readable
projection of the SDK-pure side.

| Cell             | Gate level | Failure surface                                                                             |
|------------------|------------|---------------------------------------------------------------------------------------------|
| `*` cells        | hard       | `cargo test --workspace` fails; `coverage-gate.md` flips the matching profile to `failed`.  |
| `o` cells        | soft       | Informational only — coverage matrix records the miss; CI does not fail on `o`-only misses. |
| `-` cells        | n/a        | Vector is not registered for the profile; scenario is not scheduled.                        |

### Live-stack vs SDK-pure gating

| Run mode                                       | Gates                                  |
|------------------------------------------------|----------------------------------------|
| `cargo test --workspace` (SDK-pure)            | All `*` cells; no live-server probe.   |
| `cargo test --workspace -- --ignored` (live)   | All `*` cells PLUS live HTTP probe.    |
| `integration.yml` nightly                      | Both above; uploads `journey-coverage.json` and `coverage-matrix.md`. |

### Per-profile gating digest

| Profile | Required `*` count | Currently green | Notes                                              |
|---------|-------------------:|----------------:|----------------------------------------------------|
| P-1     | 3                  | 3               | All three pass under `cargo test --workspace`.     |
| P-2     | 5                  | 5               | V-3 (replay guard) is the high-risk gate.          |
| P-3     | 5                  | 5               | V-5 + V-8 are CXP-0008 / §11 normative gates.      |
| P-4     | 4                  | 4               | V-6 idempotency is the key sidecar invariant.      |

Total: 17 normative cells, 17 currently green; 0 deferred to live-stack.

## Source of truth

- `_cotest_todos.md` P4-A (4 profiles) + P4-B (9 vectors).
- `src/scenarios/personal_agent_provisioning/`,
  `src/scenarios/agent_auth/`, `src/scenarios/agent_delegation_policy/`,
  `src/scenarios/agent_sidecar_thread/`.
- `src/scenarios/spec_section_11/`.
- `tests/agent_profile_scenarios.rs`,
  `tests/spec_section_11_scenarios.rs`.
- `docs/spec-section-11-compliance.md` (this doc's compliance counterpart).
