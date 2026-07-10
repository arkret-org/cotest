# Release evidence — 1.0.0 (circle-rollout)

Generated: 2026-05-27 — bundle for the AKP-0007 circle-rollout milestone.

> **Note**: `cotest` is `publish = false` and the milestone explicitly
> bans `git tag` / `cargo publish` / `docker push` (`_todos_all.md` §0).
> "1.0.0" here is the *spec / contract surface* identifier (`arkret-spec
> v1.0.0`) — not a cotest crate version. The evidence pack below is the
> auditable bundle that proves the SDK + servers + harness collectively
> satisfy the v1.0.0 contract before the milestone closes.

## What this pack covers

| Surface                                                  | Evidence link                                                                                  |
|----------------------------------------------------------|------------------------------------------------------------------------------------------------|
| 4 agent profiles × 9 §11 vectors grid                    | [`agent-profile-coverage.md`](agent-profile-coverage.md)                                       |
| §11 compliance (9 vectors)                               | [`spec-section-11-compliance.md`](spec-section-11-compliance.md)                               |
| Cross-project integration report                         | [`integration-report-circle-rollout.md`](integration-report-circle-rollout.md)                 |
| Mock-parity allowlist (anti-regression)                  | [`/mock-parity-allowlist.json`](../mock-parity-allowlist.json) — held at 0 entries             |
| Coverage dashboard                                       | [`coverage-dashboard.md`](coverage-dashboard.md)                                               |
| Test-strategy + complement map                           | [`test-strategy.md`](test-strategy.md), [`complement-map.md`](complement-map.md)               |
| Fuzz harness replay runbook                              | [`seed-reproducibility.md`](seed-reproducibility.md)                                           |

## CI evidence (workflows)

| Workflow                              | Job                  | Cadence                  | Surfaces                                                                                |
|---------------------------------------|----------------------|--------------------------|-----------------------------------------------------------------------------------------|
| `.github/workflows/ci.yml`            | `rust` (1.80, 1.92)  | every push + PR          | fmt / clippy `-D warnings` / build (all-features + no-default) / `cargo test --workspace` |
| `.github/workflows/ci.yml`            | `typos`              | every push + PR          | docs spelling drift                                                                     |
| `.github/workflows/ci.yml`            | `deny`               | every push + PR          | dependency advisories / licensing                                                       |
| `.github/workflows/ci.yml`            | `audit`              | every push + PR          | RustSec advisory scan                                                                   |
| `.github/workflows/ci.yml`            | `fuzz`               | every push + PR          | `envelope_fuzz` / `snapshot_fuzz` / `seal_fuzz` (60s each, 5 min cap) — **new in P5** |
| `.github/workflows/ci.yml`            | `e2e` (3 browsers)   | every push + PR          | Playwright spec-list parse smoke                                                        |

## P5 changes captured in this pack

(see `_cotest_todos.md` P5 + git history `chore(cotest): phase P5 engineering + docs`)

1. **CI**
   - Added a dedicated `fuzz` job to `ci.yml` (60s × 3 targets, capped at
     5 min total).
   - Removed every `continue-on-error: true` marker from
     `integration.yml`; upstream checkout failures now hard-fail the
     joint-bringup job, and the per-service `cargo build` step no longer
     swallows individual failures.

2. **Docs (this folder)**
   - `agent-profile-coverage.md` (closes P4-A yellow item).
   - `spec-section-11-compliance.md` (paired with above).
   - `seed-reproducibility.md` (fuzz replay runbook).
   - `release-evidence-1.0.0.md` (this file).

3. **README**
   - Documented the secret-scan positive / negative example patterns and
     the closed allowlist of redacted field names.

## Sign-off checklist

Before declaring this evidence pack frozen for the milestone:

- [x] `cargo check --workspace` PASS
- [x] `cargo test --workspace` PASS (P4 scenarios green)
- [x] `cargo clippy --workspace --all-targets -- -D warnings` PASS
- [x] `cargo fmt --all` clean
- [x] `cargo deny check` clean (run via `scripts/run-hygiene.ps1`)
- [x] `cargo audit --deny warnings` clean
- [x] `docs/agent-profile-coverage.md` 17/17 normative cells green
- [x] `docs/spec-section-11-compliance.md` 9/9 vectors green
- [ ] `.github/workflows/integration.yml` joint-bringup green run linked
      (held until the next nightly schedule cycle; not blocking P5
      bundle)

## How to consume this pack

   user-journey-level coverage snapshot.
2. Drill into [`spec-section-11-compliance.md`](spec-section-11-compliance.md)
   for the per-vector compliance proof and
   [`agent-profile-coverage.md`](agent-profile-coverage.md) for the
   profile × vector matrix.
3. Cross-check the cross-project integration story in
   [`integration-report-circle-rollout.md`](integration-report-circle-rollout.md).
4. For any fuzz finding referenced in a regression test, follow
   [`seed-reproducibility.md`](seed-reproducibility.md) to reproduce the
   input.
   (and therefore explicitly not part of the v1.0.0 compliance claim).
