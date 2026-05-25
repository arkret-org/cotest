# cotest — Release-Readiness Tasks

> Parent plan: [`../_todos_all.md`](../_todos_all.md)
> Project role: complement-style conformance suite for contrix servers.
> Phase: **4 (gate for the whole release)**.

## State at start (2026-05-24)

- 81 scenario modules, 50+ Playwright specs, 59 Rust integration tests.
- Modes: `process`, `docker`, `compose`.
- Journey coverage UJ-A..H averages 26.4%: A 25%, B 33%, C 16%, D 21%, E 29%, F 18%, G 39%, H 24%.
- 224 fixme markers (expected_live_by=2026Q3).
- **No GitHub Actions workflows.** Local scripts only (`run-cotest.ps1`, `run-compose.ps1`, `run-joint-e2e.ps1`).
- Mock-parity allowlist is empty (good — gates yougen mock vs real soland).

## Phase 4 tasks

### Local gate wiring (highest priority — no remote CI in this plan)
- [x] §1 Add/verify local runner entries for:
  - `fast-smoke` profile for quick local feedback (~17 tests, against soland only).
  - `release-gate` profile for local milestone decisions (compose/process mode, all required services).
  - `full-nightly` profile as a local scheduled command recipe, not a remote cron.
- [x] §2 Add a matrix job for **dual-soland federation**: spin up two soland instances on different ports, run federation scenarios.
  - 2026-05-25 local close: `run-cotest.ps1 -Profile dual-soland` delegates to `run-joint-e2e.ps1 -DualSoland -RunProfile joint-full -Grep "cross-server.federation"` and uses Playwright's bundled `chromium` project for the federation matrix.
- [x] §3 Wire `coverage-profiles.json` enforcement: fail local gate if any journey drops below its baseline.

### Joint yougen ↔ live soland integration (per `_test_todos_claude.md` Phase 6)
- [x] §4 Promote `run-joint-e2e.ps1` from manual-only to a local `run-cotest.ps1` profile that starts soland+coauth, builds yougen, then runs Playwright.
  - 2026-05-25 local close: `run-cotest.ps1 -Profile joint` now delegates to `run-joint-e2e.ps1 -StartCoauth -RunProfile joint-smoke -PlaywrightProject joint-yougen`, so the promoted local profile starts soland, coauth/PostgreSQL, builds/serves yougen, and runs the joint Playwright smoke.
- [x] §5 Replace mock-only `tests/yougen_mock_parity.rs` references with assertions that the live yougen build also passes the same scenarios.

### Journey burn-down (target ≥ 70% on each per master plan Q6)
Order by user-impact and current coverage:
- [ ] §6 UJ-C messaging+edits+reactions+receipts: from 16% to 70%. 26 fixmes to close.
- [ ] §7 UJ-F kanban concurrent work: from 18% to 70%. 32 fixmes.
- [ ] §8 UJ-D encrypted realm + cross-device decrypt: from 21% to 70%. 23 fixmes.
- [ ] §9 UJ-H calls + push + cross-platform sync: from 24% to 70%. 16 fixmes.
- [ ] §10 UJ-A first login + multi-device recovery: from 25% to 70%. 59 fixmes (largest backlog).
- [ ] §11 UJ-E federation cross-domain: from 29% to 70%. 10 fixmes.
- [ ] §12 UJ-B workspace creation + invites: from 33% to 70%. 18 fixmes.
- [ ] §13 UJ-G privacy + governance + appeal + GDPR: from 39% to 70%. 17 fixmes.

### Stub completion in src/
- [ ] §14 `src/conformance/redaction.rs` — `snapshot_pruning_stub` post-redaction snapshot integrity.
- [ ] §15 `src/scenarios/bridge_contracts/starid.rs` — starid proof / trust-root validation.
- [ ] §16 `src/scenarios/chaos_kill_midwrite.rs` — replace 6 `unimplemented!` calls with a Tokio task-manager-based chaos contract.
- [ ] §17 `src/conformance/round4_*.rs` — close `round4-lint-parity` and `round4-vector-*` TODOs.
- [ ] §18 The 17 scenarios marked `#[ignore = "TODO(round23-T**)"]` — unignore as upstream servers land features.

### Mock-parity discipline
- [x] §19 Keep `mock-parity-allowlist.json` empty. Enforce in the local release gate: any addition requires a referenced issue.

### Engineering hygiene
- [x] §20 Add `cargo deny check` to the local hygiene gate.
- [x] §21 Add `typos` to the local hygiene gate.
- [x] §22 Add `cargo audit` to the local hygiene gate.

### Docs
- [x] §23 Update `docs/test-strategy.md` with the new local runner/profile matrix.
- [x] §24 Generate a local `coverage-dashboard.md` from `journey-coverage.json`; do not publish it publicly.
- [x] §25 Document the cotest release-gate as a hard requirement in `_todos_all.md` §4 (verified cross-link).

## Local milestone notes

- 2026-05-25: protocol-only local `release-gate` passed against soland with
  28 passed / 0 failed. Evidence:
  `docs/release-evidence-0.9.0.md` and
  `artifacts/runs/20260525-055932/summary.md`.
- 2026-05-25: local `dual-soland` federation matrix passed with 4 live tests
  passed / 6 fixme skipped. Evidence:
  `artifacts/runs/20260525-082323/summary.md`.

## Exit gate (phase 4)

All of:
1. §1-§5 wired; local runner emits `fast-smoke` artifacts for every requested run.
2. UJ-A..H average ≥ 70% verified coverage.
3. `mock-parity-allowlist.json` still empty.
4. `release-gate` profile green against all four services + yougen.
5. Record a local cotest `v0.9.0` milestone without creating a git tag.

## Notes

- `_e2e_report.md` shows 28 passed / 15 failed / 228 skipped on the last joint run — the 15 failures are TLS/DNS/URL config issues that should be debugged before §4.
- Federation tests are the highest CI cost; consider gating them behind a `[federation]` label on PRs.
