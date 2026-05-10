# cotest

`cotest` is an out-of-repository black-box Contrix server test harness modeled
after Complement. It starts real server processes or real server containers,
drives public HTTP endpoints, and uses `contrix-rust-sdk` where typed protocol
helpers and client smoke coverage are useful.

The current default server under test is the sibling
`../soland/Cargo.toml` checkout.

## Quick Start

Recommended entrypoints:

```powershell
.\scripts\run-cotest.ps1 -Runtime process
.\scripts\run-cotest.ps1 -Runtime process -Profile fast-smoke
.\scripts\run-compose.ps1
.\scripts\build-soland-image.ps1
.\scripts\run-cotest.ps1 -Runtime docker -SutImage cotest-soland:latest
```

- `process` mode is the fast local path and spawns the SUT with `cargo run`.
- `.\scripts\run-compose.ps1` runs the process-mode `compose` profile and can
  attach live `coauth`, `floria`, `sodmin`, or `yougen` services through base
  URLs or managed service commands.
- `docker` mode is the Complement-style path and spawns the SUT with
  `docker run` while Rust tests stay host-side.
- `.\scripts\build-soland-image.ps1` builds the default SUT image from
  `soland` plus the sibling `contrix-rust-sdk` checkout using the workspace
  root as Docker build context.
- Each scripted run writes `raw.log`, `transcript.ndjson`, `summary.json`,
  `summary.md`, `summary.html`, `junit.xml`, coverage/gap reports, and
  CI profile, coverage gate, secret scan, and per-service logs to
  `artifacts/runs/<timestamp>/`, then copies the latest set to
  `artifacts/latest/`.

The primary human-readable report is
`artifacts/latest/summary.md`.

## Direct Cargo Run

```powershell
$env:COTEST_SUT_MANIFEST = "..\soland\Cargo.toml"
cargo test --tests -- --nocapture
```

If `COTEST_SUT_MANIFEST` is not set, the harness falls back to the bundled
default `soland` checkout. `SERVERX_MANIFEST` is still accepted as a legacy
override to avoid breaking older local workflows.

## Runtime Modes

- `process`: spawn the SUT with local `cargo run` against a checkout manifest.
- `compose`: run process-mode bridge-contract tests through
  `scripts/run-compose.ps1`; spawned `soland` remains under cotest lifecycle,
  while external service URLs are passed through `COAUTH_BASE_URL`,
  `FLORIA_BASE_URL`, `SODMIN_BASE_URL`, and `YOUGEN_BASE_URL`.
- `docker`: spawn the SUT from `COTEST_SUT_IMAGE` with Docker while the Rust
  tests remain host-side, similar to Complement.

See [docs/runtime-workflow.md](/E:/Works/contrix-dev/cotest/docs/runtime-workflow.md:1)
for the full startup model, Docker image contract, and result artifacts.

## Layout

- `src/harness.rs`: process lifecycle, test actor helpers, and shared HTTP
  assertion utilities.
- `src/conformance.rs`: artifact-driven offline conformance runner wired to
  `contrix-spec/spec/v1/artifacts` schemas, registries, profiles, OpenAPI, non-HTTP
  bindings, and fixtures.
- `src/scenarios/*.rs`: executable protocol and business-domain scenarios.
- `tests/*.rs`: thin integration wrappers around scenario modules.
- `../_todos.md`: Complement-derived plan and the current single-server /
  multi-server coverage matrix.
- `config/coverage-profiles.json`: machine-readable profile-to-suite coverage
  mapping used by the runner.
- `docs/test-strategy.md`: harness model and suite grouping.
- `docs/complement-map.md`: how Complement concepts map onto Contrix.
- `docs/runtime-workflow.md`: runtime modes, Docker image flow, runner scripts,
  and result presentation.

## Coverage Groups

- Single-server surface: service description, auth, collaboration, repo, sync,
  index, identity/authz, schema/policy, realtime signaling, delivery/media,
  permissions, payload contracts, and extension surface gaps.
- Offline conformance surface: Event Envelope, encoding, redaction,
  capability, sync, federation, privacy/security, and state-resolution fixtures
  loaded from `contrix-spec/spec/v1/artifacts`.
- Multi-server surface: federation readiness, contract validation, and
  cross-server collaboration flows.

## Result Artifacts

The runner script writes:

- `artifacts/runs/<timestamp>/raw.log`
- `artifacts/runs/<timestamp>/transcript.ndjson`
- `artifacts/runs/<timestamp>/summary.json`
- `artifacts/runs/<timestamp>/summary.md`
- `artifacts/runs/<timestamp>/summary.html`
- `artifacts/runs/<timestamp>/junit.xml`
- `artifacts/runs/<timestamp>/metadata.json`
- `artifacts/runs/<timestamp>/coverage-matrix.json`
- `artifacts/runs/<timestamp>/coverage-matrix.md`
- `artifacts/runs/<timestamp>/coverage-gate.json`
- `artifacts/runs/<timestamp>/coverage-gate.md`
- `artifacts/runs/<timestamp>/unresolved-gaps.json`
- `artifacts/runs/<timestamp>/unresolved-gaps.md`
- `artifacts/runs/<timestamp>/ci-profile.json`
- `artifacts/runs/<timestamp>/ci-profile.md`
- `artifacts/runs/<timestamp>/secret-scan.json`
- `artifacts/runs/<timestamp>/secret-scan.md`
- `artifacts/runs/<timestamp>/services/`
- `artifacts/latest/` as a copy of the latest run

This gives `cotest` an explicit result surface instead of relying only on
scrolling terminal output.

`-Profile fast-smoke` runs a small PR-oriented set from
`config/ci-profiles.json`; `-Profile full-nightly` runs the complete suite.
`-FailOnCoverageRegression` compares required coverage profiles against
`-CoverageBaselinePath` or the previous `artifacts/latest/coverage-matrix.json`.
Secret-shaped fields in raw logs, transcripts, and service logs fail the run
unless `-AllowSecretLeaks` is supplied.

For the runtime model comparison against Complement, including image creation,
Docker networking, host-side execution, and result formatting, see
[docs/complement-map.md](/E:/Works/contrix-dev/cotest/docs/complement-map.md:1).

The suite is organized by protocol and behavior, not milestone folders.
